import UIKit
import os.log

/// Detects a user who returns to the app mid-flow (system back / app switcher) without finishing
/// in KRDPASS, and treats it as a cancellation. Only a return AFTER the app has backgrounded
/// counts: the initial activation fires before KRDPASS ever takes the foreground.
@MainActor
final class ForegroundReturnWatcher {
    private let gracePeriod: TimeInterval
    private let log: (String, String) -> Void
    private let isStillPending: () -> Bool
    private let onAbandoned: () -> Void

    // nonisolated(unsafe) so the nonisolated deinit below can unregister them: an abandoned flow
    // drops the watcher without ever calling stop(), and a leaked observer keeps firing.
    // NotificationCenter is thread-safe, and by deinit nothing else can reach these.
    private nonisolated(unsafe) var didBecomeActiveObserver: NSObjectProtocol?
    private nonisolated(unsafe) var didEnterBackgroundObserver: NSObjectProtocol?
    private var hasBackgroundedDuringAuth = false
    private var foregroundCancelWorkItem: DispatchWorkItem?

    #if DEBUG
        // Static: app-to-app sign-in commonly uses a fresh KrdpassAuth per flow, and the
        // missing-wiring diagnostic must stay suppressed process-wide once a redirect arrives.
        private static var hasObservedDeepLinkForwarding = false
        private static var hasEmittedWiringDiagnostic = false
    #endif

    /// `gracePeriod` is how long after foregrounding to wait for a redirect before declaring
    /// cancellation: the success path usually delivers the redirect in the same activation
    /// cycle, so this only has to cover same-runloop reordering.
    init(
        gracePeriod: TimeInterval = 0.5,
        log: @escaping (String, String) -> Void,
        isStillPending: @escaping () -> Bool,
        onAbandoned: @escaping () -> Void
    ) {
        self.gracePeriod = gracePeriod
        self.log = log
        self.isStillPending = isStillPending
        self.onAbandoned = onAbandoned
    }

    deinit {
        let center = NotificationCenter.default
        if let didBecomeActiveObserver { center.removeObserver(didBecomeActiveObserver) }
        if let didEnterBackgroundObserver { center.removeObserver(didEnterBackgroundObserver) }
    }

    func start() {
        stop()
        let center = NotificationCenter.default
        didEnterBackgroundObserver = center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.hasBackgroundedDuringAuth = true }
        }
        didBecomeActiveObserver = center.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.handleAppDidBecomeActive() }
        }
    }

    func stop() {
        foregroundCancelWorkItem?.cancel()
        foregroundCancelWorkItem = nil
        hasBackgroundedDuringAuth = false

        let center = NotificationCenter.default
        if let observer = didBecomeActiveObserver {
            center.removeObserver(observer)
            didBecomeActiveObserver = nil
        }
        if let observer = didEnterBackgroundObserver {
            center.removeObserver(observer)
            didEnterBackgroundObserver = nil
        }
    }

    /// Record that a redirect reached the SDK, suppressing the missing-wiring diagnostic for
    /// the rest of the process. No-op in release builds.
    func markDeepLinkForwarded() {
        #if DEBUG
            Self.hasObservedDeepLinkForwarding = true
        #endif
    }

    private func handleAppDidBecomeActive() {
        guard isStillPending(), hasBackgroundedDuringAuth else { return }

        // The redirect usually arrives in this same activation, so let it win the race.
        foregroundCancelWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                guard let self, self.isStillPending() else { return }
                self.log("INFO", "App returned to foreground without a redirect; cancelling")
                self.warnIfLikelyMissingDeepLinkWiring()
                self.onAbandoned()
            }
        }
        foregroundCancelWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + gracePeriod, execute: workItem)
    }

    /// Surface the #1 integration mistake: an app that never forwards the KRDPASS redirect to
    /// `handle(_:)`. Without it, a successful sign-in is indistinguishable from a cancellation.
    /// DEBUG-only, once per process.
    private func warnIfLikelyMissingDeepLinkWiring() {
        #if DEBUG
            guard !Self.hasObservedDeepLinkForwarding, !Self.hasEmittedWiringDiagnostic else {
                return
            }
            Self.hasEmittedWiringDiagnostic = true
            os_log(
                """
                [KrdpassAuth] WARNING: KRDPASS returned to the foreground but the SDK never received the \
                redirect, so this sign-in was cancelled. If the user *did* complete sign-in, your app \
                is missing the KRDPASS deep-link wiring:
                  - SwiftUI: add `.withKrdpassDeepLinkHandling(auth)` to your root view.
                  - UIKit: forward `application(_:open:options:)` and \
                `application(_:continue:restorationHandler:)` to `auth.handle(_:)`.
                (DEBUG-only; shown once per launch.)
                """,
                log: OSLog(subsystem: "krd.pass.auth", category: "integration"),
                type: .fault
            )
        #endif
    }
}
