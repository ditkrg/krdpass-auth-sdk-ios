import UIKit
import XCTest

@testable import KrdpassAuth

/// The watcher is how a flow ends whenever the user does not finish in KRDPASS, so its guards are
/// behaviour, not plumbing: only a return AFTER backgrounding counts, a redirect inside the grace
/// window wins the race, and stop() must fully disarm it. Driven through the real
/// NotificationCenter, the same way UIKit drives it.
@MainActor
final class ForegroundReturnWatcherTests: XCTestCase {

    private func makeWatcher(
        gracePeriod: TimeInterval,
        isStillPending: @escaping () -> Bool,
        onAbandoned: @escaping () -> Void
    ) -> ForegroundReturnWatcher {
        ForegroundReturnWatcher(
            gracePeriod: gracePeriod,
            log: { _, _ in },
            isStillPending: isStillPending,
            onAbandoned: onAbandoned
        )
    }

    private func post(_ name: Notification.Name) {
        NotificationCenter.default.post(name: name, object: nil)
    }

    func testReturnAfterBackgroundingCancelsAPendingFlow() async {
        let abandoned = expectation(description: "onAbandoned fires")
        let watcher = makeWatcher(
            gracePeriod: 0.05, isStillPending: { true }, onAbandoned: { abandoned.fulfill() })
        watcher.start()

        post(UIApplication.didEnterBackgroundNotification)
        post(UIApplication.didBecomeActiveNotification)

        await fulfillment(of: [abandoned], timeout: 2.0)
        watcher.stop()
    }

    func testInitialActivationWithoutBackgroundingIsNotACancellation() async {
        // The first didBecomeActive fires before KRDPASS ever takes the foreground; reading it as
        // an abandoned flow would cancel every sign-in at launch.
        let abandoned = expectation(description: "onAbandoned must not fire")
        abandoned.isInverted = true
        let watcher = makeWatcher(
            gracePeriod: 0.05, isStillPending: { true }, onAbandoned: { abandoned.fulfill() })
        watcher.start()

        post(UIApplication.didBecomeActiveNotification)

        await fulfillment(of: [abandoned], timeout: 0.3)
        watcher.stop()
    }

    func testARedirectInsideTheGraceWindowWinsTheRace() async {
        // The success path usually delivers the redirect in the same activation cycle; the grace
        // re-check is what keeps a real success from being reported as a cancellation.
        var pending = true
        let abandoned = expectation(description: "onAbandoned must not fire")
        abandoned.isInverted = true
        let watcher = makeWatcher(
            gracePeriod: 0.1, isStillPending: { pending }, onAbandoned: { abandoned.fulfill() })
        watcher.start()

        post(UIApplication.didEnterBackgroundNotification)
        post(UIApplication.didBecomeActiveNotification)
        pending = false

        await fulfillment(of: [abandoned], timeout: 0.4)
        watcher.stop()
    }

    func testStopDisarmsTheWatcher() async {
        let abandoned = expectation(description: "onAbandoned must not fire")
        abandoned.isInverted = true
        let watcher = makeWatcher(
            gracePeriod: 0.05, isStillPending: { true }, onAbandoned: { abandoned.fulfill() })
        watcher.start()

        post(UIApplication.didEnterBackgroundNotification)
        watcher.stop()
        post(UIApplication.didBecomeActiveNotification)

        await fulfillment(of: [abandoned], timeout: 0.3)
    }
}
