import SwiftUI

extension View {
    /// Wire up KRDPASS deep-link handling on your root view, covering both the Universal Link
    /// (`onContinueUserActivity`) and legacy URL (`onOpenURL`) paths. Without this wiring the
    /// auth flow hangs waiting for a redirect that never arrives.
    public func withKrdpassDeepLinkHandling(_ auth: KrdpassAuth) -> some View {
        self
            .onOpenURL { url in
                auth.handle(url)
            }
            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                guard let url = activity.webpageURL else { return }
                auth.handle(url)
            }
    }
}
