import UIKit

/// Opens a URL via the system. Injectable so app-to-app launches can be mocked in tests.
/// Internal on purpose: nothing should substitute the system opener, since only the genuine
/// KRDPASS app, verified via Universal Links, may receive the launch.
@MainActor
protocol UrlOpener {
    func open(
        _ url: URL, options: [UIApplication.OpenExternalURLOptionsKey: Any],
        completion: (@MainActor (Bool) -> Void)?)
}

final class DefaultUrlOpener: UrlOpener {
    init() {}

    func open(
        _ url: URL, options: [UIApplication.OpenExternalURLOptionsKey: Any],
        completion: (@MainActor (Bool) -> Void)?
    ) {
        UIApplication.shared.open(url, options: options, completionHandler: completion)
    }
}

/// Implement this protocol and assign to `KrdpassAuth.logger` to receive log messages from the
/// SDK. By default, no logging occurs.
public protocol KrdpassLogger: Sendable {
    /// Log a message at the given level ("DEBUG", "INFO", "WARN", "ERROR").
    /// Sensitive data is redacted before it reaches the message.
    func log(level: String, message: String)
}
