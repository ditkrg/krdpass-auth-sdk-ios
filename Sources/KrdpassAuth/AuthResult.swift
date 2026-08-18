import Foundation

/// Result of a KRDPASS authentication attempt.
public enum AuthResult: Sendable {
    /// Authentication was successful.
    case success(AuthResponse)

    /// The flow ended without any response from KRDPASS: the user returned without finishing,
    /// or `cancelPendingAuthentication()` was called. A cancellation CAS reports on the redirect
    /// is NOT this case; it arrives as `.error` with the canonical code `cancelled`.
    case cancelled

    /// Authentication timed out.
    case timeout

    /// Another authentication is already in progress.
    case busy

    /// An error occurred during authentication.
    case error(AuthError)

    /// A canonical, user-safe message for any non-success result, or `nil` on success.
    public var message: String? {
        switch self {
        case .success: return nil
        case .cancelled: return KrdpassMessages.cancelled
        case .timeout: return KrdpassMessages.timeout
        case .busy: return KrdpassMessages.busy
        case .error(let error): return error.message
        }
    }

    /// True when the user chose not to finish. Branch on this rather than matching
    /// `case .cancelled` alone: matching only the case misses a deliberate Deny, which arrives
    /// as ``error(_:)`` with the canonical code `cancelled`.
    public var isCancelled: Bool {
        switch self {
        case .cancelled: return true
        case .error(let error): return error.error == "cancelled"
        default: return false
        }
    }
}

/// Successful authentication response.
public struct AuthResponse: Equatable, Sendable, CustomStringConvertible {
    /// The authorization code received from KRDPASS.
    public let code: String

    /// The state parameter from the OAuth flow (if provided).
    public let state: String?

    public init(code: String, state: String? = nil) {
        self.code = code
        self.state = state
    }

    public var description: String {
        "AuthResponse(code=[REDACTED], state=\(state ?? "nil"))"
    }
}

/// Authentication error details.
///
/// `LocalizedError`, so `localizedDescription` yields `errorDescription` instead of the generic
/// bridged NSError string.
public struct AuthError: Error, LocalizedError, Equatable, Sendable {
    /// The error code.
    public let error: String

    public let errorDescription: String?

    /// The KRDPASS install URL string, populated when `error` is `provider_not_installed`.
    /// Open this URL in a browser to take the user to the App Store (or to open the app if
    /// already installed). Derived from the environment passed to `KrdpassConfig`.
    public let installUrl: String?

    public var message: String {
        errorDescription ?? error
    }

    public init(error: String, errorDescription: String? = nil, installUrl: String? = nil) {
        self.error = error
        self.errorDescription = errorDescription
        self.installUrl = installUrl
    }

    public static func launchFailed(_ reason: String) -> AuthError {
        AuthError(error: "launch_failed", errorDescription: reason)
    }

    /// The KRDPASS app is not installed, or has not verified ownership of the authorization
    /// domain (Universal Link). The flow fails closed rather than silently opening the
    /// authorization URL in a browser; open `installUrl` to take the user to the App Store.
    public static func providerNotInstalled(installUrl: String?) -> AuthError {
        AuthError(
            error: "provider_not_installed",
            errorDescription: KrdpassMessages.providerNotInstalled,
            installUrl: installUrl
        )
    }

    public static let noCode = AuthError(
        error: "no_code", errorDescription: KrdpassMessages.noCode)

    public static func stateMismatch(errorDescription: String? = nil) -> AuthError {
        AuthError(
            error: "state_mismatch",
            errorDescription: errorDescription ?? KrdpassMessages.stateMismatch)
    }

    /// RFC 9207: the response carried an `iss` that is not this environment's authorization
    /// server. Kept distinct from `stateMismatch` so a mix-up attack is not reported as CSRF.
    public static func issuerMismatch(errorDescription: String? = nil) -> AuthError {
        AuthError(
            error: "issuer_mismatch",
            errorDescription: errorDescription ?? KrdpassMessages.issuerMismatch)
    }

    public static func invalidRedirect(errorDescription: String? = nil) -> AuthError {
        AuthError(
            error: "invalid_redirect",
            errorDescription: errorDescription ?? KrdpassMessages.invalidRedirect)
    }

    public static func platformError(_ reason: String) -> AuthError {
        AuthError(error: "platform_error", errorDescription: reason)
    }

    public static func invalidRequest(_ reason: String) -> AuthError {
        AuthError(error: "invalid_request", errorDescription: reason)
    }
}

/// General SDK errors.
public enum KrdpassError: Error, LocalizedError, Sendable {
    case configurationError(String)
    /// The ``AuthResult/cancelled`` counterpart on the `signIn` path: no response from KRDPASS.
    /// A cancellation CAS reports on the redirect arrives as ``authenticationFailed(_:code:)``
    /// with `code == "cancelled"`.
    case userCancelled
    case timeout
    case busy
    /// The payload is constrained to `Sendable` so the whole error can cross an actor boundary.
    case networkError(any Error & Sendable)
    case authenticationFailed(String, code: String?)
    /// The device's secure random source failed, so no PKCE pair or `state` could be generated.
    case pkceGenerationFailed
    /// The KRDPASS app is not installed or could not be opened. Carries the environment's
    /// install URL so callers can send the user to the store.
    case providerNotInstalled(installUrl: String?)

    public var errorDescription: String? {
        switch self {
        case .configurationError(let message):
            return "Configuration Error: \(message)"
        case .userCancelled:
            return KrdpassMessages.cancelled
        case .timeout:
            return KrdpassMessages.timeout
        case .busy:
            return KrdpassMessages.busy
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .authenticationFailed(let message, _):
            return "Authentication failed: \(message)"
        case .pkceGenerationFailed:
            return KrdpassMessages.pkceGenerationFailed
        case .providerNotInstalled:
            return KrdpassMessages.providerNotInstalled
        }
    }

    /// Structured failure code (e.g. `state_mismatch`, `invalid_id_token`), so callers can
    /// branch without parsing `errorDescription`.
    public var code: String? {
        switch self {
        case .authenticationFailed(_, let code): return code
        case .providerNotInstalled: return "provider_not_installed"
        case .userCancelled: return "cancelled"
        case .timeout: return "timeout"
        case .busy: return "busy"
        case .networkError: return "network_error"
        case .configurationError: return "invalid_request"
        case .pkceGenerationFailed: return "pkce_generation_failed"
        }
    }

    /// The KRDPASS install URL when `code == "provider_not_installed"`, nil otherwise.
    public var installUrl: String? {
        if case .providerNotInstalled(let url) = self { return url }
        return nil
    }
}
