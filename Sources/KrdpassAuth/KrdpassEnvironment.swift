import Foundation

/// Defines the KRDPASS environment to use for authentication.
public enum KrdpassEnvironment: Sendable {
    /// Production environment (app.pass.krd).
    /// Use this for live apps distributed to end users.
    case production

    /// Development environment (app.krdpass.dev.krd).
    /// Use this for testing and development.
    case development

    public var authUrl: String {
        switch self {
        case .production:
            return "https://app.pass.krd/connect/authorize"
        case .development:
            return "https://app.krdpass.dev.krd/connect/authorize"
        }
    }

    public var authServerUrl: String {
        switch self {
        case .production:
            return "https://account.id.krd"
        case .development:
            return "https://auth.dev.krd"
        }
    }

    public var userInfoEndpoint: String {
        switch self {
        case .production:
            return "https://account.id.krd/connect/userinfo"
        case .development:
            return "https://auth.dev.krd/connect/userinfo"
        }
    }

    public var tokenEndpoint: String {
        switch self {
        case .production:
            return "https://account.id.krd/connect/token"
        case .development:
            return "https://auth.dev.krd/connect/token"
        }
    }

    public var revocationEndpoint: String {
        switch self {
        case .production:
            return "https://account.id.krd/connect/revocation"
        case .development:
            return "https://auth.dev.krd/connect/revocation"
        }
    }

    public var parEndpoint: String {
        switch self {
        case .production:
            return "https://account.id.krd/connect/par"
        case .development:
            return "https://auth.dev.krd/connect/par"
        }
    }

    public var jwksEndpoint: String {
        switch self {
        case .production:
            return "https://account.id.krd/.well-known/openid-configuration/jwks"
        case .development:
            return "https://auth.dev.krd/.well-known/openid-configuration/jwks"
        }
    }

    /// The environment name (lowercase). Samples send this to a backend as the environment
    /// discriminator.
    public var name: String {
        switch self {
        case .production:
            return "production"
        case .development:
            return "development"
        }
    }

    /// The web URL for this environment. Opening it in a browser takes users to the KRDPASS
    /// install page when the app is not present, or opens the app if already installed.
    /// Surface this when returning a `provider_not_installed` error so integrators can prompt
    /// the user to install KRDPASS.
    public var installUrl: String {
        switch self {
        case .production:
            return "https://app.pass.krd"
        case .development:
            return "https://app.krdpass.dev.krd"
        }
    }
}
