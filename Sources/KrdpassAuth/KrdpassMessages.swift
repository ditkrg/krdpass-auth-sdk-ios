import Foundation

/// Canonical, user-safe error messages.
enum KrdpassMessages {
    static let cancelled = "Authentication was cancelled"
    static let timeout = "Authentication timed out"
    static let busy = "Another authentication is already in progress"
    static let providerNotInstalled =
        "The KRDPASS app is not installed or could not be opened. Please install or update KRDPASS."
    static let stateMismatch = "State parameter mismatch: possible CSRF or response injection"
    static let issuerMismatch =
        "Issuer mismatch: the response did not come from the expected authorization server"
    static let noCode = "No authorization code received"
    static let invalidRedirect = "Redirect URI does not match the exact configured endpoint"
    static let stateRequired =
        "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn()."
    static let missingIdToken = "Token response did not include an id_token"
    static let nonceMismatch = "ID token nonce mismatch (possible token replay)"
    static let pkceGenerationFailed = "Failed to generate secure PKCE pair"
}
