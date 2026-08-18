import Foundation

/// Result of a successful sign-in operation containing OAuth tokens.
public struct KrdpassTokenResult: Sendable, CustomStringConvertible {
    public let accessToken: String

    /// The OpenID Connect ID token (optional)
    public let idToken: String?

    /// The token type (usually "Bearer")
    public let tokenType: String

    /// The number of seconds until the access token expires
    public let expiresIn: Int

    public let refreshToken: String?

    /// The space-separated list of granted scopes (optional)
    public let scope: String?

    /// The date when the tokens were received.
    public let receivedAt: Date

    public init(
        accessToken: String,
        idToken: String? = nil,
        tokenType: String = "Bearer",
        expiresIn: Int = 3600,
        refreshToken: String? = nil,
        scope: String? = nil,
        receivedAt: Date = Date()
    ) {
        self.accessToken = accessToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.receivedAt = receivedAt
    }

    /// Create a token result from a dictionary of claims, typically from a backend JSON response.
    /// Handles both camelCase and snake_case keys. Returns `nil` if `accessToken` is missing or empty.
    public init?(dictionary: [String: Any]) {
        guard
            let accessToken = (dictionary["accessToken"] ?? dictionary["access_token"]) as? String,
            !accessToken.isEmpty
        else {
            return nil
        }
        self.accessToken = accessToken
        self.idToken = (dictionary["idToken"] ?? dictionary["id_token"]) as? String
        self.tokenType =
            (dictionary["tokenType"] ?? dictionary["token_type"]) as? String ?? "Bearer"
        self.expiresIn = (dictionary["expiresIn"] ?? dictionary["expires_in"]) as? Int ?? 3600
        self.refreshToken = (dictionary["refreshToken"] ?? dictionary["refresh_token"]) as? String
        self.scope = dictionary["scope"] as? String
        // Not read from the dictionary: this is a local clock stamp, and a backend-echoed value
        // would mix two clocks and corrupt isExpired().
        self.receivedAt = Date()
    }

    /// Checks if the access token is expired or will expire within `skewSeconds`.
    public func isExpired(skewSeconds: TimeInterval = 60) -> Bool {
        let expirationDate = receivedAt.addingTimeInterval(TimeInterval(expiresIn))
        return Date().addingTimeInterval(skewSeconds) >= expirationDate
    }

    public var description: String {
        """
        KrdpassTokenResult(\
        accessToken=[REDACTED], \
        idToken=\(idToken != nil ? "[REDACTED]" : "nil"), \
        tokenType='\(tokenType)', \
        expiresIn=\(expiresIn), \
        refreshToken=\(refreshToken != nil ? "[REDACTED]" : "nil"), \
        scope=\(scope ?? "nil"))
        """
    }
}
