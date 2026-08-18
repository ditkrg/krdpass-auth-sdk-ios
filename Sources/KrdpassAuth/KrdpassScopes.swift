import Foundation

/// Standard OAuth2 scopes supported by KRDPASS on iOS.
public enum KrdpassScopes {
    /// Required for OpenID Connect flows. Returns the 'sub' claim.
    public static let openid = "openid"

    /// Returns standard profile claims (name, family_name, given_name, picture).
    public static let profile = "profile"

    /// Returns digital identity claims (e.g. citizen_first, citizen_surname, birthdate).
    public static let citizenIdentity = "citizen_identity"

    /// Requests a refresh token for background/offline access.
    public static let offlineAccess = "offline_access"
}
