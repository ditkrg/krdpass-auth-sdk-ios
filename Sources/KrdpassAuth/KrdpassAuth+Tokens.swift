import Foundation

/// The token-facing half of the SDK: userinfo, refresh, revoke, and the decode/verify entry
/// points.
extension KrdpassAuth {

    /// Get user information from CAS using an access token.
    public func getUserInfo(
        accessToken: String,
        completion: @escaping (Result<KrdpassUserInfo, KrdpassError>) -> Void
    ) {
        // The async variant throws nothing but KrdpassError; the widening catch is only for the
        // compiler's exhaustiveness.
        Task {
            do {
                completion(.success(try await getUserInfo(accessToken: accessToken)))
            } catch let error as KrdpassError {
                log("ERROR", "Failed to fetch user info")
                completion(.failure(error))
            } catch {
                log("ERROR", "Failed to fetch user info")
                completion(.failure(.authenticationFailed(error.localizedDescription, code: nil)))
            }
        }
    }

    public nonisolated func getUserInfo(accessToken: String) async throws -> KrdpassUserInfo {
        guard !accessToken.isEmpty else {
            throw KrdpassError.configurationError("accessToken cannot be empty")
        }
        return try await KrdpassAuth.translatingCasErrors {
            try await casClient.getUserInfo(accessToken: accessToken)
        }
    }

    /// Refresh tokens using a refresh token.
    ///
    /// An `id_token` in the response is verified (signature, issuer, audience, expiry) before it
    /// is returned. There is no nonce binding: OpenID Connect Core 12.2 does not require one on
    /// refresh. The returned `refreshToken` is nil when the server does not rotate refresh tokens
    /// (RFC 6749 section 6); keep the one you already hold in that case.
    public nonisolated func refreshTokens(refreshToken: String, scope: String? = nil) async throws
        -> KrdpassTokenResult
    {
        let tokens = try await KrdpassAuth.translatingCasErrors {
            try await casClient.refreshTokens(refreshToken: refreshToken, scope: scope)
        }
        // A refreshed id_token gets the same verification as the signIn path's, instead of being
        // handed back unchecked.
        if let idToken = tokens.idToken, !idToken.isEmpty {
            do {
                _ = try await verifyToken(
                    idToken,
                    issuer: config.environment.authServerUrl,
                    audience: config.clientId
                )
            } catch {
                // A JWKS transport failure stays the retryable `network_error` rather than
                // reading as a bad token.
                throw KrdpassAuth.verifyErrorToKrdpassError(error)
            }
        }
        return tokens
    }

    /// Revoke an access or refresh token.
    public nonisolated func revokeToken(token: String, tokenTypeHint: String? = nil) async throws {
        try await KrdpassAuth.translatingCasErrors {
            try await casClient.revokeToken(token: token, tokenTypeHint: tokenTypeHint)
        }
    }

    /// Decode a JWT payload into its claims **without verifying the signature**.
    ///
    /// SECURITY: the returned claims are NOT authenticated and MUST NOT drive any trust or
    /// authorization decision. Always ``verifyToken(idToken:clockSkew:)`` first; this is only
    /// for cosmetic display of an already-verified token.
    ///
    /// - Throws: ``KrdpassError/configurationError(_:)`` if the token is not a parseable JWT: a
    ///   parse failure is a bad argument, not a failed authentication.
    public nonisolated func decodeTokenUnverified(_ token: String) throws -> [String: JSONValue] {
        // KrdpassError is the only error type the SDK throws from a public entry point, so the
        // internal parse failures are translated here.
        do {
            guard !token.isEmpty else {
                throw TokenVerificationError.invalidToken("Token cannot be empty")
            }
            // omittingEmptySubsequences: false, or "..a.b" collapses and an empty segment passes.
            let parts = token.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count >= 2 else {
                throw TokenVerificationError.invalidToken(
                    "JWT must have at least a header and payload")
            }

            let data = try Base64Url.decode(String(parts[1]))
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw TokenVerificationError.invalidToken("JWT payload is not valid JSON")
            }

            return flatteningSingleAudience(json)
                .mapValues(JSONValue.init(jsonSerializationOutput:))
        } catch {
            throw KrdpassError.configurationError(error.localizedDescription)
        }
    }

    /// Verify an ID token against the environment's JWKS endpoint: RS256 signature, issuer,
    /// audience and expiry. The issuer is pinned to the configured environment and the audience
    /// to the configured `clientId`, so a token minted by some other issuer for this client is
    /// rejected rather than accepted on its signature alone.
    ///
    /// - Throws: ``KrdpassError/authenticationFailed(_:code:)`` with `code` one of
    ///   `invalid_id_token` (signature, claims or expiry), `network_error` (the JWKS could not be
    ///   fetched, so a retry may help), or `verification_failed`.
    public func verifyToken(
        idToken: String,
        clockSkew: TimeInterval = 60
    ) async throws -> [String: JSONValue] {
        do {
            return try await verifyToken(
                idToken, issuer: config.environment.authServerUrl, audience: config.clientId,
                clockSkew: clockSkew)
        } catch {
            throw KrdpassAuth.verifyErrorToKrdpassError(error)
        }
    }

    /// Internal RS256 JWKS verifier with explicit issuer/audience, used by the signIn trust path
    /// and the tests.
    func verifyToken(
        _ token: String,
        issuer: String? = nil,
        audience: String? = nil,
        clockSkew: TimeInterval = 60
    ) async throws -> [String: JSONValue] {
        try await jwtVerifier.verify(
            token, issuer: issuer, audience: audience, clockSkew: clockSkew)
    }

    /// Validate the OIDC ID token returned by the client-only signIn flow: signature (JWKS),
    /// issuer, audience (== clientId), expiry, and nonce binding.
    func validateIdToken(_ idToken: String?, expectedNonce: String) async throws {
        guard let idToken = idToken, !idToken.isEmpty else {
            throw KrdpassError.authenticationFailed(
                KrdpassMessages.missingIdToken, code: "invalid_id_token")
        }
        let claims: [String: JSONValue]
        do {
            claims = try await verifyToken(
                idToken,
                issuer: config.environment.authServerUrl,
                audience: config.clientId
            )
        } catch {
            throw KrdpassError.authenticationFailed(
                "ID token validation failed: \(error.localizedDescription)",
                code: "invalid_id_token")
        }
        guard let returnedNonce = claims["nonce"]?.stringValue, returnedNonce == expectedNonce
        else {
            throw KrdpassError.authenticationFailed(
                KrdpassMessages.nonceMismatch, code: "nonce_mismatch")
        }
    }
}
