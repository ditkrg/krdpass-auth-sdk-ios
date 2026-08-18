import Foundation

/// Client for communicating directly with CAS: PAR, token exchange, userinfo, refresh, revoke.
final class CasClient: Sendable {
    private let clientId: String
    private let environment: KrdpassEnvironment
    private let session: URLSession

    init(clientId: String, environment: KrdpassEnvironment, urlSession: URLSession) {
        self.clientId = clientId
        self.environment = environment
        self.session = urlSession
    }

    private func retry<T>(
        maxAttempts: Int = 3,
        action: () async throws -> T
    ) async throws -> T {
        var attempt = 0
        while true {
            try Task.checkCancellation()
            attempt += 1
            do {
                return try await action()
            } catch {
                if attempt >= maxAttempts { throw error }

                if let casError = error as? CasException, !casError.isRetryable {
                    throw error
                }

                let delay = 1.0 * pow(2.0, Double(attempt - 1))
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }
    }

    /// Keep tokens and citizen claims out of any HTTP cache and off the app's cookie jar: an
    /// injected session may be backed by the shared on-disk `URLCache`, and setting the policy
    /// per request means never trusting the server to send `Cache-Control: no-store`.
    private func applyNoStorePolicy(to request: inout URLRequest) {
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.httpShouldHandleCookies = false
    }

    /// RFC 3986 unreserved, as an explicit ASCII list: CharacterSet.alphanumerics includes every
    /// Unicode letter and digit, which must be percent-encoded here.
    private static let formUnreserved = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )

    /// Serialize query items as a strict application/x-www-form-urlencoded body.
    ///
    /// URLComponents.percentEncodedQuery leaves "+" literal, which form decoding turns into a
    /// space server-side. Percent-encode everything outside the unreserved set instead.
    static func formURLEncode(_ items: [URLQueryItem]) -> String {
        items.map { item in
            let name =
                item.name.addingPercentEncoding(withAllowedCharacters: formUnreserved) ?? item.name
            let value =
                (item.value ?? "").addingPercentEncoding(withAllowedCharacters: formUnreserved)
                ?? ""
            return "\(name)=\(value)"
        }.joined(separator: "&")
    }

    /// POST a form-encoded body and return the decoded JSON object on success.
    private func postForm(url: URL, body: URLComponents, failureMessage: String) async throws
        -> [String: Any]
    {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formURLEncode(body.queryItems ?? []).data(using: .utf8)
        request.timeoutInterval = 30.0
        applyNoStorePolicy(to: &request)

        let (data, response) = try await self.session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw CasException(message: "Invalid response type")
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            let errorMessage = parseErrorResponse(data: data)
            throw CasException(
                message: errorMessage ?? failureMessage,
                statusCode: httpResponse.statusCode
            )
        }

        // A successful revocation (RFC 7009) returns 200 with an empty body; JSONSerialization
        // throws on empty input, so short-circuit it.
        guard !data.isEmpty else { return [:] }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    private func validateParResponse(_ json: [String: Any]) throws -> (
        requestUri: String, expiresIn: Int
    ) {
        guard let requestUri = json["request_uri"] as? String, !requestUri.isEmpty else {
            throw CasException(message: "Missing or empty request_uri in PAR response")
        }

        let expiresIn = json["expires_in"] as? Int ?? 300

        return (requestUri, expiresIn)
    }

    private func validateTokenResponse(_ json: [String: Any]) throws -> KrdpassTokenResult {
        guard let accessToken = json["access_token"] as? String, !accessToken.isEmpty else {
            throw CasException(message: "Missing or empty access_token in token response")
        }

        return KrdpassTokenResult(
            accessToken: accessToken,
            idToken: json["id_token"] as? String,
            tokenType: json["token_type"] as? String ?? "Bearer",
            expiresIn: json["expires_in"] as? Int ?? 3600,
            refreshToken: json["refresh_token"] as? String,
            scope: json["scope"] as? String
        )
    }

    /// Push an authorization request to CAS.
    func pushAuthorizationRequest(
        codeChallenge: String,
        redirectUri: String,
        scopes: [String],
        state: String? = nil,
        nonce: String? = nil
    ) async throws -> ParResponse {
        guard !codeChallenge.isEmpty else {
            throw CasException(message: "codeChallenge cannot be empty")
        }
        guard !redirectUri.isEmpty else {
            throw CasException(message: "redirectUri cannot be empty")
        }
        guard !scopes.isEmpty else {
            throw CasException(message: "scopes cannot be empty")
        }

        guard let url = URL(string: environment.parEndpoint) else {
            throw CasException(message: "Invalid PAR endpoint URL")
        }
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]

        if let state = state {
            components.queryItems?.append(URLQueryItem(name: "state", value: state))
        }
        if let nonce = nonce {
            components.queryItems?.append(URLQueryItem(name: "nonce", value: nonce))
        }

        return try await retry {
            let json = try await self.postForm(
                url: url, body: components, failureMessage: "PAR request failed")
            let (requestUri, expiresIn) = try self.validateParResponse(json)
            return ParResponse(requestUri: requestUri, expiresIn: expiresIn)
        }
    }

    /// Exchange an authorization code for tokens.
    func exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        redirectUri: String
    ) async throws -> KrdpassTokenResult {
        guard !code.isEmpty else {
            throw CasException(message: "code cannot be empty")
        }
        guard !codeVerifier.isEmpty else {
            throw CasException(message: "codeVerifier cannot be empty")
        }
        guard !redirectUri.isEmpty else {
            throw CasException(message: "redirectUri cannot be empty")
        }

        guard let url = URL(string: environment.tokenEndpoint) else {
            throw CasException(message: "Invalid token endpoint URL")
        }
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "code_verifier", value: codeVerifier),
        ]

        // An authorization code is single-use, so never retry: a blip after the server already
        // consumed the code turns into a confusing invalid_grant on replay.
        return try await retry(maxAttempts: 1) {
            let json = try await self.postForm(
                url: url, body: components, failureMessage: "Token exchange failed")
            return try self.validateTokenResponse(json)
        }
    }

    /// Get user info from CAS using an access token.
    func getUserInfo(accessToken: String) async throws -> KrdpassUserInfo {
        guard !accessToken.isEmpty else {
            throw CasException(message: "accessToken cannot be empty")
        }
        guard let url = URL(string: environment.userInfoEndpoint) else {
            throw CasException(message: "Invalid userinfo endpoint URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 30.0
        applyNoStorePolicy(to: &request)

        return try await retry {
            let (data, response) = try await self.session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw CasException(message: "Invalid response type")
            }

            guard (200..<300).contains(httpResponse.statusCode) else {
                let errorMessage = self.parseErrorResponse(data: data)
                throw CasException(
                    message: errorMessage ?? "UserInfo request failed",
                    statusCode: httpResponse.statusCode
                )
            }

            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            guard let userInfo = KrdpassUserInfo(json: json) else {
                throw CasException(message: "Missing or empty 'sub' field in UserInfo response")
            }
            return userInfo
        }
    }

    /// Refresh tokens using a refresh token.
    func refreshTokens(refreshToken: String, scope: String? = nil) async throws
        -> KrdpassTokenResult
    {
        guard !refreshToken.isEmpty else {
            throw CasException(message: "refreshToken cannot be empty")
        }
        guard let url = URL(string: environment.tokenEndpoint) else {
            throw CasException(message: "Invalid token endpoint URL")
        }
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "grant_type", value: "refresh_token"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "refresh_token", value: refreshToken),
        ]
        if let scope, !scope.isEmpty {
            components.queryItems?.append(URLQueryItem(name: "scope", value: scope))
        }

        // Refresh tokens can be rotated (single-use) by the CAS: replaying a consumed one can trip
        // reuse detection and revoke the whole token family. Same rationale as the code exchange.
        return try await retry(maxAttempts: 1) {
            let json = try await self.postForm(
                url: url, body: components, failureMessage: "Token refresh failed")
            return try self.validateTokenResponse(json)
        }
    }

    /// Revoke an access or refresh token.
    func revokeToken(token: String, tokenTypeHint: String? = nil) async throws {
        guard !token.isEmpty else {
            throw CasException(message: "token cannot be empty")
        }
        guard let url = URL(string: environment.revocationEndpoint) else {
            throw CasException(message: "Invalid revocation endpoint URL")
        }
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "token", value: token),
        ]
        if let tokenTypeHint, !tokenTypeHint.isEmpty {
            components.queryItems?.append(
                URLQueryItem(name: "token_type_hint", value: tokenTypeHint))
        }

        _ = try await retry {
            try await self.postForm(
                url: url, body: components, failureMessage: "Token revocation failed")
        }
    }

    private func parseErrorResponse(data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var parts: [String] = []
        if let error = json["error"] as? String {
            parts.append(Self.sanitizeUpstreamText(error))
        }
        if let errorDescription = json["error_description"] as? String {
            parts.append(Self.sanitizeUpstreamText(errorDescription))
        }

        return parts.isEmpty ? nil : parts.joined(separator: ": ")
    }

    /// Redact token-shaped runs from upstream CAS text and cap its length. This text reaches the
    /// host app via the ``KrdpassError`` message; a CAS deployment that echoed a submitted token
    /// back in its error body would otherwise send it straight into an app's crash reporter.
    private static func sanitizeUpstreamText(_ text: String) -> String {
        // Bound first: both patterns backtrack quadratically on a long unbroken base64url run,
        // and this text is whatever the upstream sent. JWT shape next, so a three-segment token
        // collapses to one marker instead of three. A credential cut by the bound still leaves a
        // 32-character run for the second pattern.
        text.bounded()
            .replacingOccurrences(of: jwtShaped, with: redacted, options: .regularExpression)
            .replacingOccurrences(of: longBase64UrlRun, with: redacted, options: .regularExpression)
    }

    private static let redacted = "[REDACTED]"
    // Three base64url segments joined by dots: an id_token, access_token or JWT-shaped code.
    private static let jwtShaped =
        "[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}"
    // Anything else long and opaque: an opaque access token, a refresh token, a code_verifier.
    // 32 is above any OAuth error code or human wording and below every credential we send.
    private static let longBase64UrlRun = "[A-Za-z0-9_-]{32,}"

}

/// Response from a PAR (Pushed Authorization Request) call.
struct ParResponse {
    let requestUri: String
    let expiresIn: Int
}

/// Exception thrown when CAS communication fails. Internal: ``KrdpassAuth`` translates it into
/// the public ``KrdpassError`` at its own boundary. `LocalizedError` so the parsed message and
/// status survive access through the `Error` existential.
struct CasException: Error, LocalizedError, CustomStringConvertible, Sendable {
    let message: String
    let statusCode: Int?

    init(message: String, statusCode: Int? = nil) {
        self.message = message
        self.statusCode = statusCode
    }

    /// Whether the caller may safely retry: a 5xx, 408 or 429 is transient; a 4xx or an
    /// unparseable response is permanent.
    var isRetryable: Bool {
        guard let statusCode = statusCode else { return false }
        return statusCode >= 500 || statusCode == 408 || statusCode == 429
    }

    private var fullMessage: String {
        if let statusCode = statusCode {
            return "\(message) (status: \(statusCode))"
        }
        return message
    }

    var errorDescription: String? { fullMessage }

    var description: String { fullMessage }
}
