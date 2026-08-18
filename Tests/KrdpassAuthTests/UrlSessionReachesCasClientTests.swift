import XCTest

@testable import KrdpassAuth

/// The `urlSession:` parameter on the public initialisers has to reach the CAS client, not only
/// the JWT verifier: a session injected for certificate pinning must cover every request.
/// MockURLProtocol only serves sessions configured with it, so a call that reached
/// URLSession.shared instead would attempt real network I/O and fail.
final class UrlSessionReachesCasClientTests: XCTestCase {

    private func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    @MainActor
    private func makeAuth(session: URLSession) -> KrdpassAuth {
        KrdpassAuth(
            config: KrdpassConfig(
                clientId: "client",
                redirectUri: "https://example.gov/_krdpass/oauth/callback",
                environment: .production),
            urlSession: session)
    }

    override func setUp() {
        super.setUp()
        MockURLProtocol.responseQueue = []
        MockURLProtocol.lastRequest = nil
    }

    @MainActor
    func testInjectedSessionCarriesTheUserInfoRequest() async throws {
        let auth = makeAuth(session: makeSession())
        MockURLProtocol.setResponse(Data(#"{"sub":"user-123"}"#.utf8))

        let info = try await auth.getUserInfo(accessToken: "access-token")

        XCTAssertEqual(info.sub, "user-123")
        XCTAssertEqual(
            MockURLProtocol.lastRequest?.url?.absoluteString,
            KrdpassEnvironment.production.userInfoEndpoint,
            "the userinfo request must go through the injected session")
    }

    @MainActor
    func testInjectedSessionCarriesTheRefreshRequest() async throws {
        let auth = makeAuth(session: makeSession())
        MockURLProtocol.setResponse(
            Data(#"{"access_token":"new-access","token_type":"Bearer","expires_in":3600}"#.utf8))

        let tokens = try await auth.refreshTokens(refreshToken: "refresh-token")

        XCTAssertEqual(tokens.accessToken, "new-access")
        XCTAssertEqual(
            MockURLProtocol.lastRequest?.url?.absoluteString,
            KrdpassEnvironment.production.tokenEndpoint,
            "the refresh request must go through the injected session")
    }

    /// The signIn path validates its id_token before trusting it. These two pin the refreshed
    /// id_token to the same checks: signature, issuer, audience and expiry.
    @MainActor
    func testRefreshValidatesTheReturnedIdToken() async throws {
        let auth = makeAuth(session: makeSession())
        let idToken = try JWTTestSupport.makeToken(
            issuer: KrdpassEnvironment.production.authServerUrl,
            audience: "client",
            expiresIn: 300)
        MockURLProtocol.setResponse(
            Data(
                """
                {"access_token":"new-access","token_type":"Bearer","expires_in":3600,\
                "id_token":"\(idToken)"}
                """.utf8))
        // The validator fetches the JWKS after the token response (FIFO).
        MockURLProtocol.enqueueResponse(
            JWTTestSupport.jwkJson.data(using: .utf8) ?? Data(), statusCode: 200,
            headers: ["Content-Type": "application/json"])

        let tokens = try await auth.refreshTokens(refreshToken: "refresh-token")

        XCTAssertEqual(tokens.accessToken, "new-access")
        XCTAssertEqual(tokens.idToken, idToken)
    }

    @MainActor
    func testRefreshRejectsAnIdTokenFromTheWrongIssuer() async throws {
        let auth = makeAuth(session: makeSession())
        let idToken = try JWTTestSupport.makeToken(
            issuer: "https://attacker.example", audience: "client", expiresIn: 300)
        MockURLProtocol.setResponse(
            Data(
                """
                {"access_token":"new-access","token_type":"Bearer","expires_in":3600,\
                "id_token":"\(idToken)"}
                """.utf8))
        MockURLProtocol.enqueueResponse(
            JWTTestSupport.jwkJson.data(using: .utf8) ?? Data(), statusCode: 200,
            headers: ["Content-Type": "application/json"])

        do {
            _ = try await auth.refreshTokens(refreshToken: "refresh-token")
            XCTFail("expected the refreshed id_token to be rejected on its issuer")
        } catch let error as KrdpassError {
            XCTAssertEqual(error.code, "invalid_id_token")
        }
    }

    /// The token may be perfectly good; only the key set could not be reached. Reporting
    /// invalid_id_token here tells the caller to sign the user out over a network blip.
    @MainActor
    func testRefreshReportsAnUnreachableJwksAsRetryable() async throws {
        let auth = makeAuth(session: makeSession())
        let idToken = try JWTTestSupport.makeToken(
            issuer: KrdpassEnvironment.production.authServerUrl,
            audience: "client",
            expiresIn: 300)
        MockURLProtocol.setResponse(
            Data(
                """
                {"access_token":"new-access","token_type":"Bearer","expires_in":3600,\
                "id_token":"\(idToken)"}
                """.utf8))
        MockURLProtocol.enqueueResponse(Data(), statusCode: 503)

        do {
            _ = try await auth.refreshTokens(refreshToken: "refresh-token")
            XCTFail("expected the unreachable JWKS to fail the refresh")
        } catch let error as KrdpassError {
            XCTAssertEqual(error.code, "network_error")
        }
    }

    @MainActor
    func testInjectedSessionCarriesTheRevokeRequest() async throws {
        let auth = makeAuth(session: makeSession())
        MockURLProtocol.setResponse(Data(), statusCode: 200)

        try await auth.revokeToken(token: "access-token")

        XCTAssertEqual(
            MockURLProtocol.lastRequest?.url?.absoluteString,
            KrdpassEnvironment.production.revocationEndpoint,
            "the revoke request must go through the injected session")
    }
}
