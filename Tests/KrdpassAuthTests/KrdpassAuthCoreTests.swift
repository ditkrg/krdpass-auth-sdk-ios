import XCTest

@testable import KrdpassAuth

@MainActor
final class KrdpassAuthCoreTests: XCTestCase {

    func testBuildAuthorizationUrl_constructsCorrectOAuthUrl() async throws {
        let config = KrdpassConfig(
            clientId: "test-client-123",
            redirectUri: "https://example.com/auth/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let authUrl = try auth.buildAuthorizationUrl(
            requestUri: "urn:ietf:params:oauth:request_uri:abc123", state: "test-state"
        )

        XCTAssertTrue(authUrl.hasPrefix("https://app.pass.krd/connect/authorize?"))

        guard let urlComponents = URLComponents(string: authUrl) else {
            XCTFail("Invalid URL constructed")
            return
        }

        let queryItems = urlComponents.queryItems ?? []
        let params = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value ?? "") })

        XCTAssertEqual(params["client_id"], "test-client-123")
        XCTAssertEqual(params["request_uri"], "urn:ietf:params:oauth:request_uri:abc123")
        XCTAssertEqual(params["state"], "test-state")
        // The deployed provider needs it to send the user back before it resolves the
        // request_uri; without it the flow strands with no callback.
        XCTAssertEqual(params["redirect_uri"], "https://example.com/auth/callback")
    }

    func testBuildAuthorizationUrl_worksWithDevelopmentEnvironment() async throws {
        let config = KrdpassConfig(
            clientId: "test-client-456",
            redirectUri: "https://example.com/auth/callback",
            environment: .development
        )
        let auth = KrdpassAuth(config: config)

        let authUrl = try auth.buildAuthorizationUrl(
            requestUri: "urn:ietf:params:oauth:request_uri:dev123", state: "test-state"
        )

        XCTAssertTrue(authUrl.hasPrefix("https://app.krdpass.dev.krd/connect/authorize?"))

        guard let urlComponents = URLComponents(string: authUrl) else {
            XCTFail("Invalid URL constructed")
            return
        }

        let queryItems = urlComponents.queryItems ?? []
        let params = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value ?? "") })

        XCTAssertEqual(params["client_id"], "test-client-456")
        XCTAssertEqual(params["request_uri"], "urn:ietf:params:oauth:request_uri:dev123")
        XCTAssertEqual(params["redirect_uri"], "https://example.com/auth/callback")
    }

    func testCurrentConfig_returnsConfigFromInit() async {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let currentConfig = auth.currentConfig

        XCTAssertEqual(currentConfig.clientId, "test-client")
        XCTAssertEqual(currentConfig.redirectUri, "https://example.com/callback")
        XCTAssertEqual(currentConfig.environment, .production)
    }

    func testCanHandle_returnsFalseWhenNotAuthenticating() async {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let isAuthenticating = auth.isAuthenticating
        XCTAssertFalse(isAuthenticating)

        let canHandle = auth.canHandle(URL(string: "https://example.com/callback")!)
        XCTAssertFalse(canHandle)
    }

    func testAuthenticate_rejectsNonPositiveTimeout() async {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let expectation = expectation(description: "completion")
        await MainActor.run {
            auth.authenticate(
                requestUri: "urn:ietf:params:oauth:request_uri:test", state: "test-state",
                timeout: 0
            ) { result in
                switch result {
                case .error(let error):
                    XCTAssertEqual(error.error, "platform_error")
                default:
                    XCTFail("Expected platform_error for non-positive timeout")
                }
                expectation.fulfill()
            }
        }

        await fulfillment(of: [expectation], timeout: 1.0)
    }

    func testGeneratePkcePair_returnsValidPair() async throws {
        let config = KrdpassConfig(clientId: "test", redirectUri: "https://test.com")
        let auth = KrdpassAuth(config: config)

        let pair = try auth.generatePkcePair()

        XCTAssertFalse(pair.codeVerifier.isEmpty)
        XCTAssertFalse(pair.codeChallenge.isEmpty)
        XCTAssertEqual(pair.method, "S256")

        let expectedChallenge = PkceGenerator.computeChallenge(pair.codeVerifier)
        XCTAssertEqual(pair.codeChallenge, expectedChallenge)
    }

    func testHandleError_withMatchingState_acceptsError() async throws {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)
        let expectedState = "valid-state-123"

        let expectation = XCTestExpectation(description: "Error callback")

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test", state: expectedState
        ) { result in
            if case .error(let error) = result {
                XCTAssertEqual(error.error, "server_error")
                XCTAssertEqual(error.message, "Something went wrong")
            } else {
                XCTFail("Expected error result")
            }
            expectation.fulfill()
        }

        let errorUrl = URL(
            string:
                "https://example.com/callback?error=server_error&error_description=Something%20went%20wrong&state=\(expectedState)"
        )!
        _ = auth.handle(errorUrl)

        await fulfillment(of: [expectation], timeout: 1.0)
    }
}
