import XCTest

@testable import KrdpassAuth

final class CasClientTests: XCTestCase {

    private var mockSession: URLSession!
    private var casClient: CasClient!

    override func setUp() {
        super.setUp()

        // protocolClasses must be set on the configuration BEFORE creating the URLSession.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        mockSession = URLSession(configuration: configuration)

        casClient = CasClient(
            clientId: "test-client-id", environment: .production, urlSession: mockSession)

        MockURLProtocol.responseQueue = []
        MockURLProtocol.lastRequest = nil
        MockURLProtocol.lastRequestBody = ""
    }

    override func tearDown() {
        casClient = nil
        super.tearDown()
    }

    func testPushAuthorizationRequest_succeedsWithValidResponse() async throws {
        let expectedRequestUri = "urn:ietf:params:oauth:request_uri:abc123"
        let responseData = """
            {
                "request_uri": "\(expectedRequestUri)",
                "expires_in": 300
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        let result = try await casClient.pushAuthorizationRequest(
            codeChallenge: "test-challenge",
            redirectUri: "https://example.com/callback",
            scopes: ["openid", "profile"]
        )

        XCTAssertEqual(result.requestUri, expectedRequestUri)
        XCTAssertEqual(result.expiresIn, 300)

        XCTAssertEqual(MockURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(MockURLProtocol.lastRequest?.url?.path, "/connect/par")

        let bodyString = MockURLProtocol.lastRequestBody
        XCTAssertTrue(bodyString.contains("client_id=test-client-id"))
        XCTAssertTrue(bodyString.contains("response_type=code"))
        XCTAssertTrue(bodyString.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
        XCTAssertTrue(bodyString.contains("scope=openid%20profile"))
        XCTAssertTrue(bodyString.contains("code_challenge=test-challenge"))
        XCTAssertTrue(bodyString.contains("code_challenge_method=S256"))
    }

    func testPushAuthorizationRequest_failsWithMissingRequestUri() async {
        let responseData = """
            {
                "expires_in": 300
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        do {
            _ = try await casClient.pushAuthorizationRequest(
                codeChallenge: "test-challenge",
                redirectUri: "https://example.com/callback",
                scopes: ["openid"]
            )
            XCTFail("Expected error for missing request_uri")
        } catch let error as CasException {
            XCTAssertTrue(
                error.message.contains("request_uri"),
                "Expected error about request_uri, got: \(error.message)")
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testPushAuthorizationRequest_failsWithEmptyRequestUri() async throws {
        let responseData = """
            {
                "request_uri": "",
                "expires_in": 300
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        do {
            _ = try await casClient.pushAuthorizationRequest(
                codeChallenge: "test-challenge",
                redirectUri: "https://example.com/callback",
                scopes: ["openid"]
            )
            XCTFail("Expected error for empty request_uri")
        } catch let error as CasException {
            XCTAssertTrue(
                error.message.contains("Missing or empty request_uri"),
                "Expected error about empty request_uri, got: \(error.message)")
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testPushAuthorizationRequest_failsWithHttpError() async {
        let errorResponse = """
            {
                "error": "invalid_request",
                "error_description": "Invalid parameters"
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(errorResponse, statusCode: 400, headers: [:])

        do {
            _ = try await casClient.pushAuthorizationRequest(
                codeChallenge: "test-challenge",
                redirectUri: "https://example.com/callback",
                scopes: ["openid"]
            )
            XCTFail("Expected HTTP error")
        } catch let error as CasException {
            XCTAssertEqual(error.statusCode, 400)
            XCTAssertTrue(error.message.contains("invalid_request"))
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testExchangeCodeForTokens_succeedsWithValidResponse() async throws {
        let responseData = """
            {
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test-refresh-token",
                "id_token": "test-id-token",
                "scope": "openid profile"
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        let result = try await casClient.exchangeCodeForTokens(
            code: "test-auth-code",
            codeVerifier: "test-verifier",
            redirectUri: "https://example.com/callback"
        )

        XCTAssertEqual(result.accessToken, "test-access-token")
        XCTAssertEqual(result.tokenType, "Bearer")
        XCTAssertEqual(result.expiresIn, 3600)
        XCTAssertEqual(result.refreshToken, "test-refresh-token")
        XCTAssertEqual(result.idToken, "test-id-token")
        XCTAssertEqual(result.scope, "openid profile")

        XCTAssertEqual(MockURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(MockURLProtocol.lastRequest?.url?.path, "/connect/token")

        let bodyString = MockURLProtocol.lastRequestBody
        XCTAssertTrue(bodyString.contains("grant_type=authorization_code"))
        XCTAssertTrue(bodyString.contains("client_id=test-client-id"))
        XCTAssertTrue(bodyString.contains("code=test-auth-code"))
        XCTAssertTrue(bodyString.contains("code_verifier=test-verifier"))
        XCTAssertTrue(bodyString.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
    }

    func testExchangeCodeForTokens_handlesMinimalResponse() async throws {
        let responseData = """
            {
                "access_token": "minimal-token"
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        let result = try await casClient.exchangeCodeForTokens(
            code: "test-code",
            codeVerifier: "test-verifier",
            redirectUri: "https://example.com/callback"
        )

        XCTAssertEqual(result.accessToken, "minimal-token")
        XCTAssertEqual(result.tokenType, "Bearer")
        XCTAssertEqual(result.expiresIn, 3600)
        XCTAssertNil(result.refreshToken)
        XCTAssertNil(result.idToken)
        XCTAssertNil(result.scope)
    }

    func testExchangeCodeForTokens_failsWithMissingAccessToken() async {
        let responseData = """
            {
                "token_type": "Bearer",
                "expires_in": 3600
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        do {
            _ = try await casClient.exchangeCodeForTokens(
                code: "test-code",
                codeVerifier: "test-verifier",
                redirectUri: "https://example.com/callback"
            )
            XCTFail("Expected error for missing access_token")
        } catch let error as CasException {
            XCTAssertTrue(
                error.message.contains("access_token"),
                "Expected error about access_token, got: \(error.message)")
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testExchangeCodeForTokens_failsWithEmptyAccessToken() async throws {
        let responseData = """
            {
                "access_token": "",
                "token_type": "Bearer"
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        do {
            _ = try await casClient.exchangeCodeForTokens(
                code: "test-code",
                codeVerifier: "test-verifier",
                redirectUri: "https://example.com/callback"
            )
            XCTFail("Expected error for empty access_token")
        } catch let error as CasException {
            XCTAssertTrue(
                error.message.contains("Missing or empty access_token"),
                "Expected error about empty access_token, got: \(error.message)")
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testExchangeCodeForTokens_failsWithHttpError() async {
        let errorResponse = """
            {
                "error": "invalid_grant",
                "error_description": "Authorization code expired"
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(errorResponse, statusCode: 400, headers: [:])

        do {
            _ = try await casClient.exchangeCodeForTokens(
                code: "expired-code",
                codeVerifier: "test-verifier",
                redirectUri: "https://example.com/callback"
            )
            XCTFail("Expected HTTP error")
        } catch let error as CasException {
            XCTAssertEqual(error.statusCode, 400)
            XCTAssertTrue(error.message.contains("invalid_grant"))
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testPushAuthorizationRequest_includesStateAndNonce() async throws {
        let responseData = """
            {
                "request_uri": "urn:ietf:params:oauth:request_uri:xyz789",
                "expires_in": 300
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        _ = try await casClient.pushAuthorizationRequest(
            codeChallenge: "test-challenge",
            redirectUri: "https://example.com/callback",
            scopes: ["openid"],
            state: "test-state",
            nonce: "test-nonce"
        )

        let bodyString = MockURLProtocol.lastRequestBody
        XCTAssertTrue(bodyString.contains("state=test-state"))
        XCTAssertTrue(bodyString.contains("nonce=test-nonce"))
    }

    func testPushAuthorizationRequest_excludesOptionalParamsWhenNil() async throws {
        let responseData = """
            {
                "request_uri": "urn:ietf:params:oauth:request_uri:xyz789",
                "expires_in": 300
            }
            """.data(using: .utf8)!

        MockURLProtocol.setResponse(responseData, statusCode: 200, headers: [:])

        _ = try await casClient.pushAuthorizationRequest(
            codeChallenge: "test-challenge",
            redirectUri: "https://example.com/callback",
            scopes: ["openid"]
        )

        XCTAssertEqual(MockURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(MockURLProtocol.lastRequest?.url?.path, "/connect/par")
        let bodyString = MockURLProtocol.lastRequestBody
        XCTAssertFalse(bodyString.contains("state="))
        XCTAssertFalse(bodyString.contains("nonce="))
    }

    func testRevokeToken_succeedsWithEmpty200Body() async throws {
        // RFC 7009: a successful revocation returns HTTP 200 with an EMPTY body, and
        // JSONSerialization throws on empty input, so postForm must short-circuit.
        MockURLProtocol.setResponse(Data(), statusCode: 200, headers: [:])

        try await casClient.revokeToken(token: "some-access-token")

        XCTAssertEqual(MockURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(MockURLProtocol.lastRequest?.url?.path, "/connect/revocation")
        let bodyString = MockURLProtocol.lastRequestBody
        XCTAssertTrue(bodyString.contains("client_id=test-client-id"))
        XCTAssertTrue(bodyString.contains("token=some-access-token"))
    }

    func testRefreshTokens_doesNotRetry() async {
        // A rotated refresh token is single-use: a retry replays a spent token and can revoke
        // the whole token family. Queue a 500 then a success; the call must fail on the first
        // response and leave the second untouched.
        MockURLProtocol.enqueueResponse(Data(), statusCode: 500, headers: [:])
        MockURLProtocol.enqueueResponse(
            Data(#"{"access_token":"should-never-be-reached","token_type":"Bearer"}"#.utf8),
            statusCode: 200, headers: [:])

        do {
            _ = try await casClient.refreshTokens(refreshToken: "single-use-refresh-token")
            XCTFail("expected the refresh to fail on the 500 without retrying")
        } catch {
            // expected
        }

        XCTAssertEqual(
            MockURLProtocol.responseQueue.count, 1,
            "the refresh grant must be sent exactly once, leaving the queued success unconsumed")
    }

    func testRevokeToken_failsWithHttpError() async {
        MockURLProtocol.setResponse(Data(), statusCode: 400, headers: [:])
        do {
            try await casClient.revokeToken(token: "some-access-token")
            XCTFail("expected revocation to throw on a 4xx response")
        } catch let error as CasException {
            XCTAssertEqual(error.statusCode, 400)
        } catch {
            XCTFail("Expected CasException, got \(error)")
        }
    }

    func testFormURLEncode_encodesPlusAndSpaceStrictly() {
        // The strict encoder must emit %2B for plus and %20 for space.
        let body = CasClient.formURLEncode([
            URLQueryItem(name: "value", value: "a+b c"),
            URLQueryItem(name: "unreserved", value: "AZaz09-._~"),
        ])

        XCTAssertEqual(body, "value=a%2Bb%20c&unreserved=AZaz09-._~")
    }

}
