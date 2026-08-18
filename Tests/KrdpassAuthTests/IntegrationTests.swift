import XCTest

@testable import KrdpassAuth

@MainActor
final class IntegrationTests: XCTestCase {

    private var mockUrlOpener: MockUrlOpener!

    private static let testConfig = KrdpassConfig(
        clientId: "test-client-id",
        redirectUri: "https://example.com/auth/callback",
        environment: .production
    )

    override func setUp() {
        super.setUp()
        MockURLProtocol.responseQueue = []
        MockURLProtocol.lastRequest = nil
        MockURLProtocol.lastRequestBody = ""
    }

    private func createMockedAuth(config: KrdpassConfig = testConfig) async -> KrdpassAuth {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        let session = URLSession(configuration: configuration)
        mockUrlOpener = MockUrlOpener()
        // Same mocked session for JWKS fetches too, so id_token validation hits MockURLProtocol.
        return KrdpassAuth(
            config: config,
            urlOpener: mockUrlOpener,
            urlSession: session
        )
    }

    func testAuthenticate_handlesSuccessfulFlow() async {
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(description: "Authentication completes")

        deliverRedirect(to: auth) { "code=test-auth-code&state=test-state" }

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.code, "test-auth-code")
                XCTAssertEqual(response.state, "test-state")
                expectation.fulfill()
            default:
                XCTFail("Expected success, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    /// A cancellation CAS reports on the redirect is an error result carrying the canonical
    /// `cancelled` code, not `.cancelled`. That case is reserved for a flow that ended with no
    /// response at all.
    func testAuthenticate_handlesCancellation() async {
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(description: "Authentication cancelled")

        deliverRedirect(to: auth) {
            "error=access_denied&error_description=User%20cancelled&state=test-state"
        }

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .error(let error):
                XCTAssertEqual(error.error, "cancelled")
                XCTAssertEqual(error.errorDescription, "User cancelled")
                expectation.fulfill()
            default:
                XCTFail("Expected cancellation, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    /// Every cancellation code (access_denied, login_required, consent_denied, ...) collapses
    /// to the canonical `cancelled` code, but the real reason CAS sent (e.g. "not eligible for
    /// citizen_identity") must not be lost: it rides through on `errorDescription`.
    func testAuthenticate_cancellationPreservesProviderDescription() async {
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(
            description: "Authentication cancelled with the provider description")

        deliverRedirect(to: auth) {
            "error=login_required&error_description=not%20eligible%20for%20citizen_identity"
                + "&state=test-state"
        }

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .error(let error):
                XCTAssertEqual(error.error, "cancelled")
                XCTAssertEqual(error.errorDescription, "not eligible for citizen_identity")
                expectation.fulfill()
            default:
                XCTFail("Expected cancellation, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    /// When the system can't open the KRDPASS app (not installed, or Universal Link ownership
    /// unverified), the opener's completion reports failure and the flow must fail closed with
    /// `provider_not_installed` rather than silently falling back to a browser.
    func testAuthenticate_reportsProviderNotInstalledWhenOpenFails() async {
        let auth = await createMockedAuth()
        mockUrlOpener.simulateSuccess = false
        let expectation = XCTestExpectation(description: "Provider not installed reported")

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .error(let error):
                XCTAssertEqual(error.error, "provider_not_installed")
                expectation.fulfill()
            default:
                XCTFail("Expected provider_not_installed, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    func testAuthenticate_rejectsStateMismatch() async {
        // Flow-level wiring check: a mismatched state is a CSRF signal and handle() must fail
        // closed. The decision's branches are covered by AuthResultDecisionTests.
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(description: "State mismatch rejected")

        deliverRedirect(to: auth) { "code=test-auth-code&state=forged-state" }

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "expected-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .error(let error):
                XCTAssertEqual(error.error, "state_mismatch")
                expectation.fulfill()
            default:
                XCTFail("Expected state_mismatch error, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    /// The callback URL is third-party-controllable, so a repeated query key must not trap;
    /// handle() resolves it last-wins. The duplicate has to come from the configured redirect
    /// URI itself, since a repeated OAuth response parameter is rejected by the validator first.
    func testAuthenticate_duplicateQueryKeysAreResolvedNotTrapped() async {
        let redirectUri = "https://example.com/auth/callback?a=1&a=2"
        let auth = await createMockedAuth(
            config: KrdpassConfig(
                clientId: "test-client-id", redirectUri: redirectUri, environment: .production))
        let expectation = XCTestExpectation(description: "Duplicate query key handled")

        deliverRedirect(to: auth, base: "https://example.com/auth/callback") {
            "a=1&a=2&code=test-auth-code&state=test-state"
        }

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 5.0
        ) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.code, "test-auth-code")
                expectation.fulfill()
            default:
                XCTFail("Expected the duplicate key to be resolved, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 10.0)
    }

    func testAuthenticate_handlesTimeout() async {
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(description: "Authentication times out")

        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test123",
            state: "test-state",
            timeout: 0.1
        ) { result in
            switch result {
            case .timeout:
                expectation.fulfill()
            default:
                XCTFail("Expected timeout, got \(result)")
            }
        }

        await fulfillment(of: [expectation], timeout: 2.0)
    }

    func testSignIn_handlesSuccessfulFlow() async throws {
        let config = Self.testConfig
        let auth = await createMockedAuth()

        enqueueParResponse()

        // When KRDPASS is "launched", read the state AND nonce the SDK baked into the PAR
        // request, then mint a real RS256 id_token bound to that nonce so the client-only
        // signIn id_token validation (signature + iss + aud + exp + nonce) actually passes.
        deliverRedirect(to: auth) {
            guard let state = Self.parFormValue("state"), let nonce = Self.parFormValue("nonce")
            else {
                XCTFail("Could not find state/nonce in PAR params")
                return nil
            }
            do {
                let idToken = try JWTTestSupport.makeToken(
                    issuer: config.environment.authServerUrl,
                    audience: config.clientId,
                    expiresIn: 300,
                    nonce: nonce
                )
                // Token exchange (carrying the freshly minted id_token), then the JWKS
                // the validator fetches to verify it, consumed in that order (FIFO).
                Self.enqueueTokenResponse(idToken: idToken)
                Self.enqueueJwks()
            } catch {
                XCTFail("Failed to mint id_token: \(error)")
                return nil
            }
            return "code=test-auth-code&state=\(state)"
        }

        switch await signInResult(auth) {
        case .success(let tokens):
            XCTAssertEqual(tokens.accessToken, "test-access-token")
            XCTAssertEqual(tokens.tokenType, "Bearer")
            XCTAssertEqual(tokens.expiresIn, 3600)
            XCTAssertEqual(tokens.refreshToken, "test-refresh-token")
            XCTAssertEqual(tokens.scope, "openid profile")
            XCTAssertFalse(tokens.idToken?.isEmpty ?? true)
        case .failure(let error):
            XCTFail("Expected success, got failure: \(error)")
        }
    }

    /// `signIn` reports the redirect cancellation through the same `.error` arm every other CAS
    /// error takes, so the code stays `cancelled` and the reason CAS sent survives in the
    /// message instead of being replaced by the generic "Authentication was cancelled" text.
    func testSignIn_cancellationPreservesProviderDescription() async {
        let auth = await createMockedAuth()
        enqueueParResponse()

        deliverRedirect(to: auth) {
            guard let state = Self.parFormValue("state") else {
                XCTFail("Could not find state in PAR params")
                return nil
            }
            return "error=login_required&error_description=not%20eligible%20for%20citizen_identity"
                + "&state=\(state)"
        }

        switch await signInResult(auth, scopes: ["openid"]) {
        case .success:
            XCTFail("Expected cancellation")
        case .failure(let error):
            XCTAssertEqual(error.code, "cancelled")
            XCTAssertEqual(
                error.errorDescription,
                "Authentication failed: not eligible for citizen_identity")
        }
    }

    /// The consent session dies with the request_uri, so signIn must time out at the PAR
    /// response's `expires_in`, not the (longer) requested `timeout`, when `expires_in` is
    /// shorter. Never deliver the redirect, so the only way to reach `.timeout` is the bound.
    func testSignIn_timesOutAtParExpiresInWhenShorterThanRequestedTimeout() async {
        let auth = await createMockedAuth()

        // PAR grants only 1 second, far shorter than the requested 300s timeout.
        enqueueParResponse(expiresIn: 1)

        let result = await signInResult(auth, timeout: 300.0)

        switch result {
        case .failure(.timeout):
            break
        default:
            XCTFail("Expected timeout bounded by expires_in, got \(result)")
        }
    }

    /// How the token response handed back to signIn is corrupted by `runTamperedSignIn`.
    private enum TokenTampering {
        /// The id_token carries a nonce that is not the one baked into the PAR request.
        case wrongNonce
        /// The id_token carries no nonce claim at all.
        case missingNonce
        /// The token response has no id_token at all.
        case missingIdToken
    }

    /// Drives the full mocked signIn flow (mirroring `testSignIn_handlesSuccessfulFlow`), but
    /// tampers with the token response so the id_token validation must reject it.
    private func runTamperedSignIn(_ tampering: TokenTampering) async -> Result<
        KrdpassTokenResult, KrdpassError
    > {
        let config = Self.testConfig
        let auth = await createMockedAuth()

        enqueueParResponse()

        deliverRedirect(to: auth) {
            guard let state = Self.parFormValue("state") else {
                XCTFail("Could not find state in PAR params")
                return nil
            }
            do {
                switch tampering {
                case .wrongNonce, .missingNonce:
                    let idToken = try JWTTestSupport.makeToken(
                        issuer: config.environment.authServerUrl,
                        audience: config.clientId,
                        expiresIn: 300,
                        nonce: tampering == .wrongNonce ? "wrong-nonce" : nil
                    )
                    // Token exchange, then the JWKS the validator fetches (FIFO): the
                    // signature is genuine, so validation must fail on the nonce alone.
                    Self.enqueueTokenResponse(idToken: idToken)
                    Self.enqueueJwks()
                case .missingIdToken:
                    // No JWKS enqueued: validation must fail before ever fetching keys.
                    MockURLProtocol.enqueueResponse(
                        """
                        {
                            "access_token": "test-access-token",
                            "token_type": "Bearer",
                            "expires_in": 3600
                        }
                        """.data(using: .utf8)!,
                        statusCode: 200,
                        headers: ["Content-Type": "application/json"]
                    )
                }
            } catch {
                XCTFail("Failed to mint id_token: \(error)")
                return nil
            }
            return "code=test-auth-code&state=\(state)"
        }

        return await signInResult(auth)
    }

    /// Asserts a tampered signIn run failed with the expected structured code and canonical
    /// message (see AuthResultTests), and returned no tokens.
    private func assertRejected(
        _ result: Result<KrdpassTokenResult, KrdpassError>, code: String, message: String? = nil
    ) {
        switch result {
        case .success:
            XCTFail("Expected \(code) failure, got tokens")
        case .failure(let error):
            guard case .authenticationFailed(let actualMessage, let actualCode) = error else {
                XCTFail("Expected KrdpassError.authenticationFailed, got \(error)")
                return
            }
            XCTAssertEqual(actualCode, code)
            if let message = message {
                XCTAssertEqual(actualMessage, message)
            }
        }
    }

    func testSignIn_rejectsWrongNonce() async {
        // An id_token minted for a different nonce is a token-replay signal: the flow must
        // fail closed with nonce_mismatch and surface no tokens.
        let result = await runTamperedSignIn(.wrongNonce)
        assertRejected(
            result, code: "nonce_mismatch",
            message: "ID token nonce mismatch (possible token replay)")
    }

    func testSignIn_rejectsMissingNonce() async {
        // An id_token with no nonce claim at all must be rejected the same way: absence of
        // the binding is as fatal as a mismatch.
        let result = await runTamperedSignIn(.missingNonce)
        assertRejected(result, code: "nonce_mismatch")
    }

    func testSignIn_rejectsMissingIdToken() async {
        // A token response without an id_token cannot prove who was authenticated: the flow
        // must fail closed with invalid_id_token, not fall back to the bare access token.
        let result = await runTamperedSignIn(.missingIdToken)
        assertRejected(
            result, code: "invalid_id_token",
            message: "Token response did not include an id_token")
    }

    func testSignIn_handlesNetworkFailure() async {
        let auth = await createMockedAuth()

        MockURLProtocol.setResponse(
            "Internal Server Error".data(using: .utf8)!,
            statusCode: 500,
            headers: [:]
        )

        // The timeout has to outlast the PAR retries (3 attempts plus 1s and 2s backoff) or the
        // flow legitimately reports `.timeout` first, see the PAR-phase test below.
        let result = await signInResult(auth, scopes: ["openid"], timeout: 30.0)

        switch result {
        case .success:
            XCTFail("Expected failure due to network error")
        case .failure(let error):
            XCTAssertEqual(error.code, "network_error")
        }
    }

    /// The timeout must cover the PAR phase, not just the window after KRDPASS is launched:
    /// PAR retries can run for ~93s, which would leave `signIn(timeout: 5)` wedged. A 500 makes
    /// PAR retry; the short timeout must win, and `isAuthenticating` must be clear afterwards.
    func testSignIn_timeoutCoversThePARPhase() async {
        let auth = await createMockedAuth()

        MockURLProtocol.setResponse("Internal Server Error".data(using: .utf8)!, statusCode: 500)

        let start = Date()
        let result = await signInResult(auth, scopes: ["openid"], timeout: 0.5)

        switch result {
        case .failure(.timeout):
            break
        default:
            XCTFail("Expected the PAR phase to be bounded by the timeout, got \(result)")
        }
        XCTAssertLessThan(
            Date().timeIntervalSince(start), 3.0,
            "the caller must be released at the timeout, not after the PAR retries give up")
        XCTAssertFalse(
            auth.isAuthenticating,
            "a timed-out flow must not keep the SDK busy while PAR is still retrying")
    }

    func testDeepLinkHandling_processesValidCallbacks() async {
        let auth = await createMockedAuth()

        auth.authenticate(requestUri: "test", state: "test-state", timeout: 10) { _ in }

        let testCases = [
            ("https://example.com/auth/callback?code=abc123&state=xyz", true, "Valid callback"),
            ("https://example.com/auth/callback?error=access_denied", true, "Error callback"),
            ("https://evil.com/auth/callback?code=evil", false, "Wrong domain"),
            ("https://example.com/auth/callback", true, "No params (unexpected but valid URL)"),
            ("https://example.com/wrong/path?code=abc123", false, "Path mismatch is rejected"),
            ("https://example.com:8443/auth/callback?code=abc123", false, "Wrong port"),
        ]

        for (urlString, shouldHandle, description) in testCases {
            let url = URL(string: urlString)!
            XCTAssertEqual(auth.canHandle(url), shouldHandle, description)
        }
    }

    func testConcurrentAuthentication_preventsMultipleFlows() async throws {
        let auth = await createMockedAuth()

        auth.authenticate(
            requestUri: "urn:test:first",
            state: "test-state",
            timeout: 5.0
        ) { _ in }

        try await Task.sleep(nanoseconds: 100_000_000)

        let secondExpectation = XCTestExpectation(description: "Second authentication should fail")
        auth.authenticate(
            requestUri: "urn:test:second",
            state: "test-state",
            timeout: 5.0
        ) { result in
            if case .busy = result {
                secondExpectation.fulfill()
            } else {
                XCTFail("Expected busy result for concurrent authentication, got \(result)")
            }
        }

        let thirdExpectation = XCTestExpectation(description: "Sign in direct should fail")
        auth.signIn(scopes: ["openid"]) { result in
            if case .failure(let error) = result,
                error.code == "busy"
            {
                thirdExpectation.fulfill()
            } else {
                XCTFail("Expected busy error for concurrent sign in direct, got: \(result)")
            }
        }

        await fulfillment(of: [secondExpectation, thirdExpectation], timeout: 5.0)
    }

    func testCancellation_worksDuringActiveFlow() async {
        let auth = await createMockedAuth()
        let expectation = XCTestExpectation(description: "Authentication cancelled")

        auth.authenticate(
            requestUri: "urn:test:cancel",
            state: "test-state",
            timeout: 5.0
        ) { result in
            if case .cancelled = result {
                expectation.fulfill()
            } else {
                XCTFail("Expected cancellation")
            }
        }

        auth.cancelPendingAuthentication()

        await fulfillment(of: [expectation], timeout: 2.0)
    }

    /// Deliver a redirect the moment the SDK launches the provider, so there is no fixed-delay
    /// race against the timeout. `makeQuery` runs after the PAR request, so a signIn test can
    /// read back the state and nonce the SDK generated; returning nil delivers nothing.
    private func deliverRedirect(
        to auth: KrdpassAuth,
        base: String = "https://example.com/auth/callback",
        _ makeQuery: @escaping @MainActor @Sendable () -> String?
    ) {
        mockUrlOpener.onOpen = { _ in
            Task { @MainActor [weak auth] in
                guard let auth = auth, let query = makeQuery() else { return }
                XCTAssertTrue(auth.handle(URL(string: "\(base)?\(query)")!))
            }
        }
    }

    /// Runs the async `signIn` and reshapes it into the `Result` the callback variant produces,
    /// which is what the assertions here are written against.
    private func signInResult(
        _ auth: KrdpassAuth,
        scopes: [String] = ["openid", "profile"],
        timeout: TimeInterval = 5.0
    ) async -> Result<KrdpassTokenResult, KrdpassError> {
        do {
            return .success(try await auth.signIn(scopes: scopes, timeout: timeout))
        } catch let error as KrdpassError {
            return .failure(error)
        } catch {
            XCTFail("signIn threw something other than KrdpassError: \(error)")
            return .failure(.configurationError("\(error)"))
        }
    }

    /// Extracts a form-encoded value (e.g. `state` / `nonce`) from the PAR request body.
    private static func parFormValue(_ name: String) -> String? {
        let body = MockURLProtocol.lastRequestBody
        guard let range = body.range(of: "\(name)=") else { return nil }
        let value = body[range.upperBound...].components(separatedBy: "&").first
        return (value?.isEmpty ?? true) ? nil : value
    }

    private func enqueueParResponse(expiresIn: Int = 300) {
        MockURLProtocol.enqueueResponse(
            """
            {
                "request_uri": "urn:ietf:params:oauth:request_uri:par123",
                "expires_in": \(expiresIn)
            }
            """.data(using: .utf8)!,
            statusCode: 200,
            headers: ["Content-Type": "application/json"]
        )
    }

    private static func enqueueTokenResponse(idToken: String) {
        MockURLProtocol.enqueueResponse(
            """
            {
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test-refresh-token",
                "id_token": "\(idToken)",
                "scope": "openid profile"
            }
            """.data(using: .utf8)!,
            statusCode: 200,
            headers: ["Content-Type": "application/json"]
        )
    }

    private static func enqueueJwks() {
        MockURLProtocol.enqueueResponse(
            JWTTestSupport.jwkJson.data(using: .utf8)!,
            statusCode: 200,
            headers: ["Content-Type": "application/json"]
        )
    }
}
