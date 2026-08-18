import XCTest

@testable import KrdpassAuth

final class AuthResultTests: XCTestCase {

    func testSuccess_carriesTheResponse() {
        guard
            case .success(let response) = AuthResult.success(
                AuthResponse(code: "abc123", state: "state123"))
        else { return XCTFail("Expected .success") }
        XCTAssertEqual(response.code, "abc123")
        XCTAssertEqual(response.state, "state123")
    }

    func testError_carriesTheAuthError() {
        let result = AuthResult.error(
            AuthError(error: "some_error", errorDescription: "Description"))
        guard case .error(let error) = result else { return XCTFail("Expected .error") }
        XCTAssertEqual(error.error, "some_error")
        XCTAssertEqual(error.message, "Description")
    }

    func testAuthError_message() {
        let error1 = AuthError(error: "code", errorDescription: "Human message")
        XCTAssertEqual(error1.message, "Human message")

        let error2 = AuthError(error: "code", errorDescription: nil)
        XCTAssertEqual(error2.message, "code")
    }

    /// Locks the canonical error strings. Both `AuthError` (authenticate path) and
    /// `KrdpassError` (signIn path) must surface the same text, so they're asserted together.
    func testCanonicalMessages_areConsistentAcrossBothApis() {
        XCTAssertEqual(AuthResult.cancelled.message, "Authentication was cancelled")
        XCTAssertEqual(AuthResult.timeout.message, "Authentication timed out")
        XCTAssertEqual(AuthResult.busy.message, "Another authentication is already in progress")

        XCTAssertEqual(KrdpassError.userCancelled.errorDescription, "Authentication was cancelled")
        XCTAssertEqual(KrdpassError.timeout.errorDescription, "Authentication timed out")
        XCTAssertEqual(
            KrdpassError.busy.errorDescription, "Another authentication is already in progress")

        XCTAssertEqual(
            AuthError.stateMismatch().message,
            "State parameter mismatch: possible CSRF or response injection")
        XCTAssertEqual(
            AuthError.issuerMismatch().message,
            "Issuer mismatch: the response did not come from the expected authorization server")
        XCTAssertEqual(
            AuthError.providerNotInstalled(installUrl: nil).message,
            "The KRDPASS app is not installed or could not be opened. Please install or update KRDPASS."
        )
        XCTAssertEqual(AuthError.noCode.message, "No authorization code received")
        XCTAssertEqual(
            AuthError.invalidRedirect().message,
            "Redirect URI does not match the exact configured endpoint")
    }

    /// Locks the canonical state-required guard string via the observable error of a minimal
    /// flow invocation; it only exists inline in `authenticate`.
    @MainActor
    func testCanonicalMessages_stateRequiredGuard() async {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let expectation = XCTestExpectation(description: "completion")
        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test", state: "", timeout: 5.0
        ) { result in
            guard case .error(let error) = result else {
                return XCTFail("Expected .error, got \(result)")
            }
            XCTAssertEqual(error.error, "invalid_request")
            XCTAssertEqual(
                error.message,
                "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn()."
            )
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1.0)
    }

    /// Accepting one would launch a flow whose callback the redirect validator then rejects.
    @MainActor
    func testStateRequiredGuard_rejectsWhitespaceOnlyState() async {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        let auth = KrdpassAuth(config: config)

        let expectation = XCTestExpectation(description: "completion")
        auth.authenticate(
            requestUri: "urn:ietf:params:oauth:request_uri:test", state: "   ", timeout: 5.0
        ) { result in
            guard case .error(let error) = result else {
                return XCTFail("Expected .error, got \(result)")
            }
            XCTAssertEqual(error.error, "invalid_request")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1.0)
    }

    /// `localizedDescription` routes through LocalizedError, so it carries the SDK's own message
    /// instead of the generic bridged NSError string.
    func testAuthError_localizedDescriptionUsesErrorDescription() {
        let error: Error = AuthError(
            error: "cancelled", errorDescription: "Authentication was cancelled")
        XCTAssertEqual(error.localizedDescription, "Authentication was cancelled")
    }

    /// `isCancelled` covers both cancellation shapes: no response at all, and a deny KRDPASS
    /// reported on the redirect (which arrives as `.error` with the canonical code `cancelled`).
    func testIsCancelled_coversBothShapesAndNothingElse() {
        XCTAssertTrue(AuthResult.cancelled.isCancelled)
        XCTAssertTrue(
            AuthResult.error(
                AuthError(error: "cancelled", errorDescription: "not eligible for citizen_identity")
            ).isCancelled)

        XCTAssertFalse(AuthResult.success(AuthResponse(code: "abc")).isCancelled)
        XCTAssertFalse(AuthResult.timeout.isCancelled)
        XCTAssertFalse(AuthResult.busy.isCancelled)
        XCTAssertFalse(AuthResult.error(AuthError(error: "timeout")).isCancelled)
        // Aliases never reach a caller: decideAuthResult canonicalizes them first.
        XCTAssertFalse(AuthResult.error(AuthError(error: "access_denied")).isCancelled)
    }

    func testAuthResponse_equality() {
        let response1 = AuthResponse(code: "abc", state: "xyz")
        let response2 = AuthResponse(code: "abc", state: "xyz")
        let response3 = AuthResponse(code: "abc", state: "different")

        XCTAssertEqual(response1, response2)
        XCTAssertNotEqual(response1, response3)
    }
}
