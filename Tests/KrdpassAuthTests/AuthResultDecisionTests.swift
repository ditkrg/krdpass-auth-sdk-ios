import XCTest

@testable import KrdpassAuth

/// Covers the fail-closed auth-result decision `handle()` reaches once the redirect URL has been
/// parsed. This is the SDK's CSRF / response-injection defense: a returned authorization code is
/// accepted ONLY when the returned state equals the state we sent. Every accept/reject branch is
/// asserted here, without a live flow.
final class AuthResultDecisionTests: XCTestCase {

    private let sentState = "the-state-we-sent"
    private let ourIssuer = "https://account.id.krd"

    private func decide(
        code: String? = nil,
        returnedState: String? = nil,
        error: String? = nil,
        errorDescription: String? = nil,
        returnedIss: String? = nil,
        expectedState: String? = "the-state-we-sent",
        expectedIssuer: String? = "https://account.id.krd"
    ) -> AuthResult {
        KrdpassAuth.decideAuthResult(
            code: code, returnedState: returnedState, error: error,
            errorDescription: errorDescription, returnedIss: returnedIss,
            expectedState: expectedState, expectedIssuer: expectedIssuer)
    }

    // MARK: - Code branch

    func testCodeWithMatchingState_isSuccess() {
        let result = decide(code: "auth-code-xyz", returnedState: sentState)
        guard case .success(let response) = result else {
            return XCTFail("Expected .success, got \(result)")
        }
        XCTAssertEqual(response.code, "auth-code-xyz")
        XCTAssertEqual(response.state, sentState)
    }

    func testCodeWithMismatchedState_isRejected() {
        assertError(
            decide(code: "auth-code-xyz", returnedState: "attacker-state"), "state_mismatch")
    }

    func testCodeWithNoReturnedState_isRejected() {
        assertError(decide(code: "auth-code-xyz", returnedState: nil), "state_mismatch")
    }

    func testCodeIsRejectedWhenWeNeverRecordedAnExpectedState() {
        assertError(
            decide(code: "auth-code-xyz", returnedState: sentState, expectedState: nil),
            "state_mismatch")
    }

    func testNeitherCodeNorError_isNoCode() {
        assertError(decide(), "no_code")
    }

    // MARK: - Error branch

    func testCancellationCodesAreCanonicalizedToCancelled() {
        for code in [
            "access_denied", "cancelled", "user_cancelled", "login_required", "consent_denied",
        ] {
            let result = decide(
                returnedState: sentState, error: code, errorDescription: "User said no")
            assertError(result, "cancelled")
            guard case .error(let error) = result else { return XCTFail("Expected .error") }
            // The reason CAS sent rides through untouched; the canonical code hides which of the
            // five it was, so this field is the only place it survives.
            XCTAssertEqual(error.errorDescription, "User said no")
        }
    }

    func testCancellationWithNoDescription_carriesNoDescription() {
        // The description is passed through, not backfilled with canonical text.
        let result = decide(returnedState: sentState, error: "access_denied")
        guard case .error(let error) = result else {
            return XCTFail("Expected .error, got \(result)")
        }
        XCTAssertEqual(error.error, "cancelled")
        XCTAssertNil(error.errorDescription)
    }

    func testUnknownProviderError_passesThroughVerbatim() {
        let result = decide(
            returnedState: sentState, error: "server_error", errorDescription: "boom")
        guard case .error(let error) = result else {
            return XCTFail("Expected .error, got \(result)")
        }
        XCTAssertEqual(error.error, "server_error")
        XCTAssertEqual(error.errorDescription, "boom")
    }

    func testAnOversizedProviderDescriptionIsTruncated() {
        // The provider's error_description is arbitrary upstream text, and it reaches the host
        // app verbatim.
        let result = decide(
            returnedState: sentState, error: "server_error",
            errorDescription: String(repeating: "upstream failure ", count: 250))
        guard case .error(let error) = result else {
            return XCTFail("Expected .error, got \(result)")
        }
        let description = error.errorDescription ?? ""
        XCTAssertTrue(description.hasSuffix("...[truncated]"))
        XCTAssertLessThan(description.count, 400, "description was \(description.count) chars")
    }

    func testErrorWithMismatchedState_isRejected() {
        assertError(
            decide(returnedState: "attacker-state", error: "server_error"), "state_mismatch")
    }

    func testErrorWithNoReturnedState_isRejected() {
        assertError(decide(returnedState: nil, error: "server_error"), "state_mismatch")
    }

    func testCancellationWithMismatchedState_isRejectedAsCsrfNotCancelled() {
        assertError(
            decide(returnedState: "attacker-state", error: "access_denied"), "state_mismatch")
    }

    // MARK: - RFC 9207 iss

    func testCodeWithMatchingIss_isSuccess() {
        let result = decide(code: "auth-code-xyz", returnedState: sentState, returnedIss: ourIssuer)
        guard case .success = result else { return XCTFail("Expected .success, got \(result)") }
    }

    func testCodeWithMismatchedIss_isRejected() {
        assertError(
            decide(
                code: "auth-code-xyz", returnedState: sentState,
                returnedIss: "https://attacker.example"),
            "issuer_mismatch")
    }

    func testIssIsComparedExactlyWithoutUrlNormalisation() {
        // Same convention as the id_token iss claim check: exact string equality.
        assertError(
            decide(code: "auth-code-xyz", returnedState: sentState, returnedIss: ourIssuer + "/"),
            "issuer_mismatch")
    }

    func testCodeWithNoIss_isStillSuccess() {
        // RFC 9207 iss is optional, and CAS omits it entirely on error responses.
        let result = decide(code: "auth-code-xyz", returnedState: sentState, returnedIss: nil)
        guard case .success = result else { return XCTFail("Expected .success, got \(result)") }
    }

    func testIssIsCheckedAfterState() {
        assertError(
            decide(
                code: "auth-code-xyz", returnedState: "attacker-state",
                returnedIss: "https://attacker.example"),
            "state_mismatch")
    }

    func testErrorResponseIsNotRejectedForItsIss() {
        // No credential is delivered on the error branch, and CAS sends no iss there at all.
        assertError(
            decide(
                returnedState: sentState, error: "server_error",
                returnedIss: "https://attacker.example"),
            "server_error")
    }

    private func assertError(
        _ result: AuthResult, _ expectedCode: String, file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .error(let error) = result else {
            return XCTFail("Expected .error but was \(result)", file: file, line: line)
        }
        XCTAssertEqual(error.error, expectedCode, file: file, line: line)
    }
}
