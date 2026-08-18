import XCTest

@testable import KrdpassAuth

/// Locks the three-code failure contract of the public `verifyToken(idToken:)`:
/// `invalid_id_token` (signature, claims or exp), `network_error` (JWKS fetch failed, a retry
/// may help), `verification_failed` (anything else).
final class VerifyTokenErrorContractTests: XCTestCase {

    private func code(for error: Error) -> String? {
        KrdpassAuth.verifyErrorToKrdpassError(error).code
    }

    func testClaimAndSignatureFailuresAreInvalidIdToken() {
        XCTAssertEqual(
            code(for: TokenVerificationError.invalidClaims("iss mismatch")), "invalid_id_token")
        XCTAssertEqual(
            code(for: TokenVerificationError.invalidSignature("no match")), "invalid_id_token")
        XCTAssertEqual(
            code(for: TokenVerificationError.invalidToken("not a JWT")), "invalid_id_token")
        XCTAssertEqual(code(for: TokenVerificationError.keyNotFound), "invalid_id_token")
        XCTAssertEqual(
            code(for: TokenVerificationError.unsupportedAlgorithm("none")), "invalid_id_token")
        XCTAssertEqual(code(for: TokenVerificationError.unsupportedKeyType), "invalid_id_token")
        XCTAssertEqual(code(for: TokenVerificationError.invalidKey(nil)), "invalid_id_token")
    }

    func testJwksFetchFailureIsNetworkErrorNotInvalidIdToken() {
        // The token may be perfectly good; only the key set could not be reached. Reporting
        // invalid_id_token here would tell the caller to stop retrying.
        XCTAssertEqual(code(for: TokenVerificationError.jwksFetchFailed), "network_error")
    }

    func testTransportFailureIsNetworkError() {
        XCTAssertEqual(code(for: URLError(.notConnectedToInternet)), "network_error")
        XCTAssertEqual(code(for: URLError(.timedOut)), "network_error")
    }

    func testAnythingElseFallsBackToVerificationFailed() {
        struct Unexpected: Error {}
        XCTAssertEqual(code(for: Unexpected()), "verification_failed")
    }

    func testAlreadyTypedKrdpassErrorPassesThroughSoItsCodeIsNotRenamed() {
        let original = KrdpassError.authenticationFailed(
            "Token response did not include an id_token", code: "invalid_id_token")

        let translated = KrdpassAuth.verifyErrorToKrdpassError(original)

        XCTAssertEqual(translated.code, "invalid_id_token")
        guard case .authenticationFailed(let message, _) = translated else {
            return XCTFail("expected the original case, got \(translated)")
        }
        XCTAssertEqual(message, "Token response did not include an id_token")
    }

    func testUnderlyingReasonSurvivesVerbatim() {
        // A canonical string would hide which claim failed.
        let underlying = TokenVerificationError.invalidClaims("JWT audience rejected: wrong-client")

        let translated = KrdpassAuth.verifyErrorToKrdpassError(underlying)

        guard case .authenticationFailed(let message, _) = translated else {
            return XCTFail("expected authenticationFailed, got \(translated)")
        }
        XCTAssertTrue(
            message.contains(underlying.localizedDescription),
            "claim detail lost: \(message)")
    }

    func testNoVerifyFailureEmitsNonceOrIssuerMismatch() {
        let failures: [Error] = [
            TokenVerificationError.invalidClaims("iss mismatch"),
            TokenVerificationError.jwksFetchFailed,
            TokenVerificationError.invalidSignature("no match"),
            URLError(.timedOut),
        ]

        for failure in failures {
            let emitted = code(for: failure)
            XCTAssertTrue(
                ["invalid_id_token", "network_error", "verification_failed"].contains(
                    emitted ?? ""),
                "unexpected code \(emitted ?? "nil") for \(failure)")
        }
    }
}
