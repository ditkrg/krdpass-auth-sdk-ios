import XCTest

@testable import KrdpassAuth

/// Covers `decodeTokenUnverified`, the unverified JWT payload decoder, which shares the
/// `Base64Url` helper with `JwtVerifier`. (No signature verification is performed here.)
@MainActor
final class DecodeTokenTests: XCTestCase {

    private func makeAuth() async -> KrdpassAuth {
        let config = KrdpassConfig(
            clientId: "test-client",
            redirectUri: "https://example.com/callback",
            environment: .production
        )
        return KrdpassAuth(config: config)
    }

    func testDecodeTokenUnverified_returnsPayloadClaims() async throws {
        let auth = await makeAuth()
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example",
            audience: "test-client",
            expiresIn: 300,
            nonce: "n-123",
            subject: "user-42"
        )

        let claims = try auth.decodeTokenUnverified(token)

        XCTAssertEqual(claims["sub"]?.stringValue, "user-42")
        XCTAssertEqual(claims["aud"]?.stringValue, "test-client")
        XCTAssertEqual(claims["iss"]?.stringValue, "https://issuer.example")
        XCTAssertEqual(claims["nonce"]?.stringValue, "n-123")
    }

    /// `KrdpassError` is the SDK's one public error contract. `TokenVerificationError` is internal
    /// scaffolding the README does not document, so it must never be what a caller catches from a
    /// public entry point.
    private func assertKrdpassParseError(
        _ token: String, containing fragment: String, file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let auth = await makeAuth()
        XCTAssertThrowsError(try auth.decodeTokenUnverified(token), file: file, line: line) {
            error in
            XCTAssertFalse(
                error is TokenVerificationError,
                "the internal verifier error must not leak to a caller", file: file, line: line)
            guard let krdpassError = error as? KrdpassError else {
                return XCTFail("expected KrdpassError, got \(error)", file: file, line: line)
            }
            // A parse failure is a bad argument, not a failed authentication.
            XCTAssertEqual(krdpassError.code, "invalid_request", file: file, line: line)
            XCTAssertTrue(
                krdpassError.errorDescription?.contains(fragment) == true,
                "parse reason lost, got \(krdpassError.errorDescription ?? "nil")", file: file,
                line: line)
        }
    }

    func testDecodeTokenUnverified_throwsOnEmptyToken() async throws {
        await assertKrdpassParseError("", containing: "Token cannot be empty")
    }

    func testDecodeTokenUnverified_throwsWhenMissingPayloadSegment() async throws {
        await assertKrdpassParseError(
            "only-one-segment", containing: "at least a header and payload")
    }

    func testDecodeTokenUnverified_rejectsStandardBase64Payload() async throws {
        // RFC 7515 mandates base64url: "+", "/" and "=" belong to standard base64, and accepting
        // them too would give one token several valid encodings.
        await assertKrdpassParseError(
            "aGVhZGVy.eyJhIjoiPz8_In0=.c2ln", containing: "Invalid base64url encoding")
    }

    func testDecodeTokenUnverified_throwsOnNonBase64Payload() async throws {
        // Second segment "!!!" is not valid base64url, so Base64Url.decode rejects it.
        await assertKrdpassParseError("aGVhZGVy.!!!.c2ln", containing: "Invalid base64url encoding")
    }
}
