import XCTest

@testable import KrdpassAuth

/// The server's own diagnostic reaches the caller unchanged, and retryable vs permanent
/// failures land on different KrdpassError cases (a 4xx must never look retryable).
final class CasErrorTranslationTests: XCTestCase {

    private func casFailure(status: Int?, _ parsedError: String) -> CasException {
        CasException(message: "Token refresh failed: \(parsedError)", statusCode: status)
    }

    func testPermanentFailureKeepsServerDiagnosticVerbatim() {
        let cas = casFailure(status: 400, "invalid_grant: The refresh token expired")

        let translated = KrdpassAuth.casErrorToKrdpassError(cas)

        guard case .authenticationFailed(let message, let code) = translated else {
            return XCTFail(
                "a 4xx is permanent and must not be reported as retryable, got \(translated)")
        }
        XCTAssertTrue(message.contains("invalid_grant"), "OAuth error code lost")
        XCTAssertTrue(message.contains("The refresh token expired"), "OAuth description lost")
        XCTAssertTrue(message.contains("400"), "HTTP status lost")
        // A passthrough CAS code here would rename the documented per-call failure codes
        // (refresh_failed, revoke_failed, user_info_failed).
        XCTAssertNil(code)
        XCTAssertNil(translated.installUrl)
    }

    func testRetryableFailuresBecomeNetworkError() {
        for status in [500, 502, 503, 408, 429] {
            let cas = casFailure(status: status, "temporarily unavailable")

            let translated = KrdpassAuth.casErrorToKrdpassError(cas)

            guard case .networkError = translated else {
                return XCTFail("status \(status) is transient and must be reported as retryable")
            }
            XCTAssertEqual(translated.code, "network_error")
        }
    }

    func testClientErrorsOtherThan408And429ArePermanent() {
        for status in [400, 401, 403, 404, 409, 422] {
            let translated = KrdpassAuth.casErrorToKrdpassError(
                casFailure(status: status, "denied"))

            guard case .authenticationFailed = translated else {
                return XCTFail("status \(status) must not be reported as retryable")
            }
            XCTAssertNil(translated.code)
        }
    }

    func testMalformedResponseWithNoStatusIsPermanent() {
        // CasClient throws these with no statusCode ("Missing or empty request_uri in PAR
        // response" and the token-response equivalent). The transport was fine, so retrying
        // cannot help.
        let cas = CasException(message: "Missing or empty access_token in token response")

        let translated = KrdpassAuth.casErrorToKrdpassError(cas)

        guard case .authenticationFailed(let message, _) = translated else {
            return XCTFail("a malformed response is permanent, got \(translated)")
        }
        XCTAssertTrue(message.contains("Missing or empty access_token"))
    }
}

/// The token entry points can fail with more than a `CasException` (URLError, a raw
/// JSONSerialization NSError on a malformed 2xx body, CancellationError). These lock the full
/// classification, including that it keeps the retryable/permanent split above.
@MainActor
final class TokenOpErrorTranslationTests: XCTestCase {

    func testUrlErrorIsReportedAsRetryableNetworkError() async {
        await assertTranslates(URLError(.notConnectedToInternet)) { translated in
            XCTAssertEqual(translated.code, "network_error")
        }
    }

    func testCancellationIsReportedAsRetryableNetworkError() async {
        await assertTranslates(CancellationError()) { translated in
            XCTAssertEqual(translated.code, "network_error")
        }
    }

    func testAlreadyTypedKrdpassErrorPassesThroughUnchanged() async {
        // The id_token checks throw these; re-wrapping would rename their documented code.
        await assertTranslates(
            KrdpassError.authenticationFailed("ID token nonce mismatch", code: "nonce_mismatch")
        ) { translated in
            XCTAssertEqual(translated.code, "nonce_mismatch")
            guard case .authenticationFailed(let message, _) = translated else {
                return XCTFail("expected the original case, got \(translated)")
            }
            XCTAssertEqual(message, "ID token nonce mismatch")
        }
    }

    func testUnparseableResponseIsPermanentWithNilCodeAndVerbatimMessage() async {
        let underlying = jsonDecodingFailure()
        await assertTranslates(underlying) { translated in
            guard case .authenticationFailed(let message, let code) = translated else {
                return XCTFail("a malformed 2xx body is permanent, got \(translated)")
            }
            // nil code leaves the documented per-call code (user_info_failed / refresh_failed /
            // revoke_failed).
            XCTAssertNil(code)
            XCTAssertEqual(
                message, underlying.localizedDescription, "OS reason not carried verbatim")
        }
    }

    func testCasExceptionSplitSurvivesTheWiderCatch() async {
        await assertTranslates(CasException(message: "boom", statusCode: 503)) { translated in
            XCTAssertEqual(translated.code, "network_error", "a 5xx must stay retryable")
        }
        await assertTranslates(
            CasException(message: "invalid_grant: expired", statusCode: 400)
        ) { translated in
            guard case .authenticationFailed(let message, let code) = translated else {
                return XCTFail("a 4xx must not look retryable, got \(translated)")
            }
            XCTAssertNil(code)
            XCTAssertTrue(message.contains("invalid_grant"), "server diagnostic lost")
            XCTAssertTrue(message.contains("400"), "HTTP status lost")
        }
    }

    func testGetUserInfoAsync_reportsAMalformedResponseAsKrdpassError() async {
        let auth = makeAuth()
        await assertKrdpassError(expecting: jsonDecodingFailure()) {
            _ = try await auth.getUserInfo(accessToken: "token")
        }
    }

    func testGetUserInfoCompletion_reportsAMalformedResponseAsKrdpassError() async {
        let auth = makeAuth()
        let received = await withCheckedContinuation {
            (continuation: CheckedContinuation<Error?, Never>) in
            auth.getUserInfo(accessToken: "token") { result in
                switch result {
                case .success: continuation.resume(returning: nil)
                case .failure(let error): continuation.resume(returning: error)
                }
            }
        }
        assertIsKrdpassError(received, expecting: jsonDecodingFailure())
    }

    func testRefreshTokens_reportsAMalformedResponseAsKrdpassError() async {
        let auth = makeAuth()
        await assertKrdpassError(expecting: jsonDecodingFailure()) {
            _ = try await auth.refreshTokens(refreshToken: "refresh")
        }
    }

    func testRevokeToken_reportsAMalformedResponseAsKrdpassError() async {
        let auth = makeAuth()
        await assertKrdpassError(expecting: jsonDecodingFailure()) {
            try await auth.revokeToken(token: "token")
        }
    }

    func testRefreshTokens_doesNotLeakARawUrlError() async {
        let auth = makeAuth(transportFailure: URLError(.notConnectedToInternet))
        do {
            _ = try await auth.refreshTokens(refreshToken: "refresh")
            XCTFail("expected the transport failure to surface")
        } catch let error as KrdpassError {
            XCTAssertEqual(error.code, "network_error", "a transport failure stays retryable")
        } catch {
            XCTFail("a raw \(type(of: error)) escaped a public entry point: \(error)")
        }
    }

    func testRefreshTokens_keepsTheRetryableAndPermanentSplitEndToEnd() async {
        let retryable = makeAuth(status: 503, body: Data(#"{"error":"unavailable"}"#.utf8))
        do {
            _ = try await retryable.refreshTokens(refreshToken: "refresh")
            XCTFail("expected a 503 to fail")
        } catch let error as KrdpassError {
            XCTAssertEqual(error.code, "network_error")
        } catch {
            XCTFail("expected KrdpassError, got \(error)")
        }

        let permanent = makeAuth(status: 400, body: Data(#"{"error":"invalid_grant"}"#.utf8))
        do {
            _ = try await permanent.refreshTokens(refreshToken: "refresh")
            XCTFail("expected a 400 to fail")
        } catch let error as KrdpassError {
            guard case .authenticationFailed(let message, let code) = error else {
                return XCTFail("a 400 must not look retryable, got \(error)")
            }
            XCTAssertNil(code)
            XCTAssertTrue(message.contains("invalid_grant"))
        } catch {
            XCTFail("expected KrdpassError, got \(error)")
        }
    }

    /// A CAS deployment that echoed a submitted token back in its error body would otherwise
    /// send it straight into the host app's crash reporter, via the KrdpassError message.
    func testTokenShapedRunsNeverReachTheErrorMessage() async {
        // {"alg":"RS256"}.{"sub":"user-123"}.signature-bytes-here, joined at runtime so no
        // JWT-shaped literal sits in source for a secret scanner to flag.
        let jwt = [
            "eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ1c2VyLTEyMyJ9", "c2lnbmF0dXJlLWJ5dGVzLWhlcmU",
        ].joined(separator: ".")
        let opaque = "Atu5NnPqR7vXwZ0aBcDeFgHiJkLmNoPqRsTuVwXyZ01"

        let message = await refreshFailureMessage(
            errorDescription: "token \(jwt) and \(opaque) were rejected")

        XCTAssertFalse(message.contains(jwt))
        XCTAssertFalse(message.contains(opaque))
        XCTAssertTrue(message.contains("[REDACTED]"))
        XCTAssertTrue(message.contains("invalid_grant"), "the OAuth code stays readable")
        XCTAssertTrue(message.contains("were rejected"), "the human wording stays readable")
    }

    func testAnOversizedErrorDescriptionIsTruncated() async {
        // No token shape to redact, so only the length bound can stop it.
        let message = await refreshFailureMessage(
            errorDescription: String(repeating: "code expired ", count: 100))

        XCTAssertTrue(message.contains("...[truncated]"))
        XCTAssertLessThan(message.count, 400, "message was \(message.count) chars")
    }

    /// The public `KrdpassError` message an app sees for a 400 carrying `errorDescription`.
    private func refreshFailureMessage(errorDescription: String) async -> String {
        let body = try? JSONSerialization.data(
            withJSONObject: ["error": "invalid_grant", "error_description": errorDescription])
        let auth = makeAuth(status: 400, body: body ?? Data())
        do {
            _ = try await auth.refreshTokens(refreshToken: "refresh")
            XCTFail("expected the 400 to fail")
            return ""
        } catch {
            return (error as? KrdpassError)?.errorDescription ?? "\(error)"
        }
    }

    override func tearDown() {
        FailingURLProtocol.error = nil
        super.tearDown()
    }

    /// The error JSONSerialization actually throws for a 2xx body that is not JSON, so the tests
    /// compare against the real OS message instead of a hardcoded copy of it.
    private func jsonDecodingFailure() -> NSError {
        do {
            _ = try JSONSerialization.jsonObject(with: Self.malformedBody)
            XCTFail("the malformed body must not parse")
            return NSError(domain: "unused", code: 0)
        } catch {
            return error as NSError
        }
    }

    private static let malformedBody = Data("not json".utf8)

    private func assertTranslates(
        _ thrown: Error, _ assertions: (KrdpassError) -> Void,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            try await KrdpassAuth.translatingCasErrors { throw thrown }
            XCTFail("expected a throw", file: file, line: line)
        } catch let error as KrdpassError {
            assertions(error)
        } catch {
            XCTFail(
                "a raw \(type(of: error)) escaped the translation: \(error)", file: file, line: line
            )
        }
    }

    private func assertKrdpassError(
        expecting underlying: NSError, file: StaticString = #filePath, line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected a throw", file: file, line: line)
        } catch {
            assertIsKrdpassError(error, expecting: underlying, file: file, line: line)
        }
    }

    private func assertIsKrdpassError(
        _ error: Error?, expecting underlying: NSError, file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let error else { return XCTFail("expected a failure", file: file, line: line) }
        guard let krdpassError = error as? KrdpassError else {
            return XCTFail(
                "a raw \(type(of: error)) escaped a public entry point: \(error)", file: file,
                line: line)
        }
        guard case .authenticationFailed(let message, let code) = krdpassError else {
            return XCTFail(
                "a malformed response body is permanent, got \(krdpassError)", file: file,
                line: line)
        }
        XCTAssertNil(code, "a nil code must stay nil", file: file, line: line)
        XCTAssertEqual(
            message, underlying.localizedDescription, "OS reason not carried verbatim", file: file,
            line: line)
    }

    /// Answers every request identically, rather than scripting `MockURLProtocol`'s shared static
    /// queue: the CAS client retries userinfo and revoke up to three times.
    private func makeAuth(
        status: Int = 200, body: Data = TokenOpErrorTranslationTests.malformedBody
    ) -> KrdpassAuth {
        StaticResponseURLProtocol.status = status
        StaticResponseURLProtocol.body = body
        return makeAuth(protocolClass: StaticResponseURLProtocol.self)
    }

    private func makeAuth(transportFailure: URLError) -> KrdpassAuth {
        FailingURLProtocol.error = transportFailure
        return makeAuth(protocolClass: FailingURLProtocol.self)
    }

    private func makeAuth(protocolClass: URLProtocol.Type) -> KrdpassAuth {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [protocolClass]
        let session = URLSession(configuration: configuration)
        return KrdpassAuth(
            config: KrdpassConfig(
                clientId: "test-client", redirectUri: "https://example.com/callback",
                environment: .production),
            urlSession: session)
    }
}

/// Answers every request with the same status and body.
final class StaticResponseURLProtocol: URLProtocol {
    // nonisolated(unsafe): set before the request under test, one test at a time.
    nonisolated(unsafe) static var status = 200
    nonisolated(unsafe) static var body = Data()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: Self.status, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Fails every request with a chosen `URLError`, so a genuine transport failure can be exercised.
/// `MockURLProtocol` fails with an `NSError` of its own domain, which is a different branch of the
/// classification under test.
final class FailingURLProtocol: URLProtocol {
    // nonisolated(unsafe): set before the request and cleared in tearDown, one test at a time.
    nonisolated(unsafe) static var error: URLError?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: Self.error ?? URLError(.unknown))
    }

    override func stopLoading() {}
}
