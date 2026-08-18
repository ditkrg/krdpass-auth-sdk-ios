import XCTest

@testable import KrdpassAuth

final class KrdpassConfigTests: XCTestCase {

    func testIsValidRedirectUri_customScheme_rejected() {
        let config = KrdpassConfig(clientId: "test-client", redirectUri: "myapp://callback")

        // Only HTTPS is allowed.
        XCTAssertFalse(config.isValidRedirectUri(URL(string: "myapp://callback")!))
        XCTAssertFalse(config.isValidRedirectUri(URL(string: "myapp://different/path")!))
    }

    func testIsValidRedirectUri_https_exactMatch() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.com/auth/callback")

        XCTAssertTrue(config.isValidRedirectUri(URL(string: "https://example.com/auth/callback")!))
        XCTAssertTrue(
            config.isValidRedirectUri(
                URL(string: "https://example.com/auth/callback?code=abc&state=xyz")!))
    }

    func testIsValidRedirectUri_https_rejectsHostPortAndPathMismatch() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.com/auth/callback")

        XCTAssertFalse(
            config.isValidRedirectUri(URL(string: "https://different.com/auth/callback")!))
        XCTAssertFalse(
            config.isValidRedirectUri(URL(string: "https://example.com:8443/auth/callback")!))
        XCTAssertFalse(config.isValidRedirectUri(URL(string: "http://example.com/auth/callback")!))
        XCTAssertFalse(config.isValidRedirectUri(URL(string: "https://example.com/auth/wrong")!))
        XCTAssertFalse(
            config.isValidRedirectUri(URL(string: "https://example.com/different/callback")!))
    }

    func testIsValidRedirectUri_https_caseInsensitiveHostAndDefaultPort() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.com/auth/callback")

        XCTAssertTrue(config.isValidRedirectUri(URL(string: "https://EXAMPLE.com/auth/callback")!))
        // Explicit default port equals no port.
        XCTAssertTrue(
            config.isValidRedirectUri(URL(string: "https://example.com:443/auth/callback")!))
    }

    func testIsValidRedirectUri_rejectsUserinfoAndFragment() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.com/auth/callback")

        XCTAssertFalse(
            config.isValidRedirectUri(
                URL(string: "https://example.com@evil.com/auth/callback?code=a&state=b")!))
        XCTAssertFalse(
            config.isValidRedirectUri(
                URL(string: "https://example.com/auth/callback?code=a&state=b#frag")!))
    }

    func testIsValidRedirectUri_rejectsSuffixHost() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.gov/_krdpass/oauth/callback")

        // Suffix host is a different host, not a match.
        XCTAssertFalse(
            config.isValidRedirectUri(
                "https://example.gov.evil.com/_krdpass/oauth/callback?code=abc123&state=xyz789"))

        // No malformed-percent case here: Foundation rewrites a stray "%" to "%25" inside
        // percentEncodedQuery before the validator sees it, so "code=%zz" arrives as the literal
        // "%zz". Host, path and port still have to match exactly, so there is no bypass.
    }

    func testIsValidRedirectUri_acceptsPercentEncodedInvalidUtf8() {
        let config = KrdpassConfig(
            clientId: "test-client", redirectUri: "https://example.com/auth/callback")

        // Percent-formed bytes that are not valid UTF-8 become U+FFFD, and the callback is
        // accepted.
        XCTAssertTrue(
            config.isValidRedirectUri("https://example.com/auth/callback?code=%FF&state=xyz"))
        XCTAssertTrue(
            config.isValidRedirectUri("https://example.com/auth/callback?code=abc&state=%C0%80"))
        // Also in a parameter NAME, which goes through the same decode.
        XCTAssertTrue(
            config.isValidRedirectUri("https://example.com/auth/callback?code=abc&%FF=1"))
        // No malformed-escape counter-case here, for the reason given above: Foundation rewrites
        // "%F" to "%25F" before the validator sees it. isValidPercentEncoding is exercised
        // directly by the shared vectors instead.
    }

    /// The canonical redirect-validation vectors. The vendored resource is a byte copy of
    /// shared/test-vectors/redirect-validation.json and is decoded, never retyped.
    private struct VectorDocument: Decodable {
        let version: String
        let configuredRedirectUri: String
        let vectors: [Vector]
        let issuerVectors: [IssuerVector]

        struct Vector: Decodable {
            let id: String
            let input: String
            let expected: Bool
            let reason: String
            /// Fixed-query and IP-literal vectors register their own redirect URI.
            let configuredRedirectUri: String?
        }

        struct IssuerVector: Decodable {
            let id: String
            let environment: String
            let input: String
            let expectedState: String
            let expectedResult: String
            let reason: String
            let configuredRedirectUri: String?
        }
    }

    private func loadVectors() throws -> VectorDocument {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "redirect-validation", withExtension: "json"),
            "missing test resource: redirect-validation.json")
        return try JSONDecoder().decode(VectorDocument.self, from: Data(contentsOf: url))
    }

    func testSharedRedirectValidationVectors() throws {
        let document = try loadVectors()

        var failures: [String] = []
        for vector in document.vectors {
            let configured = vector.configuredRedirectUri ?? document.configuredRedirectUri
            let config = KrdpassConfig(clientId: "test-client", redirectUri: configured)
            let actual = config.isValidRedirectUri(vector.input)
            if actual != vector.expected {
                failures.append(
                    "\(vector.id): expected \(vector.expected) but got \(actual) "
                        + "for \"\(vector.input)\" (\(vector.reason))")
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            "redirect validation diverged from the canonical vectors:\n"
                + failures.joined(separator: "\n"))
    }

    /// Drives the canonical RFC 9207 issuer vectors through the real deep-link handler, so the
    /// check is asserted where it is wired in, not on a helper in isolation.
    @MainActor
    func testSharedIssuerValidationVectors() async throws {
        let document = try loadVectors()

        var failures: [String] = []
        for vector in document.issuerVectors {
            let config = KrdpassConfig(
                clientId: "test-client",
                redirectUri: vector.configuredRedirectUri ?? document.configuredRedirectUri,
                environment: try environmentNamed(vector.environment))
            let opener = MockUrlOpener()
            let auth = KrdpassAuth(config: config, urlOpener: opener)

            // Deliver the callback the moment the SDK launches the provider: `onOpen` is the
            // "flow armed" signal, so there is no fixed-delay race against the timeout.
            opener.onOpen = { _ in
                Task { @MainActor [weak auth] in
                    guard let auth else { return }
                    _ = auth.handle(URL(string: vector.input)!)
                }
            }

            let completed = expectation(description: vector.id)
            var actual = "no result"
            auth.authenticate(
                requestUri: "urn:ietf:params:oauth:request_uri:test", state: vector.expectedState,
                timeout: 5.0
            ) { result in
                switch result {
                case .success: actual = "success"
                case .error(let error): actual = error.error
                case .cancelled: actual = "cancelled"
                case .timeout: actual = "timeout"
                case .busy: actual = "busy"
                }
                completed.fulfill()
            }
            await fulfillment(of: [completed], timeout: 5.0)

            if actual != vector.expectedResult {
                failures.append(
                    "\(vector.id): expected \(vector.expectedResult) but got \(actual) "
                        + "for \"\(vector.input)\" (\(vector.reason))")
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            "issuer validation diverged from the canonical vectors:\n"
                + failures.joined(separator: "\n"))
    }

    private struct UnknownEnvironment: Error { let name: String }

    private func environmentNamed(_ name: String) throws -> KrdpassEnvironment {
        switch name {
        case "production": return .production
        case "development": return .development
        default: throw UnknownEnvironment(name: name)
        }
    }

    /// Guards the vendored copy against silently falling behind the canonical file.
    func testVendoredVectorFileIsExpectedContractVersion() throws {
        let document = try loadVectors()
        XCTAssertEqual(document.version, "2.3")
        XCTAssertEqual(document.vectors.count, 31)
        XCTAssertEqual(document.issuerVectors.count, 9)
    }
}
