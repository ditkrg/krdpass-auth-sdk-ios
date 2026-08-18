import Foundation
import Security
import XCTest

@testable import KrdpassAuth

@MainActor
final class VerifyTokenTests: XCTestCase {
    override func setUp() {
        super.setUp()
        let data = JWTTestSupport.jwkJson.data(using: .utf8) ?? Data()
        MockURLProtocol.setResponse(
            data, statusCode: 200, headers: ["Content-Type": "application/json"])
    }

    override func tearDown() {
        MockURLProtocol.responseQueue = []
        MockURLProtocol.lastRequest = nil
        super.tearDown()
    }

    /// Every instance gets a session wired to MockURLProtocol: `URLProtocol.registerClass` only
    /// reaches `URLSession.shared`, which the SDK does not use, so relying on it would fetch the
    /// real production JWKS.
    private func makeAuth(environment: KrdpassEnvironment = .production) -> KrdpassAuth {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return KrdpassAuth(
            config: KrdpassConfig(
                clientId: "test-client", redirectUri: "https://example.com/callback",
                environment: environment),
            urlSession: URLSession(configuration: configuration))
    }

    func testVerifyToken_validToken() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()
        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertEqual(claims["iss"]?.stringValue, "https://issuer.example")
        XCTAssertEqual(claims["aud"]?.stringValue, "test-aud")
    }

    func testVerifyToken_rejectsIssuerMismatch() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://other.example", audience: "test-aud")
            XCTFail("Expected issuer mismatch")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsAudienceMismatch() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "other-aud")
            XCTFail("Expected audience mismatch")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsExpiredToken() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: -60)
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud", clockSkew: 0)
            XCTFail("Expected expiration failure")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_allowsExpiredWithinClockSkew() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: -30)
        let auth = makeAuth()
        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud", clockSkew: 60)
        XCTAssertEqual(claims["sub"]?.stringValue, "test-subject")
    }

    func testVerifyToken_clampsClockSkewSoExpiryCannotBeSwitchedOff() async throws {
        // Expired by a day: inside the caller's absurd skew, outside the 300s ceiling.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: -86400)
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud",
                clockSkew: 86400 * 365)
            XCTFail("Expected the clamped skew to reject a day-old expiry")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsNotBeforeInFuture() async throws {
        let now = Int(Date().timeIntervalSince1970)
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example",
            audience: "test-aud",
            expiresIn: 300,
            issuedAt: now,
            notBefore: now + 120
        )
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud", clockSkew: 0)
            XCTFail("Expected not-before failure")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsMissingIssuerWhenIssuerExpected() async throws {
        // A token that omits `iss` must NOT pass issuer validation vacuously (fail-closed).
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example",
            audience: "test-aud",
            expiresIn: 300,
            omitIssuer: true
        )
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected rejection for a token missing the iss claim")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsInvalidSignature() async throws {
        var token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        if let lastDot = token.lastIndex(of: ".") {
            token = String(token[..<lastDot]) + ".invalidsig"
        }
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected signature failure")
        } catch let error as TokenVerificationError {
            guard case .invalidSignature = error else {
                return XCTFail("Expected invalidSignature, got \(error)")
            }
        }
    }

    /// Drives the real crypto path, not a synthetic error value, so the CFError rethrow is
    /// exercised where a unit test cannot reach it.
    func testVerifyToken_publicApi_reportsAForgedSignatureAsInvalidIdToken() async throws {
        var token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        if let lastDot = token.lastIndex(of: ".") {
            token = String(token[..<lastDot]) + ".invalidsig"
        }
        let auth = makeAuth()

        await assertPublicApiRejects(
            token, on: auth, becauseOf: "JWT signature verification failed")
    }

    func testVerifyToken_doesNotRefetchJwksAgainForAnUnknownKidInsideTheCooldown() async throws {
        // The first verify caches setUp's JWKS. An unknown kid buys exactly one refetch, which
        // consumes the response enqueued here. A second unknown kid inside the cooldown must not
        // fetch again: with the queue drained a fetch fails as jwksFetchFailed, so keyNotFound is
        // what proves no request went out.
        let auth = makeAuth()
        let valid = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        _ = try await auth.verifyToken(
            valid, issuer: "https://issuer.example", audience: "test-aud")

        MockURLProtocol.enqueueResponse(
            JWTTestSupport.jwkJson.data(using: .utf8) ?? Data(), statusCode: 200,
            headers: ["Content-Type": "application/json"])

        for attempt in 1...2 {
            let unknown = try JWTTestSupport.makeToken(
                issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
                kid: "unknown-kid")
            do {
                _ = try await auth.verifyToken(
                    unknown, issuer: "https://issuer.example", audience: "test-aud")
                XCTFail("Expected an unknown kid to be rejected")
            } catch let error as TokenVerificationError {
                guard case .keyNotFound = error else {
                    return XCTFail("Expected keyNotFound on attempt \(attempt), got \(error)")
                }
            }
        }
        XCTAssertTrue(
            MockURLProtocol.responseQueue.isEmpty,
            "the single allowed refetch should have consumed the queued JWKS")
    }

    func testVerifyToken_rejectsAlgNone() async throws {
        // Algorithm confusion: an alg:none token must be rejected (no signature check bypass).
        let token = try JWTTestSupport.makeTokenWithAlgorithm("none", audience: "test-aud")
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected alg:none to be rejected")
        } catch let error as TokenVerificationError {
            guard case .unsupportedAlgorithm = error else {
                return XCTFail("Expected unsupportedAlgorithm, got \(error)")
            }
        }
    }

    func testVerifyToken_rejectsNonRS256Algorithm() async throws {
        // A symmetric alg (HS256) must be rejected before any signature handling.
        let token = try JWTTestSupport.makeTokenWithAlgorithm("HS256", audience: "test-aud")
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected HS256 to be rejected")
        } catch let error as TokenVerificationError {
            guard case .unsupportedAlgorithm = error else {
                return XCTFail("Expected unsupportedAlgorithm, got \(error)")
            }
        }
    }

    func testVerifyToken_publicIdTokenApi_derivesIssuerAndAudienceFromConfig() async throws {
        // The public verifyToken(idToken:) derives the audience from config.clientId and pins the
        // issuer to the configured environment's authorization server.
        let token = try JWTTestSupport.makeToken(
            issuer: KrdpassEnvironment.production.authServerUrl,
            audience: "test-client", expiresIn: 300)
        let auth = makeAuth()
        let claims = try await auth.verifyToken(idToken: token)
        XCTAssertEqual(claims["aud"]?.stringValue, "test-client")
        XCTAssertEqual(claims["iss"]?.stringValue, KrdpassEnvironment.production.authServerUrl)
    }

    func testVerifyToken_publicIdTokenApi_rejectsWrongAudience() async throws {
        // A token whose aud != the configured clientId must be rejected by the public API.
        let token = try JWTTestSupport.makeToken(
            issuer: KrdpassEnvironment.production.authServerUrl,
            audience: "someone-else", expiresIn: 300)
        let auth = makeAuth()
        await assertPublicApiRejects(token, on: auth, becauseOf: "Audience mismatch")
    }

    func testVerifyToken_publicIdTokenApi_pinsTheIssuer() async throws {
        // The issuer is pinned to the configured environment's authorization server, with no way
        // for a consumer to opt out: otherwise a correctly signed token minted for this client by
        // ANY issuer would be accepted.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://attacker.example", audience: "test-client", expiresIn: 300)
        let auth = makeAuth()
        await assertPublicApiRejects(token, on: auth, becauseOf: "Issuer mismatch")
    }

    func testVerifyToken_publicIdTokenApi_pinsTheIssuerPerEnvironment() async throws {
        // A development-environment client must not accept a production-issued token.
        let token = try JWTTestSupport.makeToken(
            issuer: KrdpassEnvironment.production.authServerUrl,
            audience: "test-client", expiresIn: 300)
        let auth = makeAuth(environment: .development)
        await assertPublicApiRejects(token, on: auth, becauseOf: "Issuer mismatch")
    }

    /// The public `verifyToken(idToken:)` must report a rejected token through ``KrdpassError``,
    /// the SDK's one public error contract, not the internal verifier's error type or a raw
    /// `CFError`, and the underlying reason has to survive the wrap.
    private func assertPublicApiRejects(
        _ token: String, on auth: KrdpassAuth, becauseOf reason: String,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await auth.verifyToken(idToken: token)
            XCTFail("Expected the token to be rejected (\(reason))", file: file, line: line)
        } catch let error as KrdpassError {
            XCTAssertEqual(error.code, "invalid_id_token", file: file, line: line)
            let message = error.errorDescription ?? ""
            XCTAssertTrue(
                message.contains(reason),
                "underlying reason lost, got \(message)", file: file, line: line)
        } catch {
            XCTFail(
                "expected KrdpassError, got \(type(of: error)): \(error)", file: file, line: line)
        }
    }

    func testVerifyToken_withNoKid_skipsNonSigningKeys() async throws {
        // A JWT with no `kid` gives the verifier no way to name its key. Taking keys.first would
        // pick the encryption key this JWKS lists first and fail a perfectly valid token.
        MockURLProtocol.setResponse(
            JWTTestSupport.jwkJsonEncryptionKeyFirst.data(using: .utf8) ?? Data(),
            statusCode: 200, headers: ["Content-Type": "application/json"])
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300, kid: nil)
        let auth = makeAuth()

        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertEqual(claims["sub"]?.stringValue, "test-subject")
    }

    func testVerifyToken_rejectsJwtWithEmptySegments() async throws {
        // "..a.b.c" must not parse as a three-part JWT: split() drops empty subsequences by
        // default, which would let a malformed token through the structural check.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()
        do {
            _ = try await auth.verifyToken(
                "..\(token)", issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected a token with empty leading segments to be rejected")
        } catch let error as TokenVerificationError {
            guard case .invalidToken = error else {
                return XCTFail("Expected invalidToken, got \(error)")
            }
        }
    }

    func testVerifyToken_reusesCachedJwks_acrossCalls() async throws {
        // setUp enqueues exactly ONE JWKS response. The first verify consumes it and caches the
        // keys; a second verify on the same instance must reuse the cache rather than refetch (the
        // queue is now empty, so a refetch would fail). Both succeeding proves the cache is hit.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()

        _ = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertTrue(
            MockURLProtocol.responseQueue.isEmpty,
            "first verify should have consumed the one JWKS response")

        // No response left to fetch, success here can only come from the cache.
        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertEqual(claims["sub"]?.stringValue, "test-subject")

        // Sanity: a fresh instance (empty cache) must fail now that the queue is drained, proving
        // the reuse above came from caching rather than an always-succeed mock.
        let fresh = makeAuth()
        do {
            _ = try await fresh.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("a fresh verifier with no JWKS response queued must fail to fetch")
        } catch {
            // Expected: jwksFetchFailed.
        }
    }

    func testVerifyToken_refetchesJwksOnceOnKidRotation() async throws {
        // A kid missing from the cached JWKS (key rotation) must trigger exactly one refetch.
        // The token is signed by the same key but advertises the rotated kid, so verification
        // only succeeds if the refetch fired and selected it.
        MockURLProtocol.enqueueResponse(
            JWTTestSupport.jwkJsonRotated.data(using: .utf8) ?? Data(),
            statusCode: 200, headers: ["Content-Type": "application/json"])
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
            kid: "test-key-v2")
        let auth = makeAuth()

        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertEqual(claims["sub"]?.stringValue, "test-subject")
        XCTAssertTrue(
            MockURLProtocol.responseQueue.isEmpty,
            "exactly the initial fetch + one rotation refetch should have been consumed")
    }

    /// The `aud` check requires exact equality, so every multi-audience token is rejected
    /// before the azp guard can run, whatever azp says. If someone relaxes `aud` to
    /// containment (OIDC Core 3.1.3.7 step 3), this test fails instead of the change being silent.
    func testVerifyToken_multipleAudiences_alwaysRejected_regardlessOfAzp() async throws {
        // One KrdpassAuth for all three: setUp enqueues a single JWKS response, and the first
        // verify caches it. A fresh instance per iteration would refetch and find nothing queued.
        let auth = makeAuth()

        for azp in ["test-aud", "other-aud", nil] {
            var extraClaims: [String: Any] = ["aud": ["test-aud", "other-aud"]]
            if let azp { extraClaims["azp"] = azp }
            let token = try JWTTestSupport.makeToken(
                issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
                extraClaims: extraClaims)

            do {
                _ = try await auth.verifyToken(
                    token, issuer: "https://issuer.example", audience: "test-aud")
                XCTFail("Expected rejection of a multi-audience token (azp: \(azp ?? "absent"))")
            } catch let error as TokenVerificationError {
                guard case .invalidClaims = error else {
                    return XCTFail("Expected invalidClaims, got \(error)")
                }
            }
        }
    }

    func testVerifyToken_singleElementAudienceArray_accepted() async throws {
        // Exact equality, not "must be a bare string": ["test-aud"] is still exactly us.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
            extraClaims: ["aud": ["test-aud"]])
        let auth = makeAuth()

        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        // Reported as a bare string whichever form the token used: a one-element array collapses.
        XCTAssertEqual(claims["aud"]?.stringValue, "test-aud")
        XCTAssertNil(claims["aud"]?.arrayValue)
    }

    func testVerifyToken_singleAudience_rejectsOtherClientsAzp() async throws {
        // A present azp naming someone else is fatal at any audience count: the issuer is
        // telling us the token was authorized for a different client.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
            extraClaims: ["azp": "other-aud"])
        let auth = makeAuth()

        do {
            _ = try await auth.verifyToken(
                token, issuer: "https://issuer.example", audience: "test-aud")
            XCTFail("Expected rejection for a single-audience token with another client's azp")
        } catch let error as TokenVerificationError {
            guard case .invalidClaims = error else {
                return XCTFail("Expected invalidClaims, got \(error)")
            }
        }
    }

    func testVerifyToken_singleAudience_acceptsMatchingAzp() async throws {
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300,
            extraClaims: ["azp": "test-aud"])
        let auth = makeAuth()

        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertEqual(claims["azp"]?.stringValue, "test-aud")
    }

    func testVerifyToken_singleAudience_acceptsAbsentAzp() async throws {
        // The ordinary shape of every id_token CAS issues. Rejecting it would break every
        // normal login, so this guards the widened check against overreaching.
        let token = try JWTTestSupport.makeToken(
            issuer: "https://issuer.example", audience: "test-aud", expiresIn: 300)
        let auth = makeAuth()

        let claims = try await auth.verifyToken(
            token, issuer: "https://issuer.example", audience: "test-aud")
        XCTAssertNil(claims["azp"])
    }
}
