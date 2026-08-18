import XCTest

@testable import KrdpassAuth

final class PkceGeneratorTests: XCTestCase {

    func testGenerate_createsValidPkcePair() throws {
        let pair = try PkceGenerator.generate()

        XCTAssertEqual(pair.method, "S256")

        // Check verifier length against the RFC 7636 bounds as literals, so the assertion is
        // independent of the constants the implementation happens to use.
        XCTAssertGreaterThanOrEqual(pair.codeVerifier.count, 43)
        XCTAssertLessThanOrEqual(pair.codeVerifier.count, 128)

        let base64UrlPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]+$")
        let verifierRange = NSRange(location: 0, length: pair.codeVerifier.count)
        XCTAssertNotNil(base64UrlPattern.firstMatch(in: pair.codeVerifier, range: verifierRange))

        let expectedChallenge = PkceGenerator.computeChallenge(pair.codeVerifier)
        XCTAssertEqual(expectedChallenge, pair.codeChallenge)
    }

    func testComputeChallenge_producesCorrectS256Hash() {
        // Test vector from RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        let actualChallenge = PkceGenerator.computeChallenge(verifier)

        XCTAssertEqual(actualChallenge, expectedChallenge)
    }

    func testComputeChallenge_isDeterministic() {
        let verifier = "same_input_every_time"
        let challenge1 = PkceGenerator.computeChallenge(verifier)
        let challenge2 = PkceGenerator.computeChallenge(verifier)

        XCTAssertEqual(challenge1, challenge2)
    }

    func testGeneratedPairs_areUnique() throws {
        let pairs = try (0..<100).map { _ in try PkceGenerator.generate() }

        let verifiers = pairs.map { $0.codeVerifier }
        XCTAssertEqual(Set(verifiers).count, verifiers.count)

        let challenges = pairs.map { $0.codeChallenge }
        XCTAssertEqual(Set(challenges).count, challenges.count)
    }

    func testChallenge_containsOnlyUrlSafeCharacters() throws {
        let pair = try PkceGenerator.generate()

        XCTAssertFalse(pair.codeChallenge.contains("+"))
        XCTAssertFalse(pair.codeChallenge.contains("/"))
        XCTAssertFalse(pair.codeChallenge.contains("="))
    }
}
