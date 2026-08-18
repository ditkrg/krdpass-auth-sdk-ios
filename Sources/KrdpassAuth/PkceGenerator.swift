import CryptoKit
import Foundation
import Security

/// An RFC 7636 PKCE code verifier and S256 challenge pair.
public struct PkcePair: Equatable, Sendable, CustomStringConvertible {
    /// The code verifier (43-128 characters, base64url alphabet).
    public let codeVerifier: String

    /// The code challenge (base64url-encoded SHA256 hash of verifier).
    public let codeChallenge: String

    /// The challenge method (always 'S256' for this implementation).
    public let method: String

    public init(codeVerifier: String, codeChallenge: String, method: String = "S256") {
        self.codeVerifier = codeVerifier
        self.codeChallenge = codeChallenge
        self.method = method
    }

    public var description: String {
        "PkcePair(codeVerifier=[REDACTED], codeChallenge=[REDACTED], method='\(method)')"
    }
}

/// Generates RFC 7636 PKCE pairs (S256) from a cryptographically secure random source.
/// Internal: ``KrdpassAuth/generatePkcePair()`` is the public entry point.
enum PkceGenerator {
    /// 32 bytes = 43 base64url characters, the RFC 7636 minimum verifier length.
    private static let verifierByteLength = 32

    static func generate() throws -> PkcePair {
        let verifierBytes = try generateRandomBytes(count: verifierByteLength)
        let codeVerifier = base64UrlEncodeNoPadding(verifierBytes)
        let codeChallenge = computeChallenge(codeVerifier)

        return PkcePair(
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge
        )
    }

    /// Computes the S256 challenge for a given verifier.
    static func computeChallenge(_ verifier: String) -> String {
        let verifierData = Data(verifier.utf8)
        let hash = SHA256.hash(data: verifierData)
        return base64UrlEncodeNoPadding(Data(hash))
    }

    internal static func generateRandomBytes(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var bytes = Data(count: count)
        let result = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }

        guard result == errSecSuccess else {
            throw PkceGenerationError.randomGenerationFailed
        }

        return bytes
    }

    internal static func base64UrlEncodeNoPadding(_ data: Data) -> String {
        // Foundation has no base64url encoder: RFC 4648 section 5 substitutions, padding stripped.
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum PkceGenerationError: Error, LocalizedError {
    case randomGenerationFailed

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            return KrdpassMessages.pkceGenerationFailed
        }
    }
}
