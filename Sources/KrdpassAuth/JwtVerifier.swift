import Foundation
import Security

/// Errors surfaced by JWT/JWKS verification. Internal: ``KrdpassError`` is the SDK's single
/// public error contract, and ``KrdpassAuth`` wraps these at the trust boundary.
enum TokenVerificationError: Error, LocalizedError, Sendable {
    case invalidToken(String)
    case unsupportedAlgorithm(String)
    case keyNotFound
    case jwksFetchFailed
    case invalidSignature(String?)
    case unsupportedKeyType
    case invalidKey(String?)
    case invalidClaims(String)

    var errorDescription: String? {
        switch self {
        case .invalidToken(let message):
            return message
        case .unsupportedAlgorithm(let alg):
            return "Unsupported JWT algorithm: \(alg)"
        case .keyNotFound:
            return "No matching key found in JWKS"
        case .jwksFetchFailed:
            return "Failed to fetch JWKS"
        case .invalidSignature(let reason):
            return ["JWT signature verification failed", reason]
                .compactMap { $0 }.joined(separator: ": ")
        case .unsupportedKeyType:
            return "Unsupported JWK key type"
        case .invalidKey(let reason):
            return ["Invalid JWK key data", reason]
                .compactMap { $0 }.joined(separator: ": ")
        case .invalidClaims(let message):
            return message
        }
    }
}

/// base64url (RFC 7515) decoding shared by the JWKS verifier and the unverified token decoder.
enum Base64Url {
    /// `+`, `/` and `=` are rejected: RFC 7515 mandates unpadded base64url, and accepting the
    /// standard-base64 spellings too would give one token several valid encodings.
    private static let alphabet = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    static func decode(_ value: String) throws -> Data {
        guard !value.isEmpty, value.allSatisfy(alphabet.contains) else {
            throw TokenVerificationError.invalidToken("Invalid base64url encoding")
        }
        var base64 =
            value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        guard let data = Data(base64Encoded: base64) else {
            throw TokenVerificationError.invalidToken("Invalid base64url encoding")
        }
        return data
    }
}

/// A one-element `aud` array collapses to its string.
func flatteningSingleAudience(_ payload: [String: Any]) -> [String: Any] {
    guard let aud = payload["aud"] as? [Any], aud.count == 1 else { return payload }
    var flattened = payload
    flattened["aud"] = aud[0]
    return flattened
}

/// Verifies RS256 JWTs against a JWKS endpoint: signature, issuer, audience, and
/// expiry/nbf/iat (clock-skew tolerant). Caches the JWKS for one hour and refetches
/// on a `kid` miss (key rotation), at most once per cooldown window.
actor JwtVerifier {
    private let jwksEndpoint: String
    private let urlSession: URLSession
    private let log: @Sendable (String, String) -> Void
    /// Isolation is not held across the async fetch, so two concurrent misses may both fetch:
    /// last write wins.
    private var jwksCache: (keys: [String: Any], expiresAt: Date)?
    private static let cacheTtl: TimeInterval = 3600
    private var lastForcedRefetchAt: Date?
    /// `verifyToken` is public, so without a cooldown a stream of tokens carrying invented kids
    /// is a stream of outbound requests.
    private static let refetchCooldown: TimeInterval = 60
    /// An unbounded skew would switch off the expiry check entirely.
    private static let maxClockSkew: TimeInterval = 300

    init(
        jwksEndpoint: String,
        urlSession: URLSession,
        log: @escaping @Sendable (String, String) -> Void = { _, _ in }
    ) {
        self.jwksEndpoint = jwksEndpoint
        self.urlSession = urlSession
        self.log = log
    }

    /// Verify a JWT against the JWKS endpoint. `issuer` and `audience` are enforced only when
    /// non-nil; `exp` is always required. Returns the claims as ``JSONValue`` (`[String: Any]`
    /// is not `Sendable` and cannot leave an actor).
    func verify(
        _ token: String,
        issuer: String?,
        audience: String?,
        clockSkew: TimeInterval
    ) async throws -> [String: JSONValue] {
        guard !token.isEmpty else {
            throw TokenVerificationError.invalidToken("Token cannot be empty")
        }
        // NaN survives both min and max, and every comparison against it is false, so a
        // non-finite argument would switch the expiry check off rather than clamp it.
        let skew = min(max(clockSkew.isFinite ? clockSkew : 0, 0), Self.maxClockSkew)

        let (header, payload, signature, signingInput) = try parseJwt(token)
        let alg = header["alg"] as? String ?? ""
        guard alg == "RS256" else {
            throw TokenVerificationError.unsupportedAlgorithm(alg)
        }

        guard let jwksUrl = URL(string: jwksEndpoint) else {
            throw TokenVerificationError.invalidToken(
                "Invalid JWKS endpoint URL: \(jwksEndpoint)")
        }
        // The JWKS endpoint is the root of trust for signature verification: require HTTPS so
        // the keys can't be swapped over a downgraded transport.
        guard jwksUrl.scheme == "https" else {
            throw TokenVerificationError.invalidToken("JWKS endpoint must use HTTPS")
        }

        let jwks: [String: Any]
        if let cache = jwksCache, cache.expiresAt > Date() {
            log("DEBUG", "Using cached JWKS for \(jwksUrl.absoluteString)")
            jwks = cache.keys
        } else {
            log("INFO", "Fetching fresh JWKS from \(jwksUrl.absoluteString)")
            jwks = try await fetchJwks(jwksUrl)
            jwksCache = (keys: jwks, expiresAt: Date().addingTimeInterval(Self.cacheTtl))
        }

        let kid = header["kid"] as? String
        var candidates = selectJwks(from: jwks, kid: kid)
        // Unknown kid: the signing key likely rotated inside the TTL, so refetch rather than
        // failing verification for up to an hour. The cooldown check and its claim are one
        // synchronous stretch of actor-isolated code, so concurrent misses yield one refetch.
        if candidates.isEmpty,
            Date().timeIntervalSince(lastForcedRefetchAt ?? .distantPast) >= Self.refetchCooldown
        {
            lastForcedRefetchAt = Date()
            log("INFO", "kid not found in JWKS; refetching from \(jwksUrl.absoluteString)")
            let fresh = try await fetchJwks(jwksUrl)
            jwksCache = (keys: fresh, expiresAt: Date().addingTimeInterval(Self.cacheTtl))
            candidates = selectJwks(from: fresh, kid: kid)
        }
        guard !candidates.isEmpty else {
            throw TokenVerificationError.keyNotFound
        }

        try verifySignature(
            candidates: candidates, signingInput: signingInput, signature: signature)

        try validateClaims(payload, issuer: issuer, audience: audience, clockSkew: skew)
        return flatteningSingleAudience(payload)
            .mapValues(JSONValue.init(jsonSerializationOutput:))
    }

    private func parseJwt(_ token: String) throws -> (
        header: [String: Any], payload: [String: Any], signature: Data, signingInput: Data
    ) {
        // omittingEmptySubsequences: false, or "..a.b.c" collapses to three parts and passes.
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw TokenVerificationError.invalidToken("JWT must have three parts")
        }

        let headerData = try Base64Url.decode(String(parts[0]))
        let payloadData = try Base64Url.decode(String(parts[1]))
        let signature = try Base64Url.decode(String(parts[2]))

        let headerJson = try JSONSerialization.jsonObject(with: headerData) as? [String: Any] ?? [:]
        let payloadJson =
            try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] ?? [:]

        let signingInput = "\(parts[0]).\(parts[1])".data(using: .utf8) ?? Data()
        return (headerJson, payloadJson, signature, signingInput)
    }

    private func fetchJwks(_ url: URL) async throws -> [String: Any] {
        var request = URLRequest(url: url)
        // An injected session may be backed by the app's shared URLCache and cookie jar, and a
        // cached JWKS would outlive a key rotation.
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.httpShouldHandleCookies = false

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
            (200..<300).contains(httpResponse.statusCode)
        else {
            throw TokenVerificationError.jwksFetchFailed
        }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    /// The keys from `jwks` that could plausibly have signed an RS256 JWT.
    ///
    /// Only RSA signing keys qualify: without the filter, a JWKS whose first entry is an
    /// encryption or EC key would fail a valid JWT that carries no `kid`. `use` and `alg` are
    /// optional in a JWK (RFC 7517), so a key that omits them stays a candidate.
    private func selectJwks(from jwks: [String: Any], kid: String?) -> [[String: Any]] {
        guard let keys = jwks["keys"] as? [[String: Any]] else { return [] }
        let candidates = keys.filter { key in
            (key["kty"] as? String) == "RSA"
                && ((key["use"] as? String) ?? "sig") == "sig"
                && ((key["alg"] as? String) ?? "RS256") == "RS256"
        }
        guard let kid else { return candidates }
        return candidates.filter { ($0["kid"] as? String) == kid }
    }

    /// Verify `signature` against each candidate key, succeeding on the first that matches: a
    /// JWT with no `kid` gives no way to know which of several signing keys minted it.
    private func verifySignature(
        candidates: [[String: Any]], signingInput: Data, signature: Data
    ) throws {
        var lastError: Error = TokenVerificationError.invalidSignature(nil)
        for jwk in candidates {
            do {
                try verifySignature(
                    publicKey: try secKeyFromJwk(jwk), signingInput: signingInput,
                    signature: signature)
                return
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func verifySignature(publicKey: SecKey, signingInput: Data, signature: Data) throws {
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            signature as CFData,
            &error
        )
        if !isValid {
            // Never rethrow the CFError: it classifies as verification_failed, not invalid_id_token.
            throw TokenVerificationError.invalidSignature(reason(error))
        }
    }

    private func reason(_ error: Unmanaged<CFError>?) -> String? {
        error.map { ($0.takeRetainedValue() as Error).localizedDescription }
    }

    private func validateClaims(
        _ claims: [String: Any],
        issuer: String?,
        audience: String?,
        clockSkew: TimeInterval
    ) throws {
        let now = Date().timeIntervalSince1970
        // When an issuer is expected, `iss` must be present AND match: a missing iss must not
        // pass vacuously; `iss` is a required claim, not an optional one.
        if let issuer {
            guard let iss = claims["iss"] as? String else {
                throw TokenVerificationError.invalidClaims("Token missing required iss claim")
            }
            if iss != issuer {
                throw TokenVerificationError.invalidClaims("Issuer mismatch")
            }
        }

        if let audience {
            let audClaim = claims["aud"]
            // aud must equal the client id exactly, not merely contain it: stricter than OIDC
            // Core 3.1.3.7 step 3. Multi-audience tokens are rejected here.
            let audMatches: Bool
            if let audString = audClaim as? String {
                audMatches = audString == audience
            } else if let audArray = audClaim as? [String] {
                audMatches = audArray == [audience]
            } else {
                audMatches = false
            }
            if !audMatches {
                throw TokenVerificationError.invalidClaims("Audience mismatch")
            }

            // OIDC Core 3.1.3.7 steps 4-5: an azp present at any audience count must name us.
            if let azp = claims["azp"] as? String, azp != audience {
                throw TokenVerificationError.invalidClaims(
                    "Authorized party (azp) does not match this client")
            }
        }

        // Always require exp so a token with no expiry can never be accepted as non-expiring.
        guard let exp = claims["exp"] as? TimeInterval else {
            throw TokenVerificationError.invalidClaims("Token missing required exp claim")
        }
        if now - clockSkew > exp {
            throw TokenVerificationError.invalidClaims("Token expired")
        }
        if let nbf = claims["nbf"] as? TimeInterval, now + clockSkew < nbf {
            throw TokenVerificationError.invalidClaims("Token not yet valid")
        }
        if let iat = claims["iat"] as? TimeInterval, now + clockSkew < iat {
            throw TokenVerificationError.invalidClaims("Token used before issued")
        }
    }

    private func secKeyFromJwk(_ jwk: [String: Any]) throws -> SecKey {
        guard let kty = jwk["kty"] as? String, kty == "RSA" else {
            throw TokenVerificationError.unsupportedKeyType
        }
        guard let n = jwk["n"] as? String, let e = jwk["e"] as? String else {
            throw TokenVerificationError.invalidKey(nil)
        }

        // A JWK modulus is an unsigned big-endian integer, but some issuers emit it with DER's
        // sign pad. Strip leading zeros before measuring it, or a padded 2048-bit key reads as
        // 2056 bits; derEncodeInteger re-adds the pad where DER needs it.
        let modulus = Data(try Base64Url.decode(n).drop { $0 == 0x00 })
        let exponent = try Base64Url.decode(e)

        // Floor the modulus at 2048 bits: RS256 with a short one is forgeable and SecKey will
        // happily build a key from it.
        guard modulus.count >= 256 else {
            throw TokenVerificationError.invalidKey(nil)
        }
        let publicKeyData = derEncodeSubjectPublicKeyInfo(modulus: modulus, exponent: exponent)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8,
        ]

        var error: Unmanaged<CFError>?
        guard
            let key = SecKeyCreateWithData(
                publicKeyData as CFData, attributes as CFDictionary, &error)
        else {
            throw TokenVerificationError.invalidKey(reason(error))
        }
        return key
    }

    private func derEncodeSubjectPublicKeyInfo(modulus: Data, exponent: Data) -> Data {
        let rsaPublicKey = derEncodeSequence(
            derEncodeInteger(modulus) + derEncodeInteger(exponent)
        )

        let rsaOid: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let algorithmIdentifier = derEncodeSequence(Data(rsaOid) + Data([0x05, 0x00]))
        let subjectPublicKey = derEncodeBitString(rsaPublicKey)

        return derEncodeSequence(algorithmIdentifier + subjectPublicKey)
    }

    private func derEncodeInteger(_ value: Data) -> Data {
        var bytes = value
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0x00, at: 0)
        }
        return Data([0x02]) + derEncodeLength(bytes.count) + bytes
    }

    private func derEncodeSequence(_ value: Data) -> Data {
        return Data([0x30]) + derEncodeLength(value.count) + value
    }

    private func derEncodeBitString(_ value: Data) -> Data {
        return Data([0x03]) + derEncodeLength(value.count + 1) + Data([0x00]) + value
    }

    private func derEncodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        let lengthBytes = withUnsafeBytes(of: length.bigEndian, Array.init).drop { $0 == 0 }
        return Data([UInt8(0x80 | lengthBytes.count)]) + lengthBytes
    }
}
