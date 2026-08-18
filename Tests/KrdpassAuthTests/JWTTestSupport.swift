import Foundation
import Security

/// Shared helpers for minting RS256-signed JWTs against an ephemeral 2048-bit RSA test key,
/// whose public half is published as ``jwkJson`` (kid `test-key`), so verification tests
/// exercise the real crypto path.
enum JWTTestSupport {
    /// Generated per process rather than checked in as a PEM literal: an armored RSA key would
    /// permanently trip secret scanners. Never path-exempt this file in a scanner config either;
    /// that makes it a blind spot for a real leak.
    ///
    /// nonisolated(unsafe): `SecKey` is not `Sendable`, but this one is written once by the
    /// lazy static initializer and only ever read (immutably) afterwards.
    nonisolated(unsafe) private static let privateKey: SecKey = {
        // isPermanent false: an in-memory key, so a test run never writes to the keychain.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrIsPermanent as String: false,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("Could not generate the RSA test key: \(String(describing: error))")
        }
        return key
    }()

    /// The JWKS the mocked endpoint serves: the public half of ``privateKey``, kid `test-key`.
    /// Kept on one line and free of spaces because ``jwkJsonEncryptionKeyFirst`` takes it apart
    /// again by substring.
    static let jwkJson: String = {
        let (n, e) = publicKeyComponents()
        return
            "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"\(n)\",\"e\":\"\(e)\"}]}"
    }()

    /// base64url `n` and `e` for ``privateKey``'s public half. `SecKeyCopyExternalRepresentation`
    /// hands back PKCS#1 `SEQUENCE { INTEGER n, INTEGER e }`, so two DER integers is the parse.
    private static func publicKeyComponents() -> (n: String, e: String) {
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
            let der = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        else {
            fatalError("Could not export the RSA test key: \(String(describing: error))")
        }
        let (sequence, _) = derValue(der)
        let (modulus, afterModulus) = derValue(sequence)
        let (exponent, _) = derValue(afterModulus)
        // A DER INTEGER is signed, so a modulus with the high bit set carries a leading 0x00 pad.
        // The JWK value is the unsigned big-endian integer, so that pad byte must come back off.
        return (base64UrlEncode(modulus.drop { $0 == 0x00 }), base64UrlEncode(exponent))
    }

    /// Splits one DER TLV off the front of `data`, returning its value bytes and what follows.
    /// Long-form lengths are handled because a 2048-bit modulus is a 0x82-length integer.
    private static func derValue(_ data: Data) -> (value: Data, rest: Data) {
        var index = data.startIndex + 1  // skip the tag byte
        var length = Int(data[index])
        index += 1
        if length & 0x80 != 0 {
            let lengthBytes = length & 0x7F
            length = data[index..<index + lengthBytes].reduce(0) { $0 << 8 | Int($1) }
            index += lengthBytes
        }
        return (data[index..<index + length], data[(index + length)...])
    }

    /// The same test key republished under a rotated `kid` (`test-key-v2`), for exercising the
    /// JWKS refetch-on-kid-miss path. The signature still validates, only the key id differs.
    static var jwkJsonRotated: String {
        jwkJson.replacingOccurrences(of: "test-key", with: "test-key-v2")
    }

    /// A JWKS whose FIRST entry is an RSA **encryption** key, with the real signing key second.
    /// Picking `keys.first` for a JWT that carries no `kid` would select the wrong one.
    static var jwkJsonEncryptionKeyFirst: String {
        let signingKey =
            jwkJson
            .replacingOccurrences(of: "{\"keys\":[", with: "")
            .replacingOccurrences(of: "]}", with: "")
        let encryptionKey =
            signingKey
            .replacingOccurrences(of: "\"use\":\"sig\"", with: "\"use\":\"enc\"")
            .replacingOccurrences(of: "\"alg\":\"RS256\"", with: "\"alg\":\"RSA-OAEP\"")
            .replacingOccurrences(of: "\"kid\":\"test-key\"", with: "\"kid\":\"enc-key\"")
        return "{\"keys\":[\(encryptionKey),\(signingKey)]}"
    }

    /// Mints an RS256-signed JWT for the fixed test key (kid `test-key`).
    static func makeToken(
        issuer: String,
        audience: String,
        expiresIn: Int,
        issuedAt: Int? = nil,
        notBefore: Int? = nil,
        nonce: String? = nil,
        subject: String = "test-subject",
        omitIssuer: Bool = false,
        kid: String? = "test-key",
        extraClaims: [String: Any] = [:]
    ) throws -> String {
        let now = Int(Date().timeIntervalSince1970)
        let iat = issuedAt ?? now
        let nbf = notBefore ?? iat
        var header: [String: Any] = [
            "alg": "RS256",
            "typ": "JWT",
        ]
        // A JWT is allowed to omit `kid` (RFC 7515), which forces the verifier to pick a key
        // from the JWKS on its own. `kid: nil` mints that shape.
        if let kid = kid { header["kid"] = kid }
        var payload: [String: Any] = [
            "aud": audience,
            "iat": iat,
            "nbf": nbf,
            "exp": now + expiresIn,
            "sub": subject,
        ]
        if !omitIssuer { payload["iss"] = issuer }
        if let nonce = nonce { payload["nonce"] = nonce }
        // Applied last so a caller can also replace a claim this helper set, which is how the
        // multi-audience `azp` cases mint an array `aud` without a second minting function.
        payload.merge(extraClaims) { _, extra in extra }

        let headerData = try JSONSerialization.data(withJSONObject: header)
        let payloadData = try JSONSerialization.data(withJSONObject: payload)
        let signingInput = "\(base64UrlEncode(headerData)).\(base64UrlEncode(payloadData))"
        let signature = try sign(data: signingInput.data(using: .utf8)!)
        return "\(signingInput).\(base64UrlEncode(signature))"
    }

    /// Mints a JWT with an arbitrary `alg` header (for algorithm-confusion tests). The token is
    /// always well-formed (3 segments); even `alg: none` gets a dummy signature, so verification
    /// is forced through the `alg` check (the confusion defense), not the structural three-part parse.
    static func makeTokenWithAlgorithm(
        _ alg: String,
        audience: String,
        issuer: String = "https://issuer.example",
        expiresIn: Int = 300
    ) throws -> String {
        let now = Int(Date().timeIntervalSince1970)
        let header: [String: Any] = ["alg": alg, "kid": "test-key", "typ": "JWT"]
        let payload: [String: Any] = [
            "aud": audience, "iss": issuer, "iat": now, "nbf": now,
            "exp": now + expiresIn, "sub": "test-subject",
        ]
        let headerData = try JSONSerialization.data(withJSONObject: header)
        let payloadData = try JSONSerialization.data(withJSONObject: payload)
        let signingInput = "\(base64UrlEncode(headerData)).\(base64UrlEncode(payloadData))"
        let sig =
            alg == "none"
            ? base64UrlEncode(Data("unused".utf8))
            : base64UrlEncode(try sign(data: signingInput.data(using: .utf8)!))
        return "\(signingInput).\(sig)"
    }

    static func sign(data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let sig = SecKeyCreateSignature(
                privateKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                data as CFData,
                &error
            ) as Data?
        else {
            throw error?.takeRetainedValue() ?? NSError(domain: "JWTTestSupport.sign", code: -1)
        }
        return sig
    }

    static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
