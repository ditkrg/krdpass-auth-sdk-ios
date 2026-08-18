import Foundation

/// Configuration for KRDPASS authentication.
public struct KrdpassConfig: Equatable, Sendable {
    public let clientId: String

    /// The Redirect URI to return to after authentication.
    public let redirectUri: String

    /// The KRDPASS environment to use (production or development).
    public let environment: KrdpassEnvironment

    /// Create a new configuration. `redirectUri` must be HTTPS, e.g. "https://example.com/callback".
    public init(
        clientId: String, redirectUri: String, environment: KrdpassEnvironment = .production
    ) {
        // HTTPS is not enforced at init, to avoid crashing existing apps; see isValidRedirectUri.
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.environment = environment
    }

    /// Check that an authorization response is for this exact configured redirect endpoint:
    /// apart from the OAuth response parameters, scheme, host, effective port, encoded path and
    /// configured query entries must be unchanged.
    public func isValidRedirectUri(_ url: URL) -> Bool {
        guard let returned = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        return matches(returned)
    }

    func isValidRedirectUri(_ urlString: String) -> Bool {
        guard let returned = URLComponents(string: urlString) else { return false }
        return matches(returned)
    }

    private func matches(_ returned: URLComponents) -> Bool {
        guard let configured = URLComponents(string: redirectUri) else { return false }
        return RedirectUriValidator.matches(configured: configured, returned: returned)
    }
}

private enum RedirectUriValidator {
    private static let httpsDefaultPort = 443
    private static let oauthResponseParameters: Set<String> = [
        "code", "state", "error", "error_description", "error_uri", "iss",
    ]
    // "If present, must not be blank", never "must be present". Comparing `iss` (RFC 9207)
    // against the authorization server belongs to `KrdpassAuth.handle`, next to the state check.
    private static let requiredNonBlankResponseParameters: Set<String> = [
        "code", "state", "error", "iss",
    ]

    private struct QueryEntry: Equatable {
        let name: String
        let value: String?
    }

    static func matches(configured: URLComponents, returned: URLComponents) -> Bool {
        guard let configuredQuery = parseQuery(configured.percentEncodedQuery),
            let returnedQuery = parseQuery(returned.percentEncodedQuery)
        else { return false }
        return matchesRedirectBase(configured, returned)
            && hasValidResponseQuery(configuredQuery: configuredQuery, returnedQuery: returnedQuery)
    }

    private static func matchesRedirectBase(_ configured: URLComponents, _ returned: URLComponents)
        -> Bool
    {
        isSafeRedirect(configured) && isSafeRedirect(returned)
            && configured.scheme?.lowercased() == returned.scheme?.lowercased()
            && configured.host?.lowercased() == returned.host?.lowercased()
            && effectivePort(configured) == effectivePort(returned)
            && configured.percentEncodedPath == returned.percentEncodedPath
    }

    private static func isSafeRedirect(_ components: URLComponents) -> Bool {
        (components.scheme?.lowercased() == "https")
            && !(components.host ?? "").isEmpty
            && components.user == nil
            && components.password == nil
            && components.percentEncodedFragment == nil
            && isValidPercentEncoding(components.percentEncodedPath)
            && isValidPercentEncoding(components.percentEncodedQuery)
    }

    private static func effectivePort(_ components: URLComponents) -> Int {
        components.port ?? httpsDefaultPort
    }

    private static func hasValidResponseQuery(
        configuredQuery: [QueryEntry], returnedQuery: [QueryEntry]
    ) -> Bool {
        // A configured URI may not itself register an OAuth response-parameter name.
        guard configuredQuery.allSatisfy({ !oauthResponseParameters.contains($0.name) }),
            let responseEntries = removeConfiguredEntries(
                configuredQuery: configuredQuery, returnedQuery: returnedQuery)
        else { return false }

        let hasNoDuplicates = Dictionary(grouping: responseEntries, by: { $0.name })
            .values.allSatisfy { $0.count <= 1 }
        let configuredNames = Set(configuredQuery.map { $0.name })
        let doesNotOverrideConfiguredQuery = responseEntries.allSatisfy {
            !configuredNames.contains($0.name)
        }
        let isNotAmbiguous =
            !responseEntries.contains { $0.name == "code" }
            || !responseEntries.contains { $0.name == "error" }
        // Blank, not empty: `?iss=%20` carries no value and must fail like an absent one.
        let hasNoBlankSecurityValues =
            responseEntries
            .filter { requiredNonBlankResponseParameters.contains($0.name) }
            .allSatisfy { !isBlank($0.value) }

        return hasNoDuplicates && doesNotOverrideConfiguredQuery && isNotAmbiguous
            && hasNoBlankSecurityValues
    }

    private static func removeConfiguredEntries(
        configuredQuery: [QueryEntry], returnedQuery: [QueryEntry]
    ) -> [QueryEntry]? {
        var remaining = returnedQuery
        for configuredEntry in configuredQuery {
            guard let index = remaining.firstIndex(of: configuredEntry) else { return nil }
            remaining.remove(at: index)
        }
        return remaining
    }

    private static func parseQuery(_ encodedQuery: String?) -> [QueryEntry]? {
        guard let encodedQuery, !encodedQuery.isEmpty else { return [] }
        var entries: [QueryEntry] = []
        for encodedEntry in encodedQuery.split(separator: "&", omittingEmptySubsequences: false) {
            guard let entry = parseQueryEntry(String(encodedEntry)) else { return nil }
            entries.append(entry)
        }
        return entries
    }

    private static func parseQueryEntry(_ encodedEntry: String) -> QueryEntry? {
        let separator = encodedEntry.firstIndex(of: "=")
        let encodedName: String
        let encodedValue: String?
        if let separator {
            encodedName = String(encodedEntry[..<separator])
            encodedValue = String(encodedEntry[encodedEntry.index(after: separator)...])
        } else {
            encodedName = encodedEntry
            encodedValue = nil
        }
        guard !encodedName.isEmpty,
            isValidPercentEncoding(encodedName),
            isValidPercentEncoding(encodedValue)
        else { return nil }
        return QueryEntry(
            name: percentDecodeLossy(encodedName),
            value: encodedValue.map(percentDecodeLossy))
    }

    /// Percent-decode leniently: percent-formed bytes that are not valid UTF-8 become U+FFFD.
    /// `removingPercentEncoding` returns nil for those ("%FF"), which would reject the callback.
    private static func percentDecodeLossy(_ value: String) -> String {
        if let decoded = value.removingPercentEncoding { return decoded }
        var bytes: [UInt8] = []
        let units = Array(value.utf8)
        var index = 0
        while index < units.count {
            if units[index] == UInt8(ascii: "%"), index + 2 < units.count,
                let high = hexValue(units[index + 1]), let low = hexValue(units[index + 2])
            {
                bytes.append(high << 4 | low)
                index += 3
            } else {
                bytes.append(units[index])
                index += 1
            }
        }
        // String(decoding:as:) substitutes U+FFFD for ill-formed sequences.
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Reject syntactically malformed percent escapes: every `%` must be followed by two hex
    /// digits. Percent-formed but invalid UTF-8 is left to ``percentDecodeLossy(_:)``.
    private static func isValidPercentEncoding(_ value: String?) -> Bool {
        guard let value else { return true }
        let units = Array(value.utf8)
        var index = 0
        while index < units.count {
            if units[index] == UInt8(ascii: "%") {
                guard index + 2 < units.count,
                    isHexDigit(units[index + 1]), isHexDigit(units[index + 2])
                else { return false }
                index += 3
            } else {
                index += 1
            }
        }
        return true
    }

    /// Nil, empty, or whitespace only.
    private static func isBlank(_ value: String?) -> Bool {
        guard let value else { return true }
        return value.allSatisfy { $0.isWhitespace }
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        hexValue(byte) != nil
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return byte - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }
}
