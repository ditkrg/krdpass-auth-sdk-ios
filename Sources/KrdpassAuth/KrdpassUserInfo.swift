import Foundation

/// A single JSON value from a claims payload.
///
/// Used instead of `[String: Any]` so ``KrdpassUserInfo`` is `Sendable`. Unrepresentable values
/// fail closed per container: one bad element drops a whole ARRAY (a surviving list is never
/// silently shorter than what the server sent), while an OBJECT drops only the offending key.
public enum JSONValue: Sendable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    /// The value as a `String`, or nil if it is not a JSON string.
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    /// The value as a `Double`, or nil if it is not a JSON number.
    public var doubleValue: Double? {
        if case .number(let value) = self { return value }
        return nil
    }

    /// The value as an `Int`, or nil if it is not a JSON number exactly representable as one.
    ///
    /// `Int(exactly:)`, not `Int(_:)`: the latter TRAPS on an out-of-range value, so a hostile
    /// claim like `{"x": 1e30}` would crash the app the moment it read the claim.
    public var intValue: Int? {
        doubleValue.flatMap { Int(exactly: $0) }
    }

    /// The value as a `Bool`, or nil if it is not a JSON boolean.
    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    /// The value as an array, or nil if it is not a JSON array.
    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    /// The value as an object, or nil if it is not a JSON object.
    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    /// The value as a `String`, or nil if it is not a JSON string or carries only whitespace.
    ///
    /// Every optional string claim reads through this so a blank claim is absent rather than
    /// `""`. The surviving value is untrimmed.
    var nonBlankString: String? {
        guard let value = stringValue,
            !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        return value
    }

    /// The value as Foundation JSON types, the inverse of `init(jsonObject:)`.
    ///
    /// Use this when handing claims to something that expects `JSONSerialization` output: those
    /// take `Any`, so passing a `JSONValue` directly compiles but does not serialize.
    public var jsonObject: Any {
        switch self {
        case .string(let value): return value
        case .number(let value): return value
        case .bool(let value): return value
        case .array(let value): return value.map(\.jsonObject)
        case .object(let value): return value.mapValues(\.jsonObject)
        case .null: return NSNull()
        }
    }

    /// Convert a value produced by `JSONSerialization`. Returns nil for anything that is not JSON.
    public init?(jsonObject value: Any) {
        switch value {
        case is NSNull:
            self = .null
        case let number as NSNumber:
            // JSONSerialization bridges true/false to NSNumber, and `as? Bool` succeeds for any
            // numeric NSNumber, so booleans have to be told apart by CoreFoundation type.
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else {
                self = .number(number.doubleValue)
            }
        case let string as String:
            self = .string(string)
        case let array as [Any]:
            // Fail closed: one unrepresentable element nils the whole array.
            let values = array.map(JSONValue.init(jsonObject:))
            guard !values.contains(where: { $0 == nil }) else { return nil }
            self = .array(values.compactMap { $0 })
        case let object as [String: Any]:
            self = .object(object.compactMapValues(JSONValue.init(jsonObject:)))
        default:
            return nil
        }
    }

    /// Convert a value that came straight out of `JSONSerialization`, where every value is
    /// representable by construction, so `.null` is unreachable rather than a fallback.
    init(jsonSerializationOutput value: Any) {
        self = JSONValue(jsonObject: value) ?? .null
    }
}

/// User information claims returned by the UserInfo endpoint: typed access to standard OpenID
/// Connect claims and KRDPASS-specific claims.
public struct KrdpassUserInfo: Sendable, CustomStringConvertible {
    /// Raw claims returned from the UserInfo endpoint, for accessing any custom claims:
    /// `userInfo.raw["custom_claim"]?.stringValue`.
    ///
    /// Warning: holds the **unredacted** response (email, citizen names, UPN, DID, birthdate).
    /// Unlike the typed accessors, `description` can't shield it; don't log `raw` wholesale.
    public let raw: [String: JSONValue]

    /// `raw` as Foundation JSON types, for handing the claim set to something that expects
    /// `JSONSerialization` output. Same unredacted content as `raw`, so the same warning applies.
    public var rawJsonObject: [String: Any] { raw.mapValues(\.jsonObject) }

    /// Subject - Identifier for the End-User.
    public let sub: String

    /// End-User's full name in displayable form including all name parts.
    public var name: String? { raw["name"]?.nonBlankString }

    /// Given name(s) or first name(s) of the End-User.
    public var givenName: String? { raw["given_name"]?.nonBlankString }

    /// Surname(s) or last name(s) of the End-User.
    public var familyName: String? { raw["family_name"]?.nonBlankString }

    /// URL of the End-User's profile picture.
    public var picture: String? {
        raw["picture"]?.nonBlankString ?? raw["citizen_profile_picture"]?.nonBlankString
    }

    /// End-User's preferred e-mail address (if granted by scope).
    public var email: String? { raw["email"]?.nonBlankString }

    public var citizenFirst: String? { raw["citizen_first"]?.nonBlankString }

    public var citizenSecond: String? { raw["citizen_second"]?.nonBlankString }

    public var citizenThird: String? { raw["citizen_third"]?.nonBlankString }

    public var citizenSurname: String? { raw["citizen_surname"]?.nonBlankString }

    public var citizenProfilePicture: String? { raw["citizen_profile_picture"]?.nonBlankString }

    public var birthdate: String? { raw["birthdate"]?.nonBlankString }

    public var sexAtBirth: String? { raw["sex_at_birth"]?.nonBlankString }

    public var upn: String? { raw["upn"]?.nonBlankString }

    /// Historical UPNs (previous values of `upn`). Must be stored; must never be displayed.
    /// Empty array when the claim is absent, or present but not an array of strings.
    public var upns: [String] {
        guard let values = raw["upns"]?.arrayValue else { return [] }
        let strings = values.compactMap(\.stringValue)
        // Fail closed: one non-string element drops the whole list, never a partial one.
        return strings.count == values.count ? strings : []
    }

    public var did: String? { raw["did"]?.nonBlankString }

    /// Create from the raw UserInfo claims. Fails if `sub` is missing or empty.
    public init?(raw: [String: JSONValue]) {
        guard let sub = raw["sub"]?.stringValue, !sub.isEmpty else {
            return nil
        }
        self.sub = sub
        self.raw = raw
    }

    /// Create from a decoded JSON dictionary, typically a `JSONSerialization` result or a backend
    /// response. Values that are not JSON are dropped. Fails if `sub` is missing or empty.
    public init?(json: [String: Any]) {
        self.init(raw: json.compactMapValues(JSONValue.init(jsonObject:)))
    }

    /// The full citizen name joined from the known parts, or nil when nothing survives.
    ///
    /// Parts are trimmed with `.whitespacesAndNewlines` before joining.
    public var citizenFullName: String? {
        let parts = [citizenFirst, citizenSecond, citizenThird, citizenSurname]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        if parts.isEmpty { return nil }
        return parts.joined(separator: " ")
    }

    public var description: String {
        return "KrdpassUserInfo(sub: [REDACTED], name: [REDACTED])"
    }
}
