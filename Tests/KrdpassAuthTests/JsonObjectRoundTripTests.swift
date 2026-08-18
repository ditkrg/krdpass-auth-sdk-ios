import XCTest

@testable import KrdpassAuth

/// JSONValue.jsonObject is the inverse of init(jsonObject:). Codecs that take `Any` will
/// compile if passed a JSONValue, then silently fail to serialize at runtime.
final class JsonObjectRoundTripTests: XCTestCase {

    func testRoundTripsEveryJsonShape() throws {
        let original: [String: Any] = [
            "sub": "abc",
            "email_verified": true,
            "age": 42,
            "score": 1.5,
            "roles": ["a", "b"],
            "nested": ["k": "v", "deep": ["n": 1]],
            "missing": NSNull(),
        ]

        let value = try XCTUnwrap(JSONValue(jsonObject: original))
        let back = try XCTUnwrap(value.jsonObject as? [String: Any])

        XCTAssertEqual(back["sub"] as? String, "abc")
        XCTAssertEqual(back["email_verified"] as? Bool, true)
        XCTAssertEqual(back["age"] as? Double, 42)
        XCTAssertEqual(back["score"] as? Double, 1.5)
        XCTAssertEqual(back["roles"] as? [String], ["a", "b"])
        XCTAssertEqual((back["nested"] as? [String: Any])?["k"] as? String, "v")
        XCTAssertTrue(back["missing"] is NSNull)
    }

    /// The result has to survive JSONSerialization.
    func testRawJsonObjectIsSerializable() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "name": "Test User",
                "email_verified": true,
                "roles": ["citizen"],
            ]))

        XCTAssertTrue(JSONSerialization.isValidJSONObject(info.rawJsonObject))
        let data = try JSONSerialization.data(withJSONObject: info.rawJsonObject)
        let decoded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(decoded["sub"] as? String, "user-1")
        XCTAssertEqual(decoded["email_verified"] as? Bool, true)
    }

    /// Both halves of ``JSONValue``'s split policy: the array with one unrepresentable element
    /// fails closed to nil, and the enclosing object then drops just that one key.
    func testArrayWithAnUnrepresentableElementIsDroppedWholesale() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: ["sub": "user-1", "roles": ["citizen", Date()]]))
        XCTAssertNil(info.raw["roles"])
        XCTAssertEqual(info.sub, "user-1", "the rest of the object survives the dropped key")
    }

    /// `raw` itself is NOT serializable, so forwarding it to JSONSerialization is broken even
    /// though it compiles.
    func testRawIsNotDirectlySerializable() throws {
        let info = try XCTUnwrap(KrdpassUserInfo(json: ["sub": "user-1"]))
        XCTAssertFalse(JSONSerialization.isValidJSONObject(info.raw))
    }

    /// A userinfo claim is attacker-influenced data off the wire, and `Int(1e30)` TRAPS, so
    /// `intValue` must return nil for an out-of-range number rather than crash the app.
    func testIntValueReturnsNilInsteadOfTrappingOnAnOutOfRangeNumber() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: ["sub": "user-1", "huge": 1e30, "negative": -1e30]))

        XCTAssertNil(info.raw["huge"]?.intValue)
        XCTAssertNil(info.raw["negative"]?.intValue)
        // The value is still readable as what it actually is.
        XCTAssertEqual(info.raw["huge"]?.doubleValue, 1e30)
    }

    func testIntValueReturnsNilForAFractionalNumberAndTheValueForAWholeOne() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: ["sub": "user-1", "score": 1.5, "age": 42, "whole": 42.0]))

        XCTAssertNil(info.raw["score"]?.intValue, "a fractional number is not an Int")
        XCTAssertEqual(info.raw["age"]?.intValue, 42)
        XCTAssertEqual(info.raw["whole"]?.intValue, 42)
    }
}
