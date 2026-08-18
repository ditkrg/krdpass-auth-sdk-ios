import XCTest

@testable import KrdpassAuth

/// upns (historical UPNs) is stored and never displayed, same rule as sub. Empty array when
/// absent or malformed.
final class UpnsTests: XCTestCase {

    func testUpnsPresentAsArrayOfStringsParses() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upns": ["old1@krd", "old2@krd"],
            ]))
        XCTAssertEqual(info.upns, ["old1@krd", "old2@krd"])
    }

    func testUpnsAbsentYieldsEmptyArray() throws {
        let info = try XCTUnwrap(KrdpassUserInfo(json: ["sub": "user-1"]))
        XCTAssertEqual(info.upns, [])
    }

    func testUpnsNonArrayValueYieldsEmptyArray() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upns": "not-an-array",
            ]))
        XCTAssertEqual(info.upns, [])
    }

    /// Blank entries are kept, unlike the blank filter on the single-value claims: this list
    /// is stored verbatim rather than displayed.
    func testUpnsKeepsBlankEntries() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upns": ["old1@krd", "", "  "],
            ]))
        XCTAssertEqual(info.upns, ["old1@krd", "", "  "])
    }

    /// Fails closed like ``JSONValue``'s array decoding, but it is a second, separate check: `42`
    /// is a perfectly good JSONValue, so the element that gets rejected here is rejected for not
    /// being a string, not for being unrepresentable.
    func testUpnsArrayWithNonStringElementYieldsEmptyArray() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upns": ["old1@krd", 42],
            ]))
        XCTAssertEqual(info.upns, [])
    }
}
