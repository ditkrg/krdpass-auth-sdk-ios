import XCTest

@testable import KrdpassAuth

/// A blank claim means "not provided". CAS sends "" for a claim it has no value for;
/// surfacing "" here instead would make an app that branches on `upn == nil` treat a blank
/// claim as present.
final class BlankClaimTests: XCTestCase {

    func testEmptyStringClaimReadsAsNil() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upn": "",
                "email": "",
                "did": "",
            ]))
        XCTAssertNil(info.upn)
        XCTAssertNil(info.email)
        XCTAssertNil(info.did)
    }

    func testWhitespaceOnlyClaimReadsAsNil() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upn": "   ",
                "given_name": "\t\n",
                "birthdate": " ",
            ]))
        XCTAssertNil(info.upn)
        XCTAssertNil(info.givenName)
        XCTAssertNil(info.birthdate)
    }

    /// The filter drops the claim, it does not trim the value: a padded claim survives as sent.
    func testPaddedClaimSurvivesUntrimmed() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "upn": " 1990123456 ",
            ]))
        XCTAssertEqual(info.upn, " 1990123456 ")
    }

    /// `picture` falls through to the citizen registry picture when it is blank, not only when
    /// it is absent.
    func testBlankPictureFallsBackToCitizenProfilePicture() throws {
        let info = try XCTUnwrap(
            KrdpassUserInfo(json: [
                "sub": "user-1",
                "picture": "  ",
                "citizen_profile_picture": "https://cdn.example.com/a.png",
            ]))
        XCTAssertEqual(info.picture, "https://cdn.example.com/a.png")
    }

    /// sub is the primary key and keeps its own rule: empty fails the parse, blank does not.
    func testBlankSubIsNotFilteredToNil() throws {
        XCTAssertNil(KrdpassUserInfo(json: ["sub": ""]))
        let info = try XCTUnwrap(KrdpassUserInfo(json: ["sub": " "]))
        XCTAssertEqual(info.sub, " ")
    }

    /// The raw claim set is untouched: the filter is about the typed accessors only.
    func testRawKeepsTheBlankValue() throws {
        let info = try XCTUnwrap(KrdpassUserInfo(json: ["sub": "user-1", "upn": ""]))
        XCTAssertEqual(info.raw["upn"]?.stringValue, "")
    }
}
