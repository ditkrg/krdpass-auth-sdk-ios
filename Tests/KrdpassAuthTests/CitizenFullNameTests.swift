import XCTest

@testable import KrdpassAuth

/// citizenFullName joins the four citizen name parts.
final class CitizenFullNameTests: XCTestCase {

    private func makeUserInfo(_ parts: [String: String]) throws -> KrdpassUserInfo {
        var json: [String: Any] = ["sub": "citizen-1"]
        for (key, value) in parts { json[key] = value }
        return try XCTUnwrap(KrdpassUserInfo(json: json))
    }

    func testJoinsAllFourParts() throws {
        let user = try makeUserInfo([
            "citizen_first": "Aram", "citizen_second": "Karwan",
            "citizen_third": "Rebaz", "citizen_surname": "Barzani",
        ])
        XCTAssertEqual(user.citizenFullName, "Aram Karwan Rebaz Barzani")
    }

    func testTrimsPaddingOnAMiddlePart() throws {
        // The padded part is in the middle, where untrimmed padding turns into a double space.
        let user = try makeUserInfo([
            "citizen_first": "Aram", "citizen_second": "  Karwan  ", "citizen_surname": "Barzani",
        ])
        XCTAssertEqual(user.citizenFullName, "Aram Karwan Barzani")
    }

    func testTrimsPaddingOnTheFirstAndLastParts() throws {
        let user = try makeUserInfo([
            "citizen_first": " Aram", "citizen_surname": "Barzani ",
        ])
        XCTAssertEqual(user.citizenFullName, "Aram Barzani")
    }

    func testDropsANewlineOnlyPart() throws {
        // .whitespaces would keep this one; Kotlin and Dart trim() drop it.
        let user = try makeUserInfo([
            "citizen_first": "Aram", "citizen_second": "\n", "citizen_surname": "Barzani",
        ])
        XCTAssertEqual(user.citizenFullName, "Aram Barzani")
    }

    func testDropsBlankAndWhitespaceOnlyParts() throws {
        let user = try makeUserInfo([
            "citizen_first": "Aram", "citizen_second": "", "citizen_third": "   ",
            "citizen_surname": "Barzani",
        ])
        XCTAssertEqual(user.citizenFullName, "Aram Barzani")
    }

    func testReturnsNilWhenEveryPartIsBlank() throws {
        let user = try makeUserInfo([
            "citizen_first": "", "citizen_second": "   ",
            "citizen_third": "\n", "citizen_surname": "\t",
        ])
        XCTAssertNil(user.citizenFullName)
    }

    func testReturnsNilWhenEveryPartIsAbsent() throws {
        XCTAssertNil(try makeUserInfo([:]).citizenFullName)
    }
}
