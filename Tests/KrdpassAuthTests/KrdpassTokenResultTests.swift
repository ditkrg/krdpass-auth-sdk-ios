import XCTest

@testable import KrdpassAuth

final class KrdpassTokenResultTests: XCTestCase {

    func testInitDictionary_camelCase() {
        let result = KrdpassTokenResult(dictionary: [
            "accessToken": "at-1",
            "idToken": "id-1",
            "tokenType": "Bearer",
            "expiresIn": 1800,
            "refreshToken": "rt-1",
            "scope": "openid profile",
        ])

        XCTAssertEqual(result?.accessToken, "at-1")
        XCTAssertEqual(result?.idToken, "id-1")
        XCTAssertEqual(result?.tokenType, "Bearer")
        XCTAssertEqual(result?.expiresIn, 1800)
        XCTAssertEqual(result?.refreshToken, "rt-1")
        XCTAssertEqual(result?.scope, "openid profile")
    }

    func testInitDictionary_snakeCase() {
        let result = KrdpassTokenResult(dictionary: [
            "access_token": "at-2",
            "id_token": "id-2",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "rt-2",
            "scope": "openid",
        ])

        XCTAssertEqual(result?.accessToken, "at-2")
        XCTAssertEqual(result?.idToken, "id-2")
        XCTAssertEqual(result?.tokenType, "Bearer")
        XCTAssertEqual(result?.expiresIn, 900)
        XCTAssertEqual(result?.refreshToken, "rt-2")
        XCTAssertEqual(result?.scope, "openid")
    }

    func testInitDictionary_appliesDefaults() {
        let result = KrdpassTokenResult(dictionary: ["accessToken": "at-3"])

        XCTAssertEqual(result?.tokenType, "Bearer")
        XCTAssertEqual(result?.expiresIn, 3600)
        XCTAssertNil(result?.idToken)
        XCTAssertNil(result?.refreshToken)
        XCTAssertNil(result?.scope)
    }

    func testInitDictionary_returnsNilWhenAccessTokenMissing() {
        XCTAssertNil(KrdpassTokenResult(dictionary: ["idToken": "id-only"]))
    }

    func testInitDictionary_returnsNilWhenAccessTokenEmpty() {
        XCTAssertNil(KrdpassTokenResult(dictionary: ["accessToken": ""]))
    }
}
