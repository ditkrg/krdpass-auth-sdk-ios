import XCTest

@testable import KrdpassAuth

/// `constantTimeEquals` backs the `state` comparison in the callback handler. These cases
/// check the helper directly; the nil/empty fail-closed behavior at its call site is covered
/// by AuthResultDecisionTests.
final class ConstantTimeEqualsTests: XCTestCase {

    func testEqualStringsMatch() {
        XCTAssertTrue(KrdpassAuth.constantTimeEquals("abc123", "abc123"))
    }

    func testEqualLengthDifferingStringsDoNotMatch() {
        XCTAssertFalse(KrdpassAuth.constantTimeEquals("abc123", "abc124"))
    }

    func testDifferentLengthStringsDoNotMatch() {
        XCTAssertFalse(KrdpassAuth.constantTimeEquals("abc123", "abc12"))
    }

    func testEmptyStringsMatch() {
        // The helper itself has no notion of "blank means fail closed"; that guard lives in
        // isStateMatch, which AuthResultDecisionTests exercises.
        XCTAssertTrue(KrdpassAuth.constantTimeEquals("", ""))
    }
}
