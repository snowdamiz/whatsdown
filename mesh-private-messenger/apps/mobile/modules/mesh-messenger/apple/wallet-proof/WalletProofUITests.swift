import XCTest

final class WalletProofUITests: XCTestCase {
  func testCustodyConfirmationAndRealBackgroundCancellation() throws {
    let app = XCUIApplication()
    app.launch()
    func tap(_ title: String) {
      let button = app.buttons[title]
      XCTAssertTrue(button.waitForExistence(timeout: 10), title)
      button.tap()
    }
    tap("Test canceled creation")
    tap("Cancel")
    tap("Create disposable wallet")
    tap("Create wallet")
    tap("Check stored address")
    tap("Sign local test packet")
    let amount = app.alerts.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "18446744073.709551615 SOL")).firstMatch
    XCTAssertTrue(amount.waitForExistence(timeout: 10))
    tap("Confirm payment")
    tap("Test background cancellation")
    XCTAssertTrue(app.alerts.buttons["Confirm payment"].waitForExistence(timeout: 10))
    XCUIDevice.shared.press(.home)
    app.activate()
    // The app fixture requires an actual UIApplicationWillResignActive event;
    // timeout/cancel alone cannot satisfy this step.
    tap("Finish proof")
    XCTAssertTrue(app.staticTexts["iOS native UI proof passed: cancel/create, persisted address, offline SDK signing, real background cancellation."].waitForExistence(timeout: 10))
  }
}
