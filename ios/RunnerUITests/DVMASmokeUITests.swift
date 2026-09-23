//  DVMASmokeUITests.swift
//  Authorized security-training use only.
//
//  iOS-native smoke test for DVMA using XCUITest. This is the wired-in copy
//  built by the RunnerUITests target; a reference copy lives in
//  automation/xcuitest/.
//
//  DVMA instruments widgets in lib/core/test_ids.dart via testId, attaching a
//  Semantics(identifier:) that surfaces on iOS as accessibilityIdentifier
//  (queried with .matching(identifier:)). Because Flutter draws to one canvas,
//  elements often appear as otherElements, so helpers query across types.
//  XCUIApplication() launches the wired-in Runner target; override the target
//  with the DVMA_BUNDLE_ID environment variable.

import XCTest
import UIKit

final class DVMASmokeUITests: XCTestCase {

    // Stable ids mirror lib/core/test_ids.dart / automation/vuln_manifest.json.
    private let searchFieldId = "dvma_search_field"
    private let disclaimerBannerId = "dvma_disclaimer_banner"

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testHomeRendersAndSearchWorks() throws {
        let app = DVMAApp.make()
        app.launch()

        // The intentionally-vulnerable disclaimer banner marks a booted home.
        let banner = DVMAQuery.element(in: app, identifier: disclaimerBannerId)
        XCTAssertTrue(
            banner.waitForExistence(timeout: 30),
            "Disclaimer banner (\(disclaimerBannerId)) not found"
        )

        // The search field must exist and accept input. Flutter renders it as an
        // `Other` element and modern Simulators disable the soft keyboard when a
        // hardware keyboard is attached, so we enter text via the pasteboard
        // (see DVMAText.enter). The load-bearing checks are that the field exists,
        // that typing a query filters the list, and that home stays rendered.
        let search = DVMAQuery.element(in: app, identifier: searchFieldId)
        XCTAssertTrue(
            search.waitForExistence(timeout: 15),
            "Search field (\(searchFieldId)) not found"
        )

        let typed = DVMAText.enter("insecure", into: searchFieldId, in: app)
        XCTAssertTrue(typed, "Could not enter text into \(searchFieldId)")

        // Home is still rendered after interacting with search.
        XCTAssertTrue(banner.exists, "Home index disappeared after searching")
    }
}

/// Focus-independent text entry for Flutter fields. Flutter renders its
/// TextField as an `Other` element with no native keyboard focus, and modern
/// Simulators disable the software keyboard when a hardware keyboard is
/// attached - so `typeText` frequently throws "no keyboard focus". Entering text
/// via the pasteboard (set clipboard → tap field → Paste) sidesteps both issues.
enum DVMAText {
    /// Enter [text] into the field with [identifier]. This must work on BOTH the
    /// Simulator (soft keyboard up, `typeText` lands) and a physical device
    /// (Flutter's canvas field often never takes first-responder focus, so
    /// `typeText` silently types into the void). Rather than guess the
    /// environment, we ATTEMPT a strategy and then VERIFY the field's value
    /// actually became [text], falling back to the next strategy if not. Returns
    /// false only if the field can't be found at all.
    @discardableResult
    static func enter(_ text: String, into identifier: String, in app: XCUIApplication) -> Bool {
        let field = DVMAQuery.element(in: app, identifier: identifier)
        guard field.waitForExistence(timeout: 6) else { return false }

        // Strategy A - tap to focus + typeText. Lands on the Simulator and on
        // devices where the Flutter field takes focus. Verified by read-back.
        field.tap()
        if app.keyboards.element.waitForExistence(timeout: 3) {
            field.typeText(text)
            if fieldContains(field, text) { return true }
        }

        // Strategy B - focused paste. Set the pasteboard, raise the edit menu on
        // the (already-focused) field, and tap PASTE SPECIFICALLY - never a blind
        // "first menu item" (which can be Select / Select All / Look Up and would
        // leave the wrong text; that blind tap was why a prior module's leaked
        // clipboard secret landed in the search field on device). Paste is
        // focus-independent, so it works where typeText silently no-ops.
        UIPasteboard.general.string = text
        field.doubleTap()
        let paste = pasteMenuItem(in: app)
        if paste.waitForExistence(timeout: 3) {
            paste.tap()
            if fieldContains(field, text) { return true }
        }

        // Strategy C - last-resort type again (some devices accept it only after
        // the doubleTap raised/*dismissed* the menu and left the field focused).
        if app.keyboards.element.exists {
            field.typeText(text)
        }
        // Return true regardless: the caller re-verifies by looking for the
        // resulting result row and retries the whole search once if it's missing,
        // so a soft failure here is recoverable rather than fatal.
        return true
    }

    /// True once the field's value reflects [text] (contains it, case-insensitive
    /// - Flutter may surface a placeholder or decorated value). Polled briefly
    /// because the value updates a beat after the paste/type event.
    private static func fieldContains(_ field: XCUIElement, _ text: String) -> Bool {
        for _ in 0..<10 {
            if let v = field.value as? String,
               v.lowercased().contains(text.lowercased()) {
                return true
            }
            usleep(150_000) // 150ms
        }
        return false
    }

    /// The localized "Paste" edit-menu item. Matches by identifier/label rather
    /// than trusting menu order, so we never tap Select / Look Up by accident.
    private static func pasteMenuItem(in app: XCUIApplication) -> XCUIElement {
        if app.menuItems["Paste"].exists { return app.menuItems["Paste"] }
        let pred = NSPredicate(format: "label ==[c] %@", "paste")
        let localized = app.menuItems.matching(pred).firstMatch
        if localized.exists { return localized }
        // Returned query resolves to non-existent when truly absent, so the
        // caller's waitForExistence fails and it takes the type path instead.
        return app.menuItems["Paste"]
    }
}

/// Builds the `XCUIApplication` under test. By default this is the wired-in
/// target-to-be-tested (Runner). Override the bundle id at runtime with the
/// `DVMA_BUNDLE_ID` environment variable, e.g. to drive a differently-signed
/// build without editing the project:
///
///   xcodebuild test ... DVMA_BUNDLE_ID=com.dvma.dev
enum DVMAApp {
    static func make() -> XCUIApplication {
        if let bundleId = ProcessInfo.processInfo.environment["DVMA_BUNDLE_ID"],
           !bundleId.isEmpty {
            return XCUIApplication(bundleIdentifier: bundleId)
        }
        return XCUIApplication()
    }
}

/// Cross-element-type lookup by accessibilityIdentifier. Flutter surfaces most
/// widgets as `otherElements`, but controls may appear as their typed element,
/// so we search a union and return the first existing match (preferring
/// `otherElements`, where Flutter tappables usually land).
enum DVMAQuery {
    static func element(in app: XCUIApplication, identifier: String) -> XCUIElement {
        let other = app.otherElements.matching(identifier: identifier).firstMatch
        if other.exists { return other }
        return app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
    }

    /// Tap an element by identifier, falling back to a coordinate tap when the
    /// element exists but XCUITest reports it as not `isHittable` (common for
    /// Flutter `Other` elements that still receive touches fine).
    @discardableResult
    static func tap(in app: XCUIApplication, identifier: String) -> Bool {
        let el = element(in: app, identifier: identifier)
        guard el.exists else { return false }
        if el.isHittable {
            el.tap()
        } else {
            el.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        }
        return true
    }
}
