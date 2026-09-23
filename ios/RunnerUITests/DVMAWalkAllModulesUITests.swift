//  DVMAWalkAllModulesUITests.swift
//  Authorized security-training use only.
//
//  iOS-native "walk every module" XCUITest driver for DVMA, parity with
//  Android's androidTest DvmaWalkAllModulesTest.kt. This is the copy built by
//  the RunnerUITests target; a reference copy lives in automation/xcuitest/.
//
//  Widgets are instrumented in lib/core/test_ids.dart via testId/testTapId,
//  which attach a Semantics(identifier:) that surfaces on iOS as the element's
//  accessibilityIdentifier. Tappables use testTapId (a MergeSemantics boundary)
//  so the id survives on iOS.
//
//  Navigation mirrors Android: category cards start collapsed, so vuln_row_*
//  only exist after expand-all. For each module we type its id into the search
//  field, tap the single result row, tap every demo action, and verify an
//  evidence_* panel. Text entry uses the pasteboard (set clipboard, tap field,
//  Paste) because a Flutter TextField is an Other element with no native
//  keyboard focus and Simulators disable the software keyboard.

import XCTest

final class DVMAWalkAllModulesUITests: XCTestCase {

    // Stable ids mirror lib/core/test_ids.dart.
    private let disclaimerBannerId = "dvma_disclaimer_banner"
    private let searchFieldId = "dvma_search_field"
    private let expandAllId = "dvma_expand_all"
    private let clearSearchId = "dvma_clear_search"
    private let rowIdPrefix = "vuln_row_"
    private let screenIdPrefix = "demo_screen_"
    private let actionIdPrefix = "demo_action_"
    private let evidenceIdPrefix = "evidence_"

    // Modules whose vulnerable path launches an EXTERNAL app via
    // UIApplication.open(url) with no scheme allowlist - that unrestricted
    // external launch IS the finding. They take DVMA out of the foreground
    // DURING navigation (before the per-module guard can run), which aborts the
    // running XCUITest method exactly like a crash. So, like the native-crash
    // module, they are EXCLUDED from the walk and proven by their own test
    // (testExternalUrlLaunchIsEvidence), keeping the walk's pass/fail clean.
    private let externalLaunchModuleIds: Set<String> = [
        "mcp_open_url_arbitrary_intent",
        "ai_output_to_intent_url",
    ]

    // Excluded from the walk because exercising it crashes the process; proven
    // separately by testNativeMemoryCrashIsEvidence().
    private let crashingModuleId = "native_code_memory_bugs"

    // Flip to true and populate to walk an explicit, ordered list instead of
    // dynamic discovery. Copy `id`s from automation/vuln_manifest.json.
    private let useExplicitList = false
    private let explicitModuleIds: [String] = [
        // Populate + set useExplicitList=true for a fast targeted subset run.
        // (The crash + external-launch modules are proven by their own tests and
        // are filtered out of the walk automatically regardless of this list.)
    ]

    override func setUpWithError() throws {
        continueAfterFailure = true // resilient walk: keep going past failures
    }

    func testWalkEveryModule() throws {
        let app = DVMAApp.make()
        app.launch()

        // Confirm the intentionally-vulnerable home index booted.
        let banner = DVMAQuery.element(in: app, identifier: disclaimerBannerId)
        XCTAssertTrue(banner.waitForExistence(timeout: 30),
                      "Disclaimer banner not found; home did not render")

        let resolved = resolveModuleIds(in: app)
        XCTAssertFalse(resolved.isEmpty, "No \(rowIdPrefix)* rows discovered")
        // Exclude modules that leave the foreground when exercised (a crash or an
        // external-app launch): they abort the running XCUITest method regardless
        // of handling, so each is proven by its own dedicated test. Walking them
        // here would kill the walk mid-list.
        let excluded = externalLaunchModuleIds.union([crashingModuleId])
        let moduleIds = resolved.filter { !excluded.contains($0) }

        var failures: [String] = []
        var noEvidence: [String] = []
        var opened = 0
        var verified = 0

        for id in moduleIds {
            let rowId = "\(rowIdPrefix)\(id)"
            let screenId = "\(screenIdPrefix)\(id)"
            do {
                // Navigate to the module by id - deep link first (keyboard-free,
                // device-reliable), then scroll-to-row, then search.
                try openModule(id: id, rowId: rowId, screenId: screenId, in: app)

                let screen = DVMAQuery.element(in: app, identifier: screenId)
                guard screen.waitForExistence(timeout: 12) else {
                    throw WalkError.notFound("demo screen \(screenId) not visible")
                }
                opened += 1

                // Exercise stateful controls first so the action fires against a
                // non-default state: modules gate behavior on a Switch (e.g.
                // "rename frida gadget") or a Slider (burst size / replay count).
                // XCUITest's slider.adjust() issues the native increment action
                // rather than a raw drag, so (unlike Appium's pointer drag) it
                // doesn't collapse the sibling demo_action_* nodes.
                exerciseControls(in: app)

                // Trigger the vulnerable path: tap every demo action so a module
                // that only records evidence on a non-first button still fires.
                let tapped = tapAllDemoActions(in: app)

                // Any module reaching here should stay in the foreground - the
                // crash/external-launch modules that leave are excluded above and
                // proven by their own tests. So an unexpected departure is a real
                // failure (record it, don't count as verified) rather than a
                // silently-tolerated pass.
                if app.state != .runningForeground {
                    failures.append("\(id): app unexpectedly left foreground")
                    print("DVMA-VERDICT: [\(id)] FAILURE (tapped \(tapped) action(s), app unexpectedly left foreground)")
                    recoverToHome(app) // relaunch a clean app for the next module
                    continue
                }

                // VERIFY: at least one evidence_* panel must be present - the
                // on-device proof the vulnerable code path ran.
                if evidencePresent(in: app) {
                    verified += 1
                    print("DVMA-VERDICT: [\(id)] VERIFIED (tapped \(tapped) action(s), evidence panel present)")
                } else {
                    noEvidence.append(id)
                    print("DVMA-VERDICT: [\(id)] NO-EVIDENCE (tapped \(tapped) action(s), no evidence_* panel)")
                }

                attachScreenshot(of: app, named: id)

                // Back to the home index for the next module.
                goBack(in: app)
                _ = banner.waitForExistence(timeout: 8)
            } catch {
                failures.append("\(id): \(error)")
                recoverToHome(app) // never rely on a stray state cascading
            }
        }

        print("DVMA walk complete: opened \(opened)/\(moduleIds.count) modules, " +
              "\(verified) verified (evidence panel present), " +
              "\(noEvidence.count) produced NO evidence, \(failures.count) failure(s). " +
              "(native-crash + external-launch modules are proven by their own tests.)")
        if !noEvidence.isEmpty {
            print("DVMA modules with NO on-device evidence panel:")
            noEvidence.forEach { print("  - \($0)") }
        }
        failures.forEach { print("  - \($0)") }
        XCTAssertTrue(failures.isEmpty, "Some modules failed to open/navigate: \(failures)")
    }

    /// Proves the native memory-safety module by its DEFINING behavior: firing
    /// the vulnerable path CRASHES the process (a real Mach-O stack overflow in
    /// `dvma_unsafe_copy`). This lives in its own test - not the walk - because
    /// XCUITest fails whatever test method is running when the app crashes, so
    /// isolating it keeps the walk's pass/fail contract clean while still making
    /// the crash an explicit, asserted outcome (the crash IS the finding).
    ///
    /// Success = the app was foreground on the module screen, we tapped its
    /// action(s), and the app is then NO LONGER foreground. The evidence artifact
    /// is written before the overflow, so it is pulled off-device like any other.
    func testNativeMemoryCrashIsEvidence() throws {
        let app = DVMAApp.make()
        // Relaunch straight into the module (keyboard-free nav, same as the walk).
        app.launchEnvironment["DVMA_OPEN_MODULE"] = crashingModuleId
        app.launch()

        let screenId = "\(screenIdPrefix)\(crashingModuleId)"
        let screen = DVMAQuery.element(in: app, identifier: screenId)
        XCTAssertTrue(screen.waitForExistence(timeout: 15),
                      "\(crashingModuleId) screen did not open")
        XCTAssertEqual(app.state, .runningForeground,
                       "app should be foreground before firing the overflow")

        // Fire the vulnerable path. The tap that triggers the overflow crashes
        // the process; that departure is the asserted evidence below.
        _ = tapAllDemoActions(in: app)

        // Poll for the process to leave the foreground (the crash).
        var departed = false
        for _ in 0..<20 {
            if app.state != .runningForeground { departed = true; break }
            usleep(200_000) // 200ms
        }
        XCTAssertTrue(departed,
                      "\(crashingModuleId) did not crash the app - the native " +
                      "overflow (dvma_unsafe_copy) is the finding and must crash")
        print("DVMA-VERDICT: [\(crashingModuleId)] VERIFIED (app crashed in the " +
              "native overflow - crash IS the evidence)")
    }

    /// Proves the open-URL App-Intent modules by their DEFINING behavior: the
    /// vulnerable path calls `UIApplication.open(url)` with no scheme allowlist,
    /// launching an EXTERNAL app and taking DVMA out of the foreground. That
    /// unrestricted external launch IS the finding. Isolated from the walk for
    /// the same reason as the crash test: the departure aborts whatever XCUITest
    /// method is running. One assertion per module: navigate in, fire the action,
    /// confirm the app left the foreground.
    func testExternalUrlLaunchIsEvidence() throws {
        for id in externalLaunchModuleIds.sorted() {
            let app = DVMAApp.make()
            app.launchEnvironment["DVMA_OPEN_MODULE"] = id
            app.launch()

            let screen = DVMAQuery.element(in: app, identifier: "\(screenIdPrefix)\(id)")
            // The launch can fire so fast the app departs before the screen query
            // resolves; only assert the screen if the app is still foreground.
            if app.state == .runningForeground {
                _ = screen.waitForExistence(timeout: 12)
            }
            if app.state == .runningForeground {
                _ = tapAllDemoActions(in: app)
            }

            var departed = false
            for _ in 0..<25 {
                if app.state != .runningForeground { departed = true; break }
                usleep(200_000)
            }
            XCTAssertTrue(departed,
                          "\(id) did not launch an external app - the unrestricted " +
                          "UIApplication.open(url) is the finding and must background DVMA")
            print("DVMA-VERDICT: [\(id)] VERIFIED (external app launched, DVMA " +
                  "backgrounded - the unrestricted launch IS the evidence)")
            app.terminate()
        }
    }

    // MARK: - Discovery

    /// The module id list, in priority order:
    ///  1. `DVMA_MODULE_IDS` env (when set): an explicit subset to walk. Lets
    ///     the harness target just the modules under test for a fast run. When
    ///     unset, the full app manifest (below) is used.
    ///  2. The app's OWN runtime manifest: a hidden `dvma_module_manifest`
    ///     accessibility node whose label is the comma-separated enabled-module
    ///     ids (VulnerabilityRegistry.enabledFor). This can NEVER drift from what
    ///     is compiled in, so it's the authoritative full-walk source.
    ///  3. An explicit in-test list, if `useExplicitList` is set.
    ///  4. Runtime scroll-discovery of visible `vuln_row_*` (last-resort).
    private func resolveModuleIds(in app: XCUIApplication) -> [String] {
        // 0) Compiled-in explicit subset (most reliable for fast targeted runs;
        //    env injection via xcodebuild is Xcode-version-fragile). Flip
        //    `useExplicitList` to true and fill `explicitModuleIds`.
        if useExplicitList, !explicitModuleIds.isEmpty {
            print("DVMA walk: using \(explicitModuleIds.count) module id(s) from explicit in-test list")
            expandAllCategories(in: app)
            return explicitModuleIds
        }
        // 1) Explicit subset via env (fast targeted runs) - takes priority so a
        //    harness invocation can walk only the modules it cares about. The
        //    harness passes it as a `TEST_RUNNER_`-prefixed build arg; depending
        //    on the Xcode version the runner env keeps or strips that prefix, so
        //    accept BOTH keys.
        let env = ProcessInfo.processInfo.environment
        if let raw = env["DVMA_MODULE_IDS"] ?? env["TEST_RUNNER_DVMA_MODULE_IDS"],
           !raw.isEmpty {
            let ids = raw.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty }
            if !ids.isEmpty {
                print("DVMA walk: using \(ids.count) module id(s) from DVMA_MODULE_IDS env")
                expandAllCategories(in: app)
                return ids
            }
        }
        // 2) App's own runtime manifest (authoritative full walk).
        if let ids = moduleIdsFromApp(app), !ids.isEmpty {
            print("DVMA walk: using \(ids.count) module id(s) from the app's runtime manifest")
            expandAllCategories(in: app) // search results still need rows built
            return ids
        }
        return discoverModuleIds(in: app)
    }

    /// Read the comma-separated enabled-module ids from the app's hidden
    /// `dvma_module_manifest` node's label. Returns nil if the node/label is
    /// absent (older build), so callers fall back to other sources.
    private func moduleIdsFromApp(_ app: XCUIApplication) -> [String]? {
        let node = DVMAQuery.element(in: app, identifier: "dvma_module_manifest")
        guard node.waitForExistence(timeout: 10) else { return nil }
        // The CSV rides on the element's label (accessibilityLabel).
        let csv = node.label
        let ids = csv.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
        return ids.isEmpty ? nil : ids
    }

    /// Expand all categories, then collect every `vuln_row_*` id (scrolling to
    /// gather the full list). Returns bare module ids in first-seen order.
    private func discoverModuleIds(in app: XCUIApplication) -> [String] {
        expandAllCategories(in: app)

        var seen: [String] = []
        var seenSet = Set<String>()
        var stableScreens = 0
        var iterations = 0

        func harvest() {
            let predicate = NSPredicate(format: "identifier BEGINSWITH %@", rowIdPrefix)
            let queries = [
                app.descendants(matching: .any).matching(predicate),
                app.otherElements.matching(predicate),
            ]
            for q in queries {
                // Snapshot to an array so a mutating tree can't invalidate an
                // index mid-loop (that caused "No matches found at index N").
                for el in q.allElementsBoundByIndex {
                    guard el.exists else { continue }
                    let ident = el.identifier
                    guard ident.hasPrefix(rowIdPrefix) else { continue }
                    let bare = String(ident.dropFirst(rowIdPrefix.count))
                    if seenSet.insert(bare).inserted { seen.append(bare) }
                }
            }
        }

        while stableScreens < 2 && iterations < maxScrolls {
            iterations += 1
            let before = seen.count
            harvest()
            stableScreens = (seen.count == before) ? stableScreens + 1 : 0
            app.swipeUp()
        }
        var guardCount = 0
        while guardCount < maxScrolls { app.swipeDown(); guardCount += 1 }
        return seen
    }

    /// Ensure every category section is expanded so all `vuln_row_*` are built.
    /// The toggle expands-all when nothing is open and collapses-all otherwise,
    /// so tap, check for rows, and tap again if the first tap collapsed.
    private func expandAllCategories(in app: XCUIApplication) {
        func rowCount() -> Int {
            app.descendants(matching: .any)
                .matching(NSPredicate(format: "identifier BEGINSWITH %@", rowIdPrefix))
                .count
        }
        let toggle = DVMAQuery.element(in: app, identifier: expandAllId)
        guard toggle.waitForExistence(timeout: 8) else { return }
        if rowCount() > 0 { return }
        DVMAQuery.tap(in: app, identifier: expandAllId)
        _ = firstRow(in: app).waitForExistence(timeout: 4)
        if rowCount() == 0 {
            DVMAQuery.tap(in: app, identifier: expandAllId)
            _ = firstRow(in: app).waitForExistence(timeout: 4)
        }
    }

    private func firstRow(in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH %@", rowIdPrefix))
            .firstMatch
    }

    // MARK: - Navigation to a module by id

    /// Open the module [id] whose demo screen is [screenId] by RELAUNCHING the
    /// app with `DVMA_OPEN_MODULE=<id>` in its launch environment. The app's root
    /// DeepLinkNavigator reads that on startup and opens the module directly
    /// through the SAME ModuleRouter.screenFor map the home list uses.
    ///
    /// Why this (not typing the id into search): XCUITest cannot reliably set a
    /// Flutter canvas TextField's value on a physical device (no `element.value =`
    /// exists, and `typeText` needs a first-responder the canvas never grants),
    /// so search navigation silently no-ops on device. Relaunch-with-env is
    /// keyboard-free, in-process (no Safari/URL round-trip), deterministic, and
    /// behaves identically on Simulator and device - the iOS-native equivalent of
    /// the Android walk's `edit.text = id` search navigation. Scroll-to-row and
    /// search remain as fallbacks.
    private func openModule(id: String, rowId: String, screenId: String, in app: XCUIApplication) throws {
        // 1) Relaunch with the module id in the launch environment (primary).
        app.terminate()
        app.launchEnvironment["DVMA_OPEN_MODULE"] = id
        app.launch()
        let screen = DVMAQuery.element(in: app, identifier: screenId)
        if screen.waitForExistence(timeout: 15) { return }

        // Clear the env so a later home-based fallback doesn't re-open this
        // module on the next relaunch.
        app.launchEnvironment["DVMA_OPEN_MODULE"] = ""

        // 2) Scroll-to-row (device fallback): expand categories, scroll to the
        //    row, tap it - no text entry needed.
        recoverToHome(app)
        expandAllCategories(in: app)
        if scrollToRowAndTap(rowId: rowId, in: app) { return }

        // 3) Search (last resort, e.g. Simulator where text entry lands).
        try openModuleBySearch(id: id, rowId: rowId, in: app)
    }

    // MARK: - Search-based navigation (deterministic, minimal scrolling)

    private func openModuleBySearch(id: String, rowId: String, in app: XCUIApplication) throws {
        // On a physical device, XCUITest cannot reliably land text into Flutter's
        // canvas-drawn search field (it never takes first-responder focus, so
        // typeText no-ops and the paste menu is flaky). So navigate the way that
        // ALWAYS works on device: categories are already expanded, so scroll the
        // target row into view and tap it. Search-based navigation is kept as a
        // fallback for environments where the field DOES accept input (and where
        // a very long list makes scrolling slow).
        if scrollToRowAndTap(rowId: rowId, in: app) { return }

        // Fallback: search-based navigation.
        let field = DVMAQuery.element(in: app, identifier: searchFieldId)
        if !field.waitForExistence(timeout: 6) { recoverToHome(app) }
        guard DVMAQuery.element(in: app, identifier: searchFieldId).waitForExistence(timeout: 6) else {
            // No search field either - one more scroll attempt after a fresh home.
            recoverToHome(app)
            expandAllCategories(in: app)
            if scrollToRowAndTap(rowId: rowId, in: app) { return }
            throw WalkError.notFound("row \(rowId) not reachable by scroll or search")
        }

        // Try up to twice: search filtering + row rendering can occasionally lose
        // a keystroke or race the list rebuild; a clean re-enter fixes it.
        for attempt in 1...2 {
            clearSearch(in: app)
            guard DVMAText.enter(id, into: searchFieldId, in: app) else {
                throw WalkError.notFound("could not type '\(id)' into \(searchFieldId)")
            }
            let row = DVMAQuery.element(in: app, identifier: rowId)
            if row.waitForExistence(timeout: 8) {
                DVMAQuery.tap(in: app, identifier: rowId)
                return
            }
            if attempt == 1 { recoverToHome(app) } // reset and retry once
        }
        // Last resort before giving up: clear search and scroll to it.
        clearSearch(in: app)
        if scrollToRowAndTap(rowId: rowId, in: app) { return }
        throw WalkError.notFound("row \(rowId) not found after searching '\(id)' (x2)")
    }

    /// Scroll the (already-expanded) home list until [rowId] is on screen, then
    /// tap it. Device-reliable navigation that needs no text entry: it sweeps
    /// down from the top, harvesting toward the row, and taps as soon as it
    /// exists and is hittable. Returns false if the row never surfaces.
    private func scrollToRowAndTap(rowId: String, in app: XCUIApplication) -> Bool {
        // Make sure we're at a home that has rows built.
        if firstRow(in: app).waitForExistence(timeout: 4) == false {
            expandAllCategories(in: app)
        }
        // Scroll to the top first so sweeps are deterministic.
        var top = 0
        while top < maxScrolls {
            let rowPred = NSPredicate(format: "identifier BEGINSWITH %@", rowIdPrefix)
            let before = app.descendants(matching: .any).matching(rowPred).count
            app.swipeDown()
            let after = app.descendants(matching: .any).matching(rowPred).count
            if before == after { break } // reached the top (list stopped moving)
            top += 1
        }
        // Now sweep down looking for the target row.
        var scrolls = 0
        while scrolls < maxScrolls {
            let row = DVMAQuery.element(in: app, identifier: rowId)
            if row.exists {
                if row.isHittable {
                    row.tap()
                } else {
                    row.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
                }
                return true
            }
            edgeSafeSwipeUp(app)
            scrolls += 1
        }
        // One more check after the final swipe.
        let row = DVMAQuery.element(in: app, identifier: rowId)
        if row.exists {
            row.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
            return true
        }
        return false
    }

    /// Tap the clear (X) affordance if present so the next query starts clean.
    /// The X only renders while the field is non-empty, so give it a brief moment
    /// to appear (the list rebuild after a back-navigation can lag), then tap it.
    /// This is the app's OWN clear control - the deterministic way to empty the
    /// shared search field between modules (never the edit-menu Select-All dance).
    private func clearSearch(in app: XCUIApplication) {
        let clear = DVMAQuery.element(in: app, identifier: clearSearchId)
        if clear.waitForExistence(timeout: 2) {
            DVMAQuery.tap(in: app, identifier: clearSearchId)
        }
    }

    /// Return to a clean, searchable home. Terminate + relaunch is the iOS
    /// analogue of Android's launch-intent recovery (no gesture reliance).
    private func recoverToHome(_ app: XCUIApplication) {
        // Clear any per-module launch env so the relaunch lands on HOME, not back
        // on a module screen (the walk sets DVMA_OPEN_MODULE for navigation).
        app.launchEnvironment["DVMA_OPEN_MODULE"] = ""
        app.terminate()
        app.launch()
        _ = DVMAQuery.element(in: app, identifier: searchFieldId).waitForExistence(timeout: 20)
    }

    // MARK: - Actions & evidence

    /// Flip every `Switch` and nudge every `Slider` on the current screen so a
    /// module that gates its behavior on a control state is exercised in a
    /// NON-default position before the action-taps fire the vulnerable path.
    /// These controls are Flutter-native so they surface as real `switches` /
    /// `sliders` element types - no custom identifier needed. Best-effort and
    /// resilient: failures here never abort the walk.
    private func exerciseControls(in app: XCUIApplication) {
        // Toggle each switch once (default -> flipped).
        for sw in app.switches.allElementsBoundByIndex {
            guard sw.exists, sw.isHittable else { continue }
            sw.tap()
        }
        // Nudge each slider toward the high end so range-driven modules (burst
        // size, replay count) run with a larger value. adjust(toNormalized
        // SliderPosition:) is the XCUITest-native way to move a slider without a
        // fragile drag that a scroll view might steal.
        for sl in app.sliders.allElementsBoundByIndex {
            guard sl.exists, sl.isHittable else { continue }
            sl.adjust(toNormalizedSliderPosition: 0.85)
        }
    }

    /// Tap every `demo_action_*` button on the current screen. Buttons have
    /// unique ids, so we snapshot the id set first (scrolling to gather any below
    /// the fold), then tap each by a FRESH per-id query. Never index into a live
    /// `matching` result across taps - the tree mutates as evidence panels appear
    /// (that caused "No matches found for Element at index N"). Returns the count.
    ///
    /// DEVICE RESILIENCE: matching uses `.any` (Flutter surfaces action nodes as
    /// varying element types - `.otherElements` alone misses buttons, which made
    /// the walk scroll a screen without ever tapping). The fix for the "stuck,
    /// scrolls but never taps/verifies" wedge is BOUNDING, not narrowing: gather
    /// is capped to `gatherScrolls` sweeps and each tap does at most 3 re-find
    /// swipes - never the old 40-deep `.exists` re-probe loop that spun forever.
    private func tapAllDemoActions(in app: XCUIApplication) -> Int {
        let predicate = NSPredicate(format: "identifier BEGINSWITH %@", actionIdPrefix)
        // `.any` matches every element type (correct); bounds keep it fast.
        func actionQuery() -> XCUIElementQuery {
            app.descendants(matching: .any).matching(predicate)
        }

        // Wait for the screen to settle: at least one demo action should exist.
        // (Screens open with an animation, and slider-first screens can report
        // zero actions on the very first snapshot - that produced the earlier
        // "tapped 0 action(s)" false negatives.)
        _ = actionQuery().firstMatch.waitForExistence(timeout: 6)

        // 1) Gather the full set of action ids, scrolling to reveal any below.
        //    Bounded to `gatherScrolls` sweeps so a screen that keeps mutating
        //    its tree can't spin here indefinitely.
        var actionIds: [String] = []
        var seen = Set<String>()
        var scrolls = 0
        while scrolls < gatherScrolls {
            let q = actionQuery()
            let countBefore = seen.count
            for el in q.allElementsBoundByIndex {
                let ident = el.identifier
                if ident.hasPrefix(actionIdPrefix), seen.insert(ident).inserted {
                    actionIds.append(ident)
                }
            }
            let before = q.count
            edgeSafeSwipeUp(app)
            let after = actionQuery().count
            // Stop once a scroll reveals no new ids and the visible count is stable.
            if seen.count == countBefore && before == after { break }
            scrolls += 1
        }

        // 2) Tap each by a fresh, cross-type unique-identifier query (stable
        //    across mutations). Each tap is bounded: at most 3 re-find swipes,
        //    never the 40-deep `.exists` re-probe loop that wedged the walk.
        var tapped = 0
        for ident in actionIds {
            // If a PRIOR tap crashed the app (some modules prove the finding by
            // crashing - e.g. the native stack overflow), stop tapping: the
            // caller checks app.state and records the crash as evidence. Querying
            // a dead app is what aborted the earlier run.
            if app.state != .runningForeground { break }
            let el = DVMAQuery.element(in: app, identifier: ident)
            var g = 0
            while g < 3 && !el.exists { app.swipeUp(); g += 1 }
            guard el.exists else { continue }
            if el.isHittable {
                el.tap()
            } else {
                el.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
            }
            tapped += 1
        }
        return tapped
    }

    /// True if any `evidence_*` panel is present, scrolling to reveal it.
    private func evidencePresent(in app: XCUIApplication) -> Bool {
        let predicate = NSPredicate(format: "identifier BEGINSWITH %@", evidenceIdPrefix)
        // `.any` so the panel matches regardless of element type (it was scoped
        // too narrowly before and evidence was missed). Bounded scroll sweeps
        // keep it fast - bounding, not narrowing, is what fixes the wedge.
        let ev = app.descendants(matching: .any).matching(predicate).firstMatch
        if ev.waitForExistence(timeout: 6) { return true }
        var guardCount = 0
        while guardCount < gatherScrolls {
            guardCount += 1
            edgeSafeSwipeUp(app)
            if app.descendants(matching: .any).matching(predicate).firstMatch.exists { return true }
        }
        return app.descendants(matching: .any).matching(predicate).firstMatch.exists
    }

    /// Scroll the content up by one page using a swipe kept on the LEFT edge and
    /// inside safe vertical insets. A full-width `Slider` (common on these demo
    /// screens) sits center-stage and would capture a center swipe as a drag
    /// (that left slider-first screens' action buttons unreachable). Swiping the
    /// left gutter delivers the gesture to the scroll view instead.
    private func edgeSafeSwipeUp(_ app: XCUIApplication) {
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.06, dy: 0.72))
        let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.06, dy: 0.28))
        start.press(forDuration: 0.05, thenDragTo: end)
    }

    // MARK: - Navigation helpers

    /// Return to the home index after a module. Pops via the nav-bar back button
    /// (or an edge-swipe fallback), repeating until the home disclaimer banner is
    /// visible or a bound is hit. Robust to deep-link pushes that may have added
    /// more than one route: keeps popping rather than assuming a single level.
    private func goBack(in app: XCUIApplication) {
        let banner = DVMAQuery.element(in: app, identifier: disclaimerBannerId)
        var hops = 0
        while hops < 6 {
            if banner.exists { return }
            let backButton = app.navigationBars.buttons.element(boundBy: 0)
            if backButton.exists && backButton.isHittable {
                backButton.tap()
            } else {
                // Interactive-pop edge swipe (left edge → right).
                let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.01, dy: 0.5))
                let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5))
                start.press(forDuration: 0.05, thenDragTo: end)
            }
            _ = banner.waitForExistence(timeout: 3)
            hops += 1
        }
    }

    /// Attach a screenshot of the current screen to the test report.
    private func attachScreenshot(of app: XCUIApplication, named name: String) {
        let screenshot = app.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "\(name).png"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private let maxScrolls = 40
    // Tighter bound for per-screen action/evidence gathering: a module screen is
    // short, so a handful of sweeps finds everything; capping low here prevents a
    // churning tree from spinning the walk (the insecure_backups wedge).
    private let gatherScrolls = 6
    private enum WalkError: Error { case notFound(String) }
}
