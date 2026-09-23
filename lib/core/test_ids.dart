import 'package:flutter/widgets.dart';

/// Stable automation identifiers for dynamic analysis / UI automation.
///
/// DVMA is a *target* app for security tooling, so it must be reliably
/// drivable by Appium (both the `appium-flutter-driver`, which finds elements
/// by [ValueKey], and native UiAutomator2 / XCUITest, which find elements by an
/// accessibility identifier). [testId] wires up *both* at once:
///
///  * a [Key] (`ValueKey<String>`) so `find.byValueKey('<id>')` works with the
///    Flutter driver, and
///  * a [Semantics] node whose `identifier` surfaces as `resource-id` on
///    Android and `accessibilityIdentifier` on iOS, so native Appium locators
///    (`~<id>` / resource-id) work too.
///
/// IDs are derived from the registry `vulnId` so a script can walk every
/// module deterministically. Keep these stable: automation suites depend on
/// them, and CI dynamic-analysis runs will break if they silently change.
class DvmaTestIds {
  DvmaTestIds._();

  // --- Home / index ----------------------------------------------------------
  static const String searchField = 'dvma_search_field';
  static const String flavorBadge = 'dvma_flavor_badge';
  static const String disclaimerBanner = 'dvma_disclaimer_banner';

  /// The app-bar toggle that expands/collapses every category section at once.
  /// Automation taps this to reveal all `vuln_row_*` rows (category sections are
  /// collapsed by default, so rows aren't built/visible until expanded).
  static const String expandAll = 'dvma_expand_all';

  /// The "clear" (X) affordance inside the search field, shown only while the
  /// query is non-empty. Automation taps this to reset search between modules.
  static const String clearSearch = 'dvma_clear_search';

  /// A hidden, zero-size element whose *label* carries the comma-separated list
  /// of enabled module ids for the active flavor/platform, the app's own
  /// runtime source of truth (VulnerabilityRegistry.enabledFor). Automation
  /// reads this instead of a repo-side manifest file, so the walk can never
  /// drift from what's actually compiled in. See [moduleManifest] usage in
  /// lib/core/home_screen.dart.
  static const String moduleManifest = 'dvma_module_manifest';

  /// A home-screen filter chip (difficulty/platform), e.g. `filter_easy`.
  static String filterChip(String key) => 'filter_${_slug(key)}';

  /// The tappable row for a given vulnerability on the home list.
  static String vulnRow(String vulnId) => 'vuln_row_$vulnId';

  /// The category header for a given category id.
  static String categoryHeader(String categoryId) => 'category_$categoryId';

  // --- Demo screen (shared scaffold) -----------------------------------------
  /// A demo screen's root, tagged with its vuln id.
  static String demoScreen(String vulnId) => 'demo_screen_$vulnId';

  /// The primary action button(s) that trigger the vulnerable code path.
  /// The id is derived from the button [label] so it stays stable and readable.
  static String demoAction(String label) => 'demo_action_${_slug(label)}';

  /// A labeled evidence panel; [label] is slugified.
  static String evidence(String label) => 'evidence_${_slug(label)}';

  static String _slug(String s) => s
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
      .replaceAll(RegExp(r'^_|_$'), '');
}

/// Wraps [child] with both a [ValueKey] and a [Semantics] identifier so it is
/// discoverable by the Flutter driver *and* native accessibility locators.
///
/// Use this for **non-tappable** anchors: screen roots, containers, labels,
/// text fields, evidence panels. It intentionally does not merge the subtree,
/// so descendants (e.g. the `demo_action_*` buttons and `evidence_*` panels
/// inside a `demo_screen_*` root) remain independently discoverable.
///
/// For a **tappable** element (a row/chip/button whose whole hit area should be
/// one addressable node), use [testTapId] instead, see the note there for why
/// tappables need special handling to keep their id on iOS.
Widget testId(String id, Widget child) {
  return Semantics(
    identifier: id,
    // Keep the child in the tree/semantics; we only add an identifier.
    container: false,
    explicitChildNodes: true,
    child: KeyedSubtree(key: ValueKey<String>(id), child: child),
  );
}

/// Like [testId], but for a **tappable** [child] (an [InkWell]/[GestureDetector]
/// /button such as a `vuln_row_*`, a filter chip, or a `demo_action_*`).
///
/// ## Why tappables need this
/// Native accessibility bridges (iOS UIAccessibility / XCUITest, Android
/// UiAutomator) only see *merged* semantics nodes. A tappable contributes its
/// own node with a tap action and a label built from its children. If our
/// identifier merely *merges* alongside it, iOS keeps the tappable's identity
/// and silently drops our `identifier`, so lookups by `accessibilityIdentifier`
/// return nothing (Android is more forgiving, which is exactly why the module
/// walk found rows on Android but zero on iOS).
///
/// The fix is to force a **single owned node**: [MergeSemantics] folds the
/// child's tap action + label INTO the node that carries our identifier, and
/// `container: true` makes that node its own accessibility element. The result
/// is one addressable element that is both tappable *and* carries `id` on both
/// platforms.
Widget testTapId(String id, Widget child) {
  return MergeSemantics(
    child: Semantics(
      identifier: id,
      container: true,
      child: KeyedSubtree(key: ValueKey<String>(id), child: child),
    ),
  );
}
