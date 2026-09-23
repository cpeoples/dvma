import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app_config.dart';
import '../vulnerability_registry.dart';
import 'module_router.dart';
import 'test_ids.dart';
import 'theme/dvma_colors.dart';
import 'theme/dvma_theme.dart';
import 'theme/theme_controller.dart';
import 'widgets.dart';

/// DVMA home: a categorized, searchable index of every enabled vulnerability.
///
/// Reads the active [AppConfig] from the widget tree and shows only the
/// vulnerabilities enabled by the current flavor. The layout reads like a
/// technical instrument: dense rows, monospace ids, severity/difficulty badges.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  String _query = '';
  DvmaDifficulty? _difficulty; // null = all
  final _searchFocus = FocusNode();
  final _searchController = TextEditingController();

  /// After the user stops typing for [_searchIdle], the keyboard is dismissed
  /// so it stops covering the results (the query and results are kept).
  static const Duration _searchIdle = Duration(seconds: 5);
  Timer? _searchIdleTimer;

  /// Category ids the user has expanded (categories are collapsed by default).
  final Set<String> _openCategories = {};

  /// Tracks whether a filter was active on the previous change, so entering a
  /// filtered state can auto-expand matching categories exactly once (the user
  /// can then collapse them again, including via "collapse all").
  bool _wasFiltering = false;

  /// Recomputes the filtering state after a search/difficulty change and, on
  /// the transition into filtering, auto-expands every matching category; on
  /// the transition back out, restores the default collapsed state.
  void _syncExpansionToFilter() {
    final q = _query.trim().toLowerCase();
    final filtering = q.isNotEmpty || _difficulty != null;
    if (filtering && !_wasFiltering) {
      _openCategories
        ..clear()
        ..addAll(VulnerabilityRegistry.categories.map((c) => c.id));
    } else if (!filtering && _wasFiltering) {
      _openCategories.clear();
    }
    _wasFiltering = filtering;
  }

  /// (Re)starts the idle timer that dismisses the keyboard once the user pauses
  /// typing. Cancelled when the field is cleared so it never fires on an empty
  /// query.
  void _restartSearchIdleTimer() {
    _searchIdleTimer?.cancel();
    if (_query.isEmpty) return;
    _searchIdleTimer = Timer(_searchIdle, () {
      if (mounted) _searchFocus.unfocus();
    });
  }

  @override
  void dispose() {
    _searchIdleTimer?.cancel();
    _searchFocus.dispose();
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final config = context.read<AppConfig>();
    final enabled = VulnerabilityRegistry.enabledFor(config);
    final q = _query.trim().toLowerCase();
    final filtered = enabled.where((v) {
      if (_difficulty != null && v.difficulty != _difficulty) return false;
      if (q.isNotEmpty &&
          !v.title.toLowerCase().contains(q) &&
          !v.id.toLowerCase().contains(q) &&
          !v.summary.toLowerCase().contains(q)) {
        return false;
      }
      return true;
    }).toList();

    // When a search or difficulty filter is active, matching categories are
    // auto-expanded (see [_syncExpansionToFilter]); the user can still collapse
    // them, so expansion is driven purely by [_openCategories].
    final categories = VulnerabilityRegistry.categories
        .where((c) => filtered.any((v) => v.category == c.id))
        .toList();

    // "Collapse/expand all" acts on the currently visible categories. If any is
    // open, the button collapses all; otherwise it expands all.
    final anyOpen = categories.any((c) => _openCategories.contains(c.id));
    void toggleAll() => setState(() {
      FocusManager.instance.primaryFocus?.unfocus();
      if (anyOpen) {
        _openCategories.clear();
      } else {
        _openCategories.addAll(categories.map((c) => c.id));
      }
    });

    return Scaffold(
      appBar: AppBar(
        titleSpacing: DvmaSpacing.md,
        // Amber radial glow behind the leading icon + title, turns the mark's
        // "warning" energy into an intentional header backdrop. Anchored to the
        // top-left so it sits behind the icon/title, fading out before the
        // actions. Purely decorative; ignores pointer events.
        flexibleSpace: IgnorePointer(
          child: Container(
            decoration: const BoxDecoration(
              gradient: RadialGradient(
                center: Alignment(-0.85, -0.1),
                radius: 0.9,
                colors: [
                  Color(0x33E8A33D), // amber @ ~20%
                  Color(0x0FE8A33D), // amber @ ~6%
                  Color(0x00E8A33D), // transparent
                ],
                stops: [0.0, 0.5, 1.0],
              ),
            ),
          ),
        ),
        title: Row(
          mainAxisSize: MainAxisSize.min,
          // Bottom-align so the icon's baseline tracks the text block's bottom,
          // then nudge the icon up so the yield-sign's lower edge lines up with
          // the bottom of the "Damn Vulnerable Mobile App" subtitle (the mark
          // has empty phone-body space above the triangle, so centered alignment
          // sits it too low).
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            // App icon before the title, the tightly-cropped mark (phone +
            // hazard triangle, no transparent glow padding) so it fills its box
            // and reads large, with the SAME dark phone styling as the original
            // launcher icon (#0F1512 body / #4A5A52 outline). The AppBar
            // flexibleSpace draws the amber glow backdrop, which gives the dark
            // mark enough contrast on the dark bar, so both themes use it.
            Transform.translate(
              offset: const Offset(0, -2),
              child: Image.asset(
                'assets/branding/dvma_header_mark.png',
                width: 42,
                height: 42,
                filterQuality: FilterQuality.medium,
              ),
            ),
            const SizedBox(width: DvmaSpacing.sm),
            Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('DVMA'),
                Text(
                  'Damn Vulnerable Mobile App',
                  style: TextStyle(
                    fontSize: 11,
                    height: 1.1,
                    fontWeight: FontWeight.w400,
                    color: DvmaColors.of(context).textSecondary,
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Toggle theme',
            icon: Icon(context.watch<ThemeController>().icon),
            onPressed: () => context.read<ThemeController>().cycle(),
          ),
          Padding(
            padding: const EdgeInsets.only(right: DvmaSpacing.lg),
            child: Center(
              child: testId(
                DvmaTestIds.flavorBadge,
                DvmaBadge(
                  label: config.flavor.toUpperCase(),
                  color: DvmaColors.accent,
                ),
              ),
            ),
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(56),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              DvmaSpacing.lg,
              0,
              DvmaSpacing.lg,
              DvmaSpacing.md,
            ),
            child: testId(
              DvmaTestIds.searchField,
              TextField(
                controller: _searchController,
                focusNode: _searchFocus,
                onChanged: (v) => setState(() {
                  _query = v;
                  _syncExpansionToFilter();
                  _restartSearchIdleTimer();
                }),
                decoration: InputDecoration(
                  hintText: 'search vulnerabilities...',
                  prefixIcon: const Icon(Icons.search, size: 18),
                  isDense: true,
                  suffixIcon: _query.isEmpty
                      ? null
                      : testTapId(
                          DvmaTestIds.clearSearch,
                          IconButton(
                            tooltip: 'Clear search',
                            icon: const Icon(Icons.close, size: 18),
                            onPressed: () => setState(() {
                              _searchController.clear();
                              _query = '';
                              _searchIdleTimer?.cancel();
                              _syncExpansionToFilter();
                            }),
                          ),
                        ),
                ),
              ),
            ),
          ),
        ),
      ),
      body: GestureDetector(
        // Tapping empty space (list background, gaps) dismisses the keyboard
        // and drops search focus. Translucent so child rows/chips/buttons still
        // receive their own taps.
        behavior: HitTestBehavior.translucent,
        onTap: () => FocusManager.instance.primaryFocus?.unfocus(),
        child: Column(
          children: [
            // Hidden accessibility node whose label carries the comma-separated
            // enabled module ids (the app's own runtime source of truth).
            // Automation reads this to walk every compiled-in module without a
            // repo-side manifest that could go stale. It must have a NON-ZERO
            // frame, XCUITest treats 0x0 elements as non-existent, so we give
            // it a 1x1 fully-transparent box (visually imperceptible).
            Semantics(
              identifier: DvmaTestIds.moduleManifest,
              label: enabled.map((v) => v.id).join(','),
              container: true,
              child: const SizedBox(width: 1, height: 1),
            ),
            _DisclaimerBanner(count: enabled.length),
            Row(
              children: [
                Expanded(
                  child: _FilterBar(
                    difficulty: _difficulty,
                    onDifficulty: (d) => setState(() {
                      FocusManager.instance.primaryFocus?.unfocus();
                      _difficulty = d;
                      _syncExpansionToFilter();
                    }),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.only(right: DvmaSpacing.sm),
                  child: testTapId(
                    DvmaTestIds.expandAll,
                    IconButton(
                      tooltip: anyOpen ? 'Collapse all' : 'Expand all',
                      icon: Icon(
                        anyOpen
                            ? Icons.unfold_less_rounded
                            : Icons.unfold_more_rounded,
                      ),
                      onPressed: toggleAll,
                    ),
                  ),
                ),
              ],
            ),
            Expanded(
              child: filtered.isEmpty
                  ? const _EmptyResults()
                  : ListView.builder(
                      padding: const EdgeInsets.only(bottom: DvmaSpacing.xl),
                      itemCount: categories.length,
                      itemBuilder: (context, i) {
                        final cat = categories[i];
                        final vulns = filtered
                            .where((v) => v.category == cat.id)
                            .toList();
                        return _CategorySection(
                          category: cat,
                          vulns: vulns,
                          expanded: _openCategories.contains(cat.id),
                          onToggle: () => setState(() {
                            // Tapping a category also drops search focus /
                            // keyboard (the InkWell consumes the tap, so the
                            // body GestureDetector never sees it).
                            FocusManager.instance.primaryFocus?.unfocus();
                            if (!_openCategories.remove(cat.id)) {
                              _openCategories.add(cat.id);
                            }
                          }),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Horizontal difficulty filter-chip row. The modern single-catalog navigation
/// pattern: narrow the list in place rather than hiding destinations behind a
/// drawer/tabs. (Platform is handled by the build's hard filter, so no
/// Android/iOS chip is needed.)
class _FilterBar extends StatelessWidget {
  const _FilterBar({required this.difficulty, required this.onDifficulty});

  final DvmaDifficulty? difficulty;
  final ValueChanged<DvmaDifficulty?> onDifficulty;

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return SizedBox(
      height: 44,
      child: ListView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(
          horizontal: DvmaSpacing.lg,
          vertical: DvmaSpacing.sm,
        ),
        children: [
          _FilterChip(
            label: 'ALL',
            selected: difficulty == null,
            color: c.textSecondary,
            onTap: () => onDifficulty(null),
          ),
          for (final d in DvmaDifficulty.values)
            _FilterChip(
              label: d.label,
              selected: difficulty == d,
              color: d.color,
              onTap: () => onDifficulty(difficulty == d ? null : d),
            ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.label,
    required this.selected,
    required this.color,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final Color color;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return testTapId(
      DvmaTestIds.filterChip(label),
      Padding(
        padding: const EdgeInsets.only(right: DvmaSpacing.sm),
        child: InkWell(
          borderRadius: DvmaRadii.chipRadius,
          onTap: onTap,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: selected
                  ? color.withValues(alpha: 0.16)
                  : Colors.transparent,
              border: Border.all(
                color: selected ? color.withValues(alpha: 0.7) : c.border,
              ),
              borderRadius: DvmaRadii.chipRadius,
            ),
            child: Text(
              label,
              style: DvmaTheme.mono(
                fontSize: 11,
                fontWeight: FontWeight.w700,
                color: selected ? color : c.textSecondary,
                letterSpacing: 0.5,
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _EmptyResults extends StatelessWidget {
  const _EmptyResults();
  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.filter_alt_off_outlined, size: 32, color: c.textFaint),
          const SizedBox(height: DvmaSpacing.sm),
          Text(
            'No modules match the current filters.',
            style: DvmaTheme.mono(fontSize: 12, color: c.textSecondary),
          ),
        ],
      ),
    );
  }
}

class _DisclaimerBanner extends StatelessWidget {
  const _DisclaimerBanner({required this.count});
  final int count;

  @override
  Widget build(BuildContext context) {
    return testId(
      DvmaTestIds.disclaimerBanner,
      Container(
        width: double.infinity,
        color: DvmaColors.severityCritical.withValues(alpha: 0.10),
        padding: const EdgeInsets.symmetric(
          horizontal: DvmaSpacing.lg,
          vertical: DvmaSpacing.sm,
        ),
        child: Row(
          children: [
            const Icon(
              Icons.warning_amber_rounded,
              size: 16,
              color: DvmaColors.severityCritical,
            ),
            const SizedBox(width: DvmaSpacing.sm),
            Expanded(
              child: Text(
                'Intentionally vulnerable. Authorized training use only. '
                '$count vulnerabilities enabled.',
                style: DvmaTheme.mono(
                  fontSize: 11,
                  color: DvmaColors.of(context).textSecondary,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CategorySection extends StatelessWidget {
  const _CategorySection({
    required this.category,
    required this.vulns,
    required this.expanded,
    required this.onToggle,
  });
  final VulnerabilityCategory category;
  final List<VulnerabilityEntry> vulns;

  /// Whether this section is expanded. Categories are collapsed by default and
  /// auto-expanded while a filter is active (the parent seeds this state).
  final bool expanded;

  /// Toggles [expanded]; owned by the parent so a "collapse/expand all" control
  /// can drive every section.
  final VoidCallback onToggle;

  /// Per-difficulty counts for this category's (filtered) modules.
  ({int easy, int medium, int hard}) _difficultyCounts() {
    int e = 0, m = 0, h = 0;
    for (final v in vulns) {
      switch (v.difficulty) {
        case DvmaDifficulty.easy:
          e++;
        case DvmaDifficulty.medium:
          m++;
        case DvmaDifficulty.hard:
          h++;
      }
    }
    return (easy: e, medium: m, hard: h);
  }

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        testId(
          DvmaTestIds.categoryHeader(category.id),
          Padding(
            // Margin lives outside the InkWell so the ink splash never paints
            // into the gap around the header (the "grey box" flicker).
            padding: const EdgeInsets.fromLTRB(
              DvmaSpacing.lg,
              DvmaSpacing.xl,
              DvmaSpacing.lg,
              0,
            ),
            child: Material(
              color: c.surfaceHigh,
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(DvmaRadii.sm),
                topRight: Radius.circular(DvmaRadii.sm),
              ),
              child: InkWell(
                // Tapping toggles the section; disabled while a filter forces
                // it open (the caret then just reflects the forced state).
                onTap: onToggle,
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(DvmaRadii.sm),
                  topRight: Radius.circular(DvmaRadii.sm),
                ),
                child: Container(
                  padding: const EdgeInsets.fromLTRB(
                    DvmaSpacing.md,
                    DvmaSpacing.sm,
                    DvmaSpacing.md,
                    DvmaSpacing.sm,
                  ),
                  decoration: const BoxDecoration(
                    border: Border(
                      left: BorderSide(color: DvmaColors.accent, width: 3),
                    ),
                    borderRadius: BorderRadius.only(
                      topLeft: Radius.circular(DvmaRadii.sm),
                      topRight: Radius.circular(DvmaRadii.sm),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            expanded
                                ? Icons.keyboard_arrow_down
                                : Icons.keyboard_arrow_right,
                            size: 18,
                            color: c.textSecondary,
                          ),
                          const SizedBox(width: DvmaSpacing.xs),
                          Expanded(
                            child: Text(
                              category.title.toUpperCase(),
                              style: DvmaTheme.mono(
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                color: c.textPrimary,
                                letterSpacing: 1.0,
                              ),
                            ),
                          ),
                          const SizedBox(width: DvmaSpacing.sm),
                          DvmaBadge(
                            label: category.owaspMobile,
                            color: DvmaColors.forFrameworkTag(
                              category.owaspMobile,
                            ),
                          ),
                          const SizedBox(width: DvmaSpacing.sm),
                          _DifficultyTally(
                            counts: _difficultyCounts(),
                            total: vulns.length,
                            faint: c.textFaint,
                          ),
                        ],
                      ),
                      if (category.description.isNotEmpty) ...[
                        const SizedBox(height: 3),
                        Padding(
                          padding: const EdgeInsets.only(left: 22),
                          child: Text(
                            category.description,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 12,
                              color: c.textSecondary,
                              height: 1.35,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
        if (expanded)
          Container(
            margin: const EdgeInsets.fromLTRB(
              DvmaSpacing.lg,
              0,
              DvmaSpacing.lg,
              0,
            ),
            decoration: BoxDecoration(
              border: Border(
                left: BorderSide(color: c.border),
                right: BorderSide(color: c.border),
                bottom: BorderSide(color: c.border),
              ),
              borderRadius: const BorderRadius.only(
                bottomLeft: Radius.circular(DvmaRadii.sm),
                bottomRight: Radius.circular(DvmaRadii.sm),
              ),
            ),
            child: Column(
              children: [
                for (var i = 0; i < vulns.length; i++)
                  _VulnRow(vuln: vulns[i], isLast: i == vulns.length - 1),
              ],
            ),
          ),
      ],
    );
  }
}

/// The colored per-category difficulty tally (`15 · 7E 1M 4H`) shown in the
/// header. The count + separator stay faint; each difficulty count is tinted
/// with its severity color so the mix is scannable at a glance.
class _DifficultyTally extends StatelessWidget {
  const _DifficultyTally({
    required this.counts,
    required this.total,
    required this.faint,
  });

  final ({int easy, int medium, int hard}) counts;
  final int total;
  final Color faint;

  @override
  Widget build(BuildContext context) {
    Widget span(String text, Color color) =>
        DvmaMono(text, color: color, fontSize: 11);

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        span('$total · ', faint),
        if (counts.easy > 0) span('${counts.easy}E', DvmaColors.severityLow),
        if (counts.medium > 0) ...[
          if (counts.easy > 0) span(' ', faint),
          span('${counts.medium}M', DvmaColors.severityMedium),
        ],
        if (counts.hard > 0) ...[
          if (counts.easy > 0 || counts.medium > 0) span(' ', faint),
          span('${counts.hard}H', DvmaColors.severityHigh),
        ],
      ],
    );
  }
}

class _VulnRow extends StatelessWidget {
  const _VulnRow({required this.vuln, this.isLast = false});
  final VulnerabilityEntry vuln;
  final bool isLast;

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    // The build is already hard-filtered to the current platform, so a chip
    // matching that platform (e.g. "ANDROID" on an Android build) is redundant
    // noise. Only surface a chip when the module's single platform DIFFERS from
    // the running platform (informative), and never for shared modules.
    final current = context.read<AppConfig>().platform;
    final single = vuln.platforms.length == 1 ? vuln.platforms.first : null;
    final showChip = single != null && single != current;
    return testTapId(
      DvmaTestIds.vulnRow(vuln.id),
      InkWell(
        onTap: () {
          // Drop any active focus (e.g. the search field) so the soft keyboard
          // does not reappear when we pop back to the home screen.
          FocusManager.instance.primaryFocus?.unfocus();
          final builder = ModuleRouter.screenFor(vuln.id);
          Navigator.of(context)
              .push(MaterialPageRoute<void>(builder: (_) => builder(context)));
        },
        child: Container(
          decoration: BoxDecoration(
            border: Border(
              // Hairline between rows only (the container draws the last edge).
              bottom: isLast ? BorderSide.none : BorderSide(color: c.border),
              // A left "spine" tinted by difficulty, so difficulty is scannable
              // vertically down the whole list at a glance.
              left: BorderSide(color: vuln.difficulty.color, width: 3),
            ),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: DvmaSpacing.md,
            vertical: DvmaSpacing.md,
          ),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      vuln.title,
                      style: TextStyle(
                        fontWeight: FontWeight.w600,
                        color: c.textPrimary,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Row(
                      children: [
                        Flexible(
                          child: DvmaMono(
                            vuln.id,
                            color: c.textFaint,
                            fontSize: 11,
                          ),
                        ),
                        if (showChip) ...[
                          const SizedBox(width: DvmaSpacing.sm),
                          DvmaBadge(
                            label: single == 'ios' ? 'iOS' : 'ANDROID',
                            color: DvmaColors.severityLow,
                            small: true,
                          ),
                        ],
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(width: DvmaSpacing.sm),
              DvmaBadge.difficulty(vuln.difficulty),
              const SizedBox(width: DvmaSpacing.sm),
              Icon(Icons.chevron_right, size: 18, color: c.textFaint),
            ],
          ),
        ),
      ),
    );
  }
}
