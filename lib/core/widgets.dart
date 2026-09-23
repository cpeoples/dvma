import 'package:flutter/material.dart';

import '../vulnerability_registry.dart';
import 'theme/dvma_colors.dart';
import 'theme/dvma_theme.dart';

/// A small monospace badge with a tinted border, used to display severity,
/// difficulty, or a category/standard tag. Monospace + tight radius marks it
/// visually as structured technical metadata rather than decorative chrome.
class DvmaBadge extends StatelessWidget {
  const DvmaBadge({
    super.key,
    required this.label,
    required this.color,
    this.filled = false,
    this.small = false,
  });

  final String label;
  final Color color;
  final bool filled;

  /// A more compact variant (smaller text/padding), for dense inline use such
  /// as a per-row platform tag.
  final bool small;

  /// Convenience constructor for a difficulty badge.
  factory DvmaBadge.difficulty(DvmaDifficulty difficulty, {Key? key}) {
    return DvmaBadge(
      key: key,
      label: difficulty.label,
      color: difficulty.color,
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: small ? 4 : 6,
        vertical: small ? 1 : 2,
      ),
      decoration: BoxDecoration(
        color: filled ? color : color.withValues(alpha: 0.12),
        border: Border.all(color: color.withValues(alpha: 0.5)),
        borderRadius: DvmaRadii.chipRadius,
      ),
      child: Text(
        label,
        style: DvmaTheme.mono(
          fontSize: small ? 8 : 10,
          fontWeight: FontWeight.w700,
          color: filled ? c.base : color,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

/// The full framework mapping for a module, rendered as grouped rows of colored
/// chips, parity with the Hugo docs' detail pages. Each standard family gets a
/// labeled row (CWE / MASVS / MASWE / MASTG / OWASP) and each ref is a
/// [DvmaBadge] tinted by [DvmaColors.forFrameworkTag], so a tag reads the same
/// color here and in the docs. Rows with no refs are omitted. When [entry] is
/// null (unresolved), only the difficulty badge is shown.
class DvmaFrameworkChips extends StatelessWidget {
  const DvmaFrameworkChips({
    super.key,
    required this.difficulty,
    required this.entry,
  });

  final DvmaDifficulty difficulty;
  final VulnerabilityEntry? entry;

  @override
  Widget build(BuildContext context) {
    final e = entry;
    if (e == null) return DvmaBadge.difficulty(difficulty);

    // OWASP refs live on scalar fields; collect the non-null ones (Mobile is
    // required, LLM/Agentic are optional and only present on AI modules).
    final owasp = <String>[
      'OWASP-${e.owaspMobile}',
      if (e.owaspLlm != null) e.owaspLlm!,
      if (e.owaspAgentic != null) e.owaspAgentic!,
    ];

    // Ordered families -> refs; empty families are dropped by _row.
    final rows = <Widget?>[
      _row('CWE', e.cwe),
      _row('MASVS', e.masvs),
      _row('MASWE', e.maswe),
      _row('MASTG', [...e.mastgV2, ...e.mastgDemo]),
      _row('OWASP', owasp),
    ].whereType<Widget>().toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        DvmaBadge.difficulty(difficulty),
        const SizedBox(height: DvmaSpacing.sm),
        ...rows,
      ],
    );
  }

  /// One labeled family row, or null when [refs] is empty (so the caller can
  /// drop it). The label is a dim caption; each ref is a colored chip.
  Widget? _row(String family, List<String> refs) {
    if (refs.isEmpty) return null;
    final color = DvmaColors.forFrameworkTag(refs.first);
    return Padding(
      padding: const EdgeInsets.only(bottom: DvmaSpacing.xs),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 56,
            child: Text(
              family,
              style: DvmaTheme.mono(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),
          ),
          Expanded(
            child: Wrap(
              spacing: DvmaSpacing.xs,
              runSpacing: DvmaSpacing.xs,
              children: refs
                  .map(
                    (r) => DvmaBadge(
                      label: r,
                      color: DvmaColors.forFrameworkTag(r),
                      small: true,
                    ),
                  )
                  .toList(),
            ),
          ),
        ],
      ),
    );
  }
}

/// A monospace inline code/token span for rendering vulnerability IDs, tokens,
/// hex, or short log fragments in the "raw technical data" style.
class DvmaMono extends StatelessWidget {
  const DvmaMono(this.text, {super.key, this.color, this.fontSize = 12});

  final String text;
  final Color? color;
  final double fontSize;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: DvmaTheme.mono(
        fontSize: fontSize,
        color: color ?? DvmaColors.of(context).textSecondary,
      ),
    );
  }
}
