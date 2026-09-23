import 'package:flutter/material.dart';

/// DVMA design tokens.
///
/// The interface is meant to read like a *technical instrument* for security
/// testing, not a consumer app. Every value here is a deliberate choice:
///
///  * Dark-first, near-black base (a desaturated green-black, never pure #000).
///  * A single hazard-amber accent that reads as "warning" rather than
///    terminal-cosplay green or generic SaaS purple.
///  * A dedicated severity scale whose colors carry real information
///    (vulnerability severity), so they earn their place as color.
///  * Tight corner radii (4-8px) so the UI reads precise/technical instead of
///    soft consumer-app pill shapes.
///
/// ## Light/dark theming
///
/// Surface/text/border tokens are *brightness-dependent* and live on
/// [DvmaPalette]; read them via [DvmaColors.of] so a widget picks up the active
/// (light or dark) scheme automatically:
///
/// ```dart
/// final c = DvmaColors.of(context);
/// Container(color: c.base, ...);
/// ```
///
/// The **accent** and **severity** colors are information-carrying, so they are
/// intentionally *constant* across both modes and remain static on
/// [DvmaColors].
class DvmaColors {
  DvmaColors._();

  /// The active palette for [context], resolved from the current
  /// [Theme.brightness]. Use for any surface/text/border color.
  static DvmaPalette of(BuildContext context) =>
      Theme.of(context).brightness == Brightness.light
      ? DvmaPalette.light
      : DvmaPalette.dark;

  // --- Accent (hazard-amber: reads as "warning") -----------------------------
  // Constant across light/dark: the accent is a brand/warning signal.
  static const Color accent = Color(0xFFE8A33D);
  static const Color accentPressed = Color(0xFFC9861F);
  static const Color onAccent = Color(0xFF17110A);

  // --- Severity scale (information-carrying, not decorative) -----------------
  // Constant across light/dark: these encode vulnerability severity, so the
  // same hue must mean the same thing regardless of theme.
  static const Color severityCritical = Color(0xFFD64545);
  static const Color severityHigh = Color(0xFFE8843D);
  static const Color severityMedium = Color(0xFFD9B23D);
  static const Color severityLow = Color(0xFF4A90A4);
  static const Color severityInfo = Color(0xFF6B7280);

  /// Success/pass (used sparingly, e.g. an assertion that a demo still works).
  static const Color pass = Color(0xFF4FA97E);
  static const Color danger = severityCritical;

  // --- Security-framework chip colors ---------------------------------------
  // Per-framework hues for the CWE / OWASP / MASVS / MASTG / MASWE metadata
  // chips. These mirror the Hugo docs palette (.hugo/static/css/custom.css
  // `.framework-chip-*`) so a tag reads the same color in the app and the docs.
  static const Color frameworkCwe = Color(0xFF4A90A4); // teal
  static const Color frameworkOwasp = Color(0xFFE8A33D); // amber (brand accent)
  static const Color frameworkMasvs = Color(0xFF2DD4BF); // cyan
  static const Color frameworkMastg = Color(0xFFA855F7); // purple
  static const Color frameworkMaswe = Color(0xFFE16478); // pink

  /// Maps a metadata tag (e.g. `CWE-200`, `MASVS-STORAGE-2`, `MASTG-TEST-0001`,
  /// `MASWE-0001`, `M1`, `LLM01`, `ASI03`) to its framework color, matching the
  /// Hugo docs. The OWASP families, Mobile Top 10 (`M1`..`M10`), LLM Top 10
  /// (`LLM01`..), and Agentic Top 10 (`ASI01`..), all share the OWASP amber, as
  /// they do in the docs. Unknown/unprefixed tags fall back to neutral gray.
  static Color forFrameworkTag(String tag) {
    final t = tag.toUpperCase();
    if (t.startsWith('CWE')) return frameworkCwe;
    if (t.startsWith('MASVS')) return frameworkMasvs;
    if (t.startsWith('MASTG')) return frameworkMastg;
    if (t.startsWith('MASWE')) return frameworkMaswe;
    if (t.startsWith('OWASP') ||
        t.startsWith('LLM') ||
        t.startsWith('ASI') ||
        RegExp(r'^M\d').hasMatch(t)) {
      return frameworkOwasp;
    }
    return severityInfo;
  }
}

/// Brightness-dependent surface/text/border tokens.
///
/// Two instances exist, [DvmaPalette.dark] (the primary "technical instrument"
/// look) and [DvmaPalette.light]. Resolve the right one with
/// [DvmaColors.of].
@immutable
class DvmaPalette {
  const DvmaPalette({
    required this.brightness,
    required this.base,
    required this.surface,
    required this.surfaceHigh,
    required this.border,
    required this.textPrimary,
    required this.textSecondary,
    required this.textFaint,
  });

  final Brightness brightness;

  /// App background.
  final Color base;

  /// Slightly raised surface (cards, sheets).
  final Color surface;

  /// Higher elevation / hovered surface.
  final Color surfaceHigh;

  /// Hairline borders and dividers.
  final Color border;

  final Color textPrimary;
  final Color textSecondary;
  final Color textFaint;

  /// Dark (default): a desaturated green-black base, never pure black.
  static const DvmaPalette dark = DvmaPalette(
    brightness: Brightness.dark,
    base: Color(0xFF0D1210),
    surface: Color(0xFF141B18),
    surfaceHigh: Color(0xFF1C2621),
    border: Color(0xFF2A3630),
    textPrimary: Color(0xFFE6ECE8),
    textSecondary: Color(0xFF9AA8A1),
    textFaint: Color(0xFF6B7A73),
  );

  /// Light: a warm off-white paper with the same green-tinted neutrals, tuned
  /// for contrast so the amber accent and severity scale still read correctly.
  static const DvmaPalette light = DvmaPalette(
    brightness: Brightness.light,
    base: Color(0xFFF4F6F4),
    surface: Color(0xFFFFFFFF),
    surfaceHigh: Color(0xFFE9EEEB),
    border: Color(0xFFD3DAD5),
    textPrimary: Color(0xFF16201B),
    textSecondary: Color(0xFF4A574F),
    textFaint: Color(0xFF7E8A83),
  );
}

/// Corner radii. Deliberately tight - technical, not consumer-soft.
class DvmaRadii {
  DvmaRadii._();
  static const double xs = 4;
  static const double sm = 6;
  static const double md = 8;

  static const BorderRadius cardRadius = BorderRadius.all(Radius.circular(md));
  static const BorderRadius chipRadius = BorderRadius.all(Radius.circular(xs));
  static const BorderRadius buttonRadius = BorderRadius.all(
    Radius.circular(sm),
  );
}

/// Spacing scale (4px baseline grid).
class DvmaSpacing {
  DvmaSpacing._();
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 16;
  static const double xl = 24;
  static const double xxl = 32;
}

/// Difficulty levels used by the registry, mapped to a color for badges.
enum DvmaDifficulty { easy, medium, hard }

extension DvmaDifficultyColor on DvmaDifficulty {
  Color get color {
    switch (this) {
      case DvmaDifficulty.easy:
        return DvmaColors.severityLow;
      case DvmaDifficulty.medium:
        return DvmaColors.severityMedium;
      case DvmaDifficulty.hard:
        return DvmaColors.severityHigh;
    }
  }

  String get label {
    switch (this) {
      case DvmaDifficulty.easy:
        return 'EASY';
      case DvmaDifficulty.medium:
        return 'MEDIUM';
      case DvmaDifficulty.hard:
        return 'HARD';
    }
  }
}
