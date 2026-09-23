import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import 'dvma_colors.dart';

/// Builds DVMA's Material 3 theme.
///
/// Material 3 is the engine (it is the modern cross-platform baseline in the
/// Flutter SDK today), but the default look is fully replaced: intentional
/// color scheme, a two-family type scale, and tight technical shapes. That
/// replacement - not the widget library - is what makes the app read as
/// "designed" rather than templated.
///
/// Type roles are deliberately distinct:
///   * Inter (sans)          -> UI chrome and body text.
///   * JetBrains Mono (mono) -> anything technical: vulnerability IDs, code,
///     logs, hex/token output. Mono type is a structural signal that you are
///     looking at raw/technical data.
class DvmaTheme {
  DvmaTheme._();

  /// Monospace text style for technical data (IDs, tokens, logs, code).
  /// Exposed so widgets can opt individual strings into the "raw data" look.
  static TextStyle mono({
    double fontSize = 13,
    FontWeight fontWeight = FontWeight.w500,
    Color? color,
    double? letterSpacing,
  }) {
    return GoogleFonts.jetBrainsMono(
      fontSize: fontSize,
      fontWeight: fontWeight,
      color: color,
      letterSpacing: letterSpacing,
      height: 1.4,
    );
  }

  static ThemeData dark() => _build(DvmaPalette.dark);
  static ThemeData light() => _build(DvmaPalette.light);

  /// Builds the Material 3 theme for [p], so light and dark share one
  /// definition and only differ by their surface/text/border palette.
  static ThemeData _build(DvmaPalette p) {
    final isLight = p.brightness == Brightness.light;
    final colorScheme = ColorScheme(
      brightness: p.brightness,
      primary: DvmaColors.accent,
      onPrimary: DvmaColors.onAccent,
      primaryContainer: DvmaColors.accentPressed,
      onPrimaryContainer: DvmaColors.onAccent,
      secondary: DvmaColors.severityLow,
      onSecondary: p.base,
      error: DvmaColors.severityCritical,
      onError: Colors.white,
      surface: p.surface,
      onSurface: p.textPrimary,
      surfaceContainerHighest: p.surfaceHigh,
      onSurfaceVariant: p.textSecondary,
      outline: p.border,
      outlineVariant: p.border,
    );

    final baseTextTheme = GoogleFonts.interTextTheme(
      ThemeData(brightness: p.brightness).textTheme,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: p.brightness,
      colorScheme: colorScheme,
      scaffoldBackgroundColor: p.base,
      canvasColor: p.base,
      dividerColor: p.border,
      textTheme: baseTextTheme.apply(
        bodyColor: p.textPrimary,
        displayColor: p.textPrimary,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: p.base,
        foregroundColor: p.textPrimary,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        systemOverlayStyle: isLight
            ? SystemUiOverlayStyle.dark
            : SystemUiOverlayStyle.light,
        titleTextStyle: GoogleFonts.inter(
          fontSize: 18,
          fontWeight: FontWeight.w600,
          color: p.textPrimary,
        ),
      ),
      cardTheme: CardThemeData(
        color: p.surface,
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: DvmaRadii.cardRadius,
          side: BorderSide(color: p.border),
        ),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: p.surfaceHigh,
        side: BorderSide(color: p.border),
        shape: const RoundedRectangleBorder(borderRadius: DvmaRadii.chipRadius),
        labelStyle: mono(fontSize: 11, color: p.textSecondary),
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: DvmaColors.accent,
          foregroundColor: DvmaColors.onAccent,
          elevation: 0,
          shape: const RoundedRectangleBorder(
            borderRadius: DvmaRadii.buttonRadius,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
          textStyle: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.textPrimary,
          side: BorderSide(color: p.border),
          shape: const RoundedRectangleBorder(
            borderRadius: DvmaRadii.buttonRadius,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.surfaceHigh,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 12,
        ),
        border: OutlineInputBorder(
          borderRadius: DvmaRadii.buttonRadius,
          borderSide: BorderSide(color: p.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: DvmaRadii.buttonRadius,
          borderSide: BorderSide(color: p.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: DvmaRadii.buttonRadius,
          borderSide: const BorderSide(color: DvmaColors.accent, width: 1.5),
        ),
        labelStyle: TextStyle(color: p.textSecondary),
        hintStyle: mono(fontSize: 13, color: p.textFaint),
      ),
      listTileTheme: ListTileThemeData(
        iconColor: p.textSecondary,
        textColor: p.textPrimary,
      ),
      dividerTheme: DividerThemeData(color: p.border, thickness: 1, space: 1),
    );
  }
}
