import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Holds the user's light/dark preference and persists it.
///
/// DVMA is dark-first (the "technical instrument" identity), so the default is
/// [ThemeMode.dark] until the user chooses otherwise. The choice is saved to
/// [SharedPreferences] and restored on next launch.
class ThemeController extends ChangeNotifier {
  ThemeController([this._mode = ThemeMode.dark]);

  static const String _prefsKey = 'dvma_theme_mode';

  ThemeMode _mode;
  ThemeMode get mode => _mode;

  /// Loads the saved preference (defaults to dark) into a fresh controller.
  static Future<ThemeController> load() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_prefsKey);
    return ThemeController(_parse(saved));
  }

  Future<void> setMode(ThemeMode mode) async {
    if (mode == _mode) return;
    _mode = mode;
    notifyListeners();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_prefsKey, mode.name);
  }

  /// Toggles between dark and light. (There is intentionally no `system` mode:
  /// a 3-state cycle has an "invisible" step whenever `system` matches the OS
  /// setting, which reads as a broken toggle.)
  Future<void> cycle() =>
      setMode(_mode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark);

  /// The icon representing the mode the toggle will switch *to*, so the button
  /// previews its action: a sun in dark mode, a moon in light mode.
  IconData get icon => _mode == ThemeMode.dark
      ? Icons.light_mode_outlined
      : Icons.dark_mode_outlined;

  static ThemeMode _parse(String? name) =>
      name == 'light' ? ThemeMode.light : ThemeMode.dark;
}
