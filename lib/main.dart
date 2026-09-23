import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'app_config.dart';
import 'core/deep_link_navigator.dart';
import 'core/home_screen.dart';
import 'core/theme/dvma_theme.dart';
import 'core/theme/theme_controller.dart';
import 'modules/ai_ml/mock_llm.dart';

/// DVMA - Damn Vulnerable Mobile App.
///
/// FOR AUTHORIZED TRAINING / TESTING USE only. Do not deploy to production
/// infrastructure or app stores. See the root README disclaimer.
///
/// The active build flavor is parsed once here from `--dart-define` values
/// (see [AppConfig]) and provided to the widget tree. The vulnerability
/// registry and UI read it to surface only the enabled vulnerabilities.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final config = AppConfig.fromEnvironment();
  // Opt-in: route the AI modules to a real model (OpenRouter) when a key was
  // provided via --dart-define; no-op otherwise (offline MockLlm). See mock_llm.
  LlmConfig.fromEnvironment();
  final theme = await ThemeController.load();
  runApp(DvmaApp(config: config, theme: theme));
}

class DvmaApp extends StatelessWidget {
  DvmaApp({super.key, required this.config, required this.theme});

  final AppConfig config;
  final ThemeController theme;

  // Owned by MaterialApp; the deep-link handler drives it to push module
  // screens for `dvma://module/<id>` links (see DeepLinkNavigator).
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<AppConfig>.value(value: config),
        ChangeNotifierProvider<ThemeController>.value(value: theme),
      ],
      child: Consumer<ThemeController>(
        builder: (context, theme, _) => MaterialApp(
          title: 'DVMA',
          debugShowCheckedModeBanner: false,
          navigatorKey: _navigatorKey,
          theme: DvmaTheme.light(),
          darkTheme: DvmaTheme.dark(),
          themeMode: theme.mode,
          home: DeepLinkNavigator(
            navigatorKey: _navigatorKey,
            child: const HomeScreen(),
          ),
        ),
      ),
    );
  }
}
