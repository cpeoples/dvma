import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'module_router.dart';

/// Wraps the app's home and routes `dvma://module/<id>` deep links to the
/// matching module screen via [ModuleRouter.screenFor].
///
/// DVMA already registers the `dvma://` URL scheme (iOS `CFBundleURLTypes`,
/// Android intent filter) and depends on `app_links`, but nothing at the app
/// root consumed a *navigation* link - the scheme was only used inside
/// individual demo modules. This root handler makes the app openable straight
/// to any module by id, e.g. `dvma://module/temp_file_leftovers`.
///
/// It is also the iOS automation seam. XCUITest cannot reliably set a Flutter
/// canvas TextField's value on a physical device (there is no `element.value =`
/// in XCUITest, and `typeText` needs a first-responder the canvas never grants),
/// so the iOS "walk every module" test navigates by opening this deep link per
/// module id instead of typing into the search field - the keyboard-free
/// equivalent of the Android walk's `edit.text = id` search navigation. The
/// deep link resolves through the SAME `ModuleRouter.screenFor` map the home
/// list uses, so there is no separate, drift-prone navigation path.
///
/// Link grammar (host or first path segment is the module id, both accepted so
/// `dvma://module/<id>` and `dvma://<id>` work):
///   `dvma://module/<vulnId>`
///   `dvma://module?id=<vulnId>`
class DeepLinkNavigator extends StatefulWidget {
  const DeepLinkNavigator({super.key, required this.child, this.navigatorKey});

  /// The app's home widget (rendered as the navigator's first route).
  final Widget child;

  /// Navigator used to push module screens. When null, the nearest [Navigator]
  /// found via [navigatorKey]'s context is used; supplying an explicit key lets
  /// [MaterialApp] own the navigator while this widget still drives it.
  final GlobalKey<NavigatorState>? navigatorKey;

  @override
  State<DeepLinkNavigator> createState() => _DeepLinkNavigatorState();
}

class _DeepLinkNavigatorState extends State<DeepLinkNavigator> {
  final AppLinks _appLinks = AppLinks();
  StreamSubscription<Uri>? _sub;

  /// Test-only channel: the native side reads `DVMA_OPEN_MODULE` from the process
  /// environment (which XCUITest's launchEnvironment populates natively) and
  /// returns it here. See ios/Runner/DvmaNativeProbes.swift `dvma/automation`.
  static const MethodChannel _automationChannel = MethodChannel(
    'dvma/automation',
  );

  @override
  void initState() {
    super.initState();
    _initDeepLinks();
  }

  Future<void> _initDeepLinks() async {
    // Automation seam: when launched by the "walk every module" harness with a
    // target module id, open that module immediately on startup. The id comes
    // from the NATIVE side (ProcessInfo.environment via the dvma/automation
    // channel) because Dart's Platform.environment does not see XCUITest's
    // launchEnvironment on iOS. This is the keyboard-free, in-process navigation
    // the walk uses instead of typing into Flutter's canvas search field.
    final envModule = await _envModuleId();
    if (envModule != null && envModule.isNotEmpty) {
      _openModuleDeferred(envModule);
    }

    // Cold start: the link that launched the app (if any).
    try {
      final initial = await _appLinks.getInitialLink();
      if (initial != null) _handleUri(initial);
    } catch (_) {
      // A malformed/absent initial link must never block app startup.
    }
    // Warm links while the app is running.
    _sub = _appLinks.uriLinkStream.listen(
      _handleUri,
      onError: (_) {
        /* ignore malformed links */
      },
    );
  }

  /// Module id supplied via the launch environment (automation), or null.
  /// Read natively via [_automationChannel]; any error/absence yields null so
  /// normal launches are unaffected.
  Future<String?> _envModuleId() async {
    try {
      final id = await _automationChannel.invokeMethod<String>(
        'openModuleOnLaunch',
      );
      if (id != null && id.trim().isNotEmpty) return id.trim();
    } catch (_) {
      // Channel not registered / not implemented -> normal launch, no-op.
    }
    return null;
  }

  void _openModuleDeferred(String id) {
    WidgetsBinding.instance.addPostFrameCallback((_) => _openModule(id));
  }

  /// Parse a `dvma://module/<id>` (or `dvma://<id>`) URI and push the module.
  void _handleUri(Uri uri) {
    final id = _moduleIdFrom(uri);
    if (id == null || id.isEmpty) return;
    // Defer to after the current frame so a cold-start link finds a mounted
    // navigator.
    WidgetsBinding.instance.addPostFrameCallback((_) => _openModule(id));
  }

  /// Extract the module id from the link. Accepts, in priority order:
  ///   1. `?id=<vulnId>` query parameter,
  ///   2. the last non-empty path segment (so `dvma://module/<id>` works),
  ///   3. the host (so the shorthand `dvma://<id>` works).
  String? _moduleIdFrom(Uri uri) {
    if (uri.scheme != 'dvma') return null;
    final q = uri.queryParameters['id'];
    if (q != null && q.isNotEmpty) return q;
    final segs = uri.pathSegments.where((s) => s.isNotEmpty).toList();
    if (segs.isNotEmpty) return segs.last;
    if (uri.host.isNotEmpty && uri.host != 'module') return uri.host;
    return null;
  }

  void _openModule(String id) {
    // The root navigator may not be mounted on the very first frame after a cold
    // launch; retry briefly so an env/deep-link open right at startup still lands.
    _openModuleWithRetry(id, attempt: 0);
  }

  void _openModuleWithRetry(String id, {required int attempt}) {
    final navigator =
        widget.navigatorKey?.currentState ??
        (mounted ? Navigator.maybeOf(context) : null);
    if (navigator == null) {
      if (attempt >= 20) return; // ~2s of frames; give up quietly
      WidgetsBinding.instance.addPostFrameCallback(
        (_) => _openModuleWithRetry(id, attempt: attempt + 1),
      );
      return;
    }
    final builder = ModuleRouter.screenFor(id);
    navigator.push(MaterialPageRoute<void>(builder: (ctx) => builder(ctx)));
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
