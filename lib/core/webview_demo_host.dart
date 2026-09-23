import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import 'vuln_demo_scaffold.dart';

/// Shared plumbing for the DVMA modules that back their vulnerability with a
/// real Android System WebView (via the `webview_flutter` plugin).
///
/// A WebView can only be created when a platform implementation is registered
/// (a real Android/iOS device or emulator). Under `flutter test`, and on the
/// web, no platform is registered, so calling `WebViewController()` would
/// throw. [supportsRealWebView] gates every real-WebView code path so the
/// module screens still build (and `flutter test` still passes) on those hosts,
/// falling back to a text panel via [RealWebViewView].
bool get supportsRealWebView {
  if (kIsWeb) return false;
  try {
    // Android is where the DVMA WebView modules are exercised; the plugin's
    // Android platform is what these demos configure (mixed content, remote
    // debugging, file access, JS channels, navigation delegates).
    return Platform.isAndroid || Platform.isIOS;
  } catch (_) {
    // Platform can throw on unsupported hosts; treat as "no real WebView".
    return false;
  }
}

/// Renders [controller] inside a bounded box on a real device, or a short
/// explanatory panel when a real WebView is unavailable (tests / web / desktop).
///
/// The [controller] is created lazily by the owning screen only when
/// [supportsRealWebView] is true, so it is null on non-device hosts.
class RealWebViewView extends StatelessWidget {
  const RealWebViewView({
    super.key,
    required this.controller,
    this.height = 220,
    this.unavailableNote =
        'Real WebView unavailable on this host (test/web/desktop). '
        'Run on an Android device/emulator to render live attacker content.',
  });

  /// The live controller, or null when [supportsRealWebView] is false.
  final WebViewController? controller;

  /// Bounded render height for the embedded WebView.
  final double height;

  /// Text shown when no real WebView backing exists.
  final String unavailableNote;

  @override
  Widget build(BuildContext context) {
    final c = controller;
    if (c == null) {
      return EvidencePanel(
        label: 'webview (unavailable)',
        value: unavailableNote,
      );
    }
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: SizedBox(
        height: height,
        child: DecoratedBox(
          decoration: BoxDecoration(border: Border.all(color: Colors.white24)),
          child: WebViewWidget(controller: c),
        ),
      ),
    );
  }
}
