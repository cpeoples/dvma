import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/webview_file` channel (see
/// DvmaNativeProbes.swift).
///
/// iOS backs wkwebview_untrusted_url_local_file with a real `WKWebView`. The
/// legacy `allowFileAccessFromFileURLs` / `file://`-origin XHR trick is dead on
/// modern WebKit, so instead a custom `WKURLSchemeHandler` (scheme `dvma-app://`)
/// serves both the untrusted attacker page and a seeded secret file under one
/// origin. The injected `<script>` `fetch()`es the secret same-origin and posts
/// it back through a `WKScriptMessageHandler`; the bytes are reported here.
/// Returns null off-iOS so the caller keeps its existing (real on Android) path.
class WebviewFileBridge {
  const WebviewFileBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/webview_file');

  static bool get isAvailable => Platform.isIOS;

  /// Runs the real WKWebView local-file read for [payload] (reflected unescaped
  /// into the page) and returns the native report, including the file bytes the
  /// injected script exfiltrated.
  static Future<String?> readLocalFile(String payload) => invokeNativeString(
    _channel,
    isAvailable,
    'readLocalFile',
    {'payload': payload},
  );
}
