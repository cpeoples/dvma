/// Cross-Origin Iframe -> Native Bridge helper.
///
/// INTENTIONALLY VULNERABLE (CWE-346 / CWE-1021 / CWE-668): a JS-bridge message
/// handler (Android addJavascriptInterface / WebMessageListener; iOS
/// WKUserContentController / WKScriptMessageHandler) is registered on the
/// WebView, but the message handler does not verify that the message came from
/// the MAIN FRAME or from the trusted first-party origin. So a cross-origin
/// iframe embedded in the page can post a message to the bridge, the native
/// side honors it as if it were the trusted app UI, and returns the session /
/// access token - which the iframe then exfiltrates. This is the Home Assistant
/// Companion CVE-2026-44698 class.
///
/// The screen drives this over a real WebView JS bridge: a cross-origin iframe
/// posts the message across the native channel and the native side returns the
/// token (vuln) or requires isMainFrame && origin==trusted (secure).
/// [BridgeMessageHandler] models the frame/origin decision and is kept as a
/// deterministic in-memory fallback for `flutter test`. Tests assert the token
/// is exfiltrated from a cross-origin iframe on the vuln path and blocked on
/// the secure path.
library;

/// Where a bridge message originated inside the WebView.
enum BridgeFrame { mainFrame, iframe }

/// A message posted to the native bridge from web content.
class BridgeMessage {
  const BridgeMessage({
    required this.method,
    required this.frame,
    required this.origin,
  });

  /// The bridge method being invoked (e.g. `getAccessToken`).
  final String method;

  /// The frame the message came from.
  final BridgeFrame frame;

  /// The origin of the frame that posted the message.
  final String origin;
}

/// The outcome of handling a bridge message.
class BridgeResponse {
  const BridgeResponse({
    required this.handled,
    required this.blocked,
    this.token,
    this.blockReason,
  });

  /// Whether the bridge acted on the message.
  final bool handled;

  /// Whether the bridge refused the message (secure path).
  final bool blocked;

  /// The access token returned to the caller (null unless leaked).
  final String? token;

  /// Why the message was refused (secure path only).
  final String? blockReason;

  /// True when a token was returned to web content that was not the trusted
  /// main frame - i.e. the actual cross-origin exfiltration hit.
  bool tokenExfiltrated(BridgeMessage msg, String trustedOrigin) =>
      handled &&
      token != null &&
      (msg.frame != BridgeFrame.mainFrame || msg.origin != trustedOrigin);
}

/// A minimal, in-memory model of a WebView JS-bridge message handler.
class BridgeMessageHandler {
  BridgeMessageHandler({required this.trustedOrigin});

  /// The first-party origin the app WebView is authenticated to.
  final String trustedOrigin;

  /// The session/access token the bridge can hand back to the app UI.
  static const String accessToken = 'eyJhbGciOiJIUzI1NiJ9.at-9f3c-secret';

  /// VULN: the handler answers any `getAccessToken` message and returns the
  /// token, regardless of which frame/origin sent it. A cross-origin iframe
  /// gets the token just like the trusted main frame would.
  BridgeResponse handle(BridgeMessage msg) {
    if (msg.method == 'getAccessToken') {
      return const BridgeResponse(
        handled: true,
        blocked: false,
        token: accessToken,
      );
    }
    return const BridgeResponse(handled: false, blocked: false);
  }

  /// SECURE contrast: require the message to originate from the MAIN FRAME AND
  /// from the trusted origin before returning anything sensitive. A cross-origin
  /// iframe (or a main frame that navigated to an untrusted origin) is refused.
  BridgeResponse handleSafe(BridgeMessage msg) {
    if (msg.frame != BridgeFrame.mainFrame) {
      return const BridgeResponse(
        handled: false,
        blocked: true,
        blockReason: 'message not from main frame (iframe rejected)',
      );
    }
    if (msg.origin != trustedOrigin) {
      return BridgeResponse(
        handled: false,
        blocked: true,
        blockReason: 'origin ${msg.origin} not trusted',
      );
    }
    if (msg.method == 'getAccessToken') {
      return const BridgeResponse(
        handled: true,
        blocked: false,
        token: accessToken,
      );
    }
    return const BridgeResponse(handled: false, blocked: false);
  }
}
