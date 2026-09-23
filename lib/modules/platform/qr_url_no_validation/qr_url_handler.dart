/// QR Scanner -> URL With No Validation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-601 / CWE-20): a scanned QR code's payload is
/// treated as a trusted URL/deeplink and opened/navigated WITHOUT validation.
/// A QR code is fully attacker-controlled, so it can carry a `javascript:`
/// URI, a privileged in-app deeplink, or a phishing https link, and the app
/// will act on it as if the user typed it (Firefox iOS QR-scanner
/// CVE-2025-54145 class).
///
/// This is an offline + deterministic simulation. [QrUrlHandler] does not open
/// anything for real; it classifies the scanned payload and records what action
/// it *would* take. Tests can assert a dangerous payload is opened/navigated on
/// the vuln path and refused on the secure path (scheme allowlist + explicit
/// user confirmation for external links).
library;

/// What the app decided to do with a scanned QR payload.
enum QrAction {
  /// Navigate to a privileged in-app deeplink route.
  openDeeplink,

  /// Open an external web URL.
  openExternalUrl,

  /// Execute a javascript: URI (worst case).
  executeJavascript,

  /// Do nothing / refuse.
  refused,
}

/// The outcome of handling a scanned QR payload.
class QrHandleResult {
  const QrHandleResult({
    required this.payload,
    required this.action,
    required this.opened,
    this.blockReason,
  });

  /// The raw scanned payload.
  final String payload;

  /// The action the app took.
  final QrAction action;

  /// Whether the app actually navigated/opened/executed something.
  final bool opened;

  /// Why the payload was refused (secure path).
  final String? blockReason;

  /// True when a dangerous (non-plain-https) payload was acted on.
  bool get openedDangerous =>
      opened &&
      (action == QrAction.executeJavascript || action == QrAction.openDeeplink);
}

class QrUrlHandler {
  const QrUrlHandler._();

  /// VULN: trust the scanned payload as a URL and open/navigate it directly.
  /// `javascript:` executes, `dvma://` deeplinks hit privileged routes, and
  /// external URLs open - all with no validation or user confirmation.
  static QrHandleResult handle(String payload) {
    final uri = Uri.tryParse(payload.trim());
    final scheme = uri?.scheme.toLowerCase() ?? '';
    final action = switch (scheme) {
      'javascript' => QrAction.executeJavascript,
      'dvma' => QrAction.openDeeplink,
      _ => QrAction.openExternalUrl,
    };
    return QrHandleResult(payload: payload, action: action, opened: true);
  }

  /// SECURE contrast: only treat the payload as an EXTERNAL https link, and
  /// only after refusing dangerous schemes and privileged in-app deeplinks. A
  /// real app would additionally show a confirmation with the full host before
  /// opening; here we simply refuse anything that is not plain https.
  static QrHandleResult handleSafe(String payload) {
    final uri = Uri.tryParse(payload.trim());
    final scheme = uri?.scheme.toLowerCase() ?? '';
    if (scheme == 'javascript') {
      return QrHandleResult(
        payload: payload,
        action: QrAction.refused,
        opened: false,
        blockReason: 'refused non-navigational scheme (javascript:)',
      );
    }
    if (scheme == 'dvma') {
      return QrHandleResult(
        payload: payload,
        action: QrAction.refused,
        opened: false,
        blockReason: 'refused privileged in-app deeplink from untrusted QR',
      );
    }
    if (scheme != 'https') {
      return QrHandleResult(
        payload: payload,
        action: QrAction.refused,
        opened: false,
        blockReason: 'refused non-https scheme ($scheme)',
      );
    }
    return QrHandleResult(
      payload: payload,
      action: QrAction.openExternalUrl,
      opened: true,
    );
  }
}
