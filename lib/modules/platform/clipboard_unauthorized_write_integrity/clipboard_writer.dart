/// Clipboard Unauthorized Write / Integrity Tampering helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-471 / CWE-668): untrusted content -
/// a page loaded in the app's WebView, or another app - OVERWRITES the system
/// clipboard with no user gesture and no origin check. The user copies a
/// value (e.g. a crypto wallet address / IBAN) and, before they paste,
/// attacker-controlled content silently swaps the clipboard for an attacker's
/// address, so the user pastes the WRONG value (a classic address-swap /
/// clipboard-hijack). The integrity of what the user pastes is broken.
///
/// This helper is an offline + deterministic model: [SystemClipboard] is an
/// in-memory clipboard and [ClipboardWriter] performs writes on behalf of some
/// origin. (The module screen additionally mirrors the attacker write to the
/// real system clipboard via `Clipboard.setData`; this helper stays in-memory
/// so the origin/gesture decision is unit-testable.) The vulnerable
/// [writeFromContent] accepts a write from ANY origin with no gesture; the
/// secure [writeFromContentSafe] requires a trusted origin and a valid
/// user-gesture token, refusing untrusted / gesture-less writes.
library;

/// An in-memory system clipboard.
class SystemClipboard {
  SystemClipboard(this._value);

  String _value;

  /// The value currently on the clipboard.
  String get value => _value;

  void set(String value) => _value = value;
}

/// The outcome of a clipboard write attempt.
class ClipboardWriteResult {
  const ClipboardWriteResult({
    required this.origin,
    required this.attemptedValue,
    required this.clipboardAfter,
    required this.wrote,
    required this.tampered,
    this.denyReason,
  });

  /// The origin that attempted the write.
  final String origin;

  /// The value the origin tried to place on the clipboard.
  final String attemptedValue;

  /// The clipboard contents AFTER the attempt.
  final String clipboardAfter;

  /// Whether the write landed.
  final bool wrote;

  /// True when an UNTRUSTED origin overwrote a value the user had copied - the
  /// integrity-tampering hit (the user will paste the attacker value).
  final bool tampered;

  /// Why the safe writer refused.
  final String? denyReason;
}

/// Performs clipboard writes for some origin, with or without safety checks.
class ClipboardWriter {
  ClipboardWriter(this._clipboard);

  final SystemClipboard _clipboard;

  /// The user's own app UI - the only origin allowed to write.
  static const String trustedOrigin = 'app://dvma.wallet';

  /// A hostile page loaded in the in-app WebView.
  static const String untrustedOrigin = 'https://evil.example/pay';

  /// The address the USER actually copied.
  static const String userAddress = 'bc1qUSER0000copiedbythehumanaddr';

  /// The address the attacker swaps in.
  static const String attackerAddress = 'bc1qATTACKERdrainswalletaddr999';

  /// A valid user-gesture token minted by a real tap in trusted UI.
  static const String validGestureToken = 'gesture:tap#legit';

  /// VULN: write [value] to the clipboard for ANY [origin] with no gesture and
  /// no origin check, so untrusted content silently overwrites what the user
  /// copied.
  ClipboardWriteResult writeFromContent(String origin, String value) {
    final before = _clipboard.value;
    _clipboard.set(value);
    return ClipboardWriteResult(
      origin: origin,
      attemptedValue: value,
      clipboardAfter: _clipboard.value,
      wrote: true,
      tampered: origin != trustedOrigin && before != value,
      denyReason: null,
    );
  }

  /// SECURE contrast: only accept a write from a TRUSTED origin that presents a
  /// valid user-gesture token. Untrusted origins and gesture-less writes are
  /// refused, so the value the user copied is preserved.
  ClipboardWriteResult writeFromContentSafe(
    String origin,
    String value, {
    String? gestureToken,
  }) {
    if (origin != trustedOrigin) {
      return ClipboardWriteResult(
        origin: origin,
        attemptedValue: value,
        clipboardAfter: _clipboard.value,
        wrote: false,
        tampered: false,
        denyReason: 'untrusted origin "$origin" may not write the clipboard',
      );
    }
    if (gestureToken != validGestureToken) {
      return ClipboardWriteResult(
        origin: origin,
        attemptedValue: value,
        clipboardAfter: _clipboard.value,
        wrote: false,
        tampered: false,
        denyReason: 'clipboard write requires a genuine user gesture',
      );
    }
    _clipboard.set(value);
    return ClipboardWriteResult(
      origin: origin,
      attemptedValue: value,
      clipboardAfter: _clipboard.value,
      wrote: true,
      tampered: false,
      denyReason: null,
    );
  }
}
