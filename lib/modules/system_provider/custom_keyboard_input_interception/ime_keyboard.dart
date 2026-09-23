/// Custom Keyboard Input Interception helper.
///
/// INTENTIONALLY VULNERABLE (CWE-522 / CWE-359 / CWE-829): a custom keyboard /
/// InputMethodService (or iOS keyboard extension) receives every keystroke the
/// user types across OTHER apps - including passwords and OTPs in secure
/// fields. Because it was granted network access ("Allow Full Access") and runs
/// without isolation, it logs and exfiltrates that input to an attacker sink.
///
/// This is an offline + deterministic SIMULATION. [ImeKeyboard] receives keys
/// for a [TypedField] that may be marked `secureField`, holds a
/// `hasNetworkAccess` flag, and appends captured/exfiltrated keys to in-memory
/// sinks. The vulnerable [onKey] logs+exfiltrates everything (secure fields
/// included); the secure [onKeySafe] refuses to log/transmit for secure fields
/// and runs with no network access (isolation).
library;

/// A text field the keyboard is currently editing.
class TypedField {
  const TypedField({required this.name, required this.secureField});

  /// A human label for the field (e.g. "banking password").
  final String name;

  /// Whether the field is a secure/password field (IME should not persist it).
  final bool secureField;
}

/// The outcome of feeding a sequence of keystrokes to the keyboard.
class InterceptionResult {
  const InterceptionResult({
    required this.field,
    required this.captured,
    required this.exfiltrated,
    required this.sensitiveLeaked,
    this.note,
  });

  final TypedField field;

  /// The keystrokes logged locally by the keyboard.
  final String captured;

  /// The keystrokes transmitted off-device to the attacker sink.
  final String exfiltrated;

  /// True when a SECURE field's content was captured/exfiltrated - the hit.
  final bool sensitiveLeaked;

  /// Explanation (secure path).
  final String? note;
}

class ImeKeyboard {
  ImeKeyboard({required this.hasNetworkAccess});

  /// Whether the keyboard extension has "Allow Full Access" / network egress.
  final bool hasNetworkAccess;

  /// The local keylog (what the IME persisted).
  final List<String> keylog = <String>[];

  /// The attacker-controlled exfiltration sink (what left the device).
  final List<String> exfilSink = <String>[];

  /// A realistic secure field: the victim's banking password.
  static const TypedField passwordField = TypedField(
    name: 'banking password',
    secureField: true,
  );

  /// A non-secure field: a search box.
  static const TypedField searchField = TypedField(
    name: 'search query',
    secureField: false,
  );

  /// The sensitive value typed into the secure field.
  static const String secret = 'Hunter2!-OTP-448213';

  /// The attacker's beacon endpoint (never actually contacted - simulation).
  static const String exfilEndpoint = 'https://mitm.evil.example/keys';

  /// VULN: log and exfiltrate every key for every field. The keyboard makes no
  /// distinction for secure fields and, having network access, beacons the
  /// captured text to the attacker.
  InterceptionResult onKey(TypedField field, String text) {
    for (final ch in text.split('')) {
      keylog.add(ch);
      if (hasNetworkAccess) exfilSink.add(ch);
    }
    return InterceptionResult(
      field: field,
      captured: keylog.join(),
      exfiltrated: exfilSink.join(),
      sensitiveLeaked:
          field.secureField && (keylog.isNotEmpty || exfilSink.isNotEmpty),
    );
  }

  /// SECURE contrast: never persist or transmit keystrokes typed into a secure
  /// field, and run WITHOUT network access (isolation) so nothing can be
  /// exfiltrated even for non-secure input.
  InterceptionResult onKeySafe(TypedField field, String text) {
    if (field.secureField) {
      return InterceptionResult(
        field: field,
        captured: keylog.join(),
        exfiltrated: exfilSink.join(),
        sensitiveLeaked: false,
        note: 'secure field: input not logged and not transmitted',
      );
    }
    for (final ch in text.split('')) {
      keylog.add(ch); // local buffer only; still no network egress.
    }
    return InterceptionResult(
      field: field,
      captured: keylog.join(),
      exfiltrated: exfilSink.join(), // stays empty: isolated, no network.
      sensitiveLeaked: false,
      note: 'non-secure field buffered locally; keyboard is network-isolated',
    );
  }
}
