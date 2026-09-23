/// Invisible / Unicode prompt-injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-77 / CWE-176, OWASP LLM01): instructions are
/// smuggled into benign-looking text using zero-width characters (U+200B/
/// U+200C/U+FEFF) and an RTL override (U+202E). The app's [sanitize] only trims
/// and collapses ASCII whitespace - it does not strip these characters - so the
/// hidden instruction survives sanitization and reaches the model verbatim.
///
/// Deterministic + offline so a test can assert the hidden instruction is not
/// stripped and is still present after "sanitization".
class UnicodePromptInjection {
  UnicodePromptInjection._();

  static const String zeroWidthSpace = '\u200B';
  static const String zeroWidthNonJoiner = '\u200C';
  static const String zeroWidthNoBreakSpace = '\uFEFF'; // BOM / ZWNBSP
  static const String rtlOverride = '\u202E';

  static final List<String> _invisibles = [
    zeroWidthSpace,
    zeroWidthNonJoiner,
    zeroWidthNoBreakSpace,
    rtlOverride,
  ];

  /// Embeds [instruction] invisibly inside [visible] by appending it wrapped in
  /// zero-width delimiters and an RTL override. The instruction text itself is
  /// left intact (so a model reading the raw bytes still parses it), but the
  /// surrounding zero-width / RTL-override markers make it render as (near)
  /// nothing to a human reviewer.
  static String hideInstruction(String visible, String instruction) {
    // Sandwich the intact instruction between invisible markers. The markers
    // are what a correct sanitizer must strip; the app's sanitizer does not.
    return '$visible'
        '$zeroWidthSpace$zeroWidthNonJoiner$rtlOverride'
        '$instruction'
        '$zeroWidthNoBreakSpace$zeroWidthSpace';
  }

  /// True if [text] contains any of the smuggling characters.
  static bool containsHidden(String text) => _invisibles.any(text.contains);

  /// Recovers the hidden instruction (strips the invisible markers to reveal
  /// what was smuggled) - used by the UI to show what the model actually saw.
  static String revealHidden(String text) {
    var out = text;
    for (final ch in _invisibles) {
      out = out.replaceAll(ch, '');
    }
    return out;
  }

  /// The app's "sanitizer".
  ///
  /// VULN: it only trims/collapses ASCII whitespace and never removes the
  /// zero-width / RTL-override characters, so the hidden instruction passes
  /// straight through to the model.
  static String sanitize(String text) =>
      text.trim().replaceAll(RegExp(r'[ \t]+'), ' ');

  /// What a correct sanitizer would do: strip all invisible/formatting
  /// control characters before the text is trusted.
  static String secureSanitize(String text) {
    var out = text;
    for (final ch in _invisibles) {
      out = out.replaceAll(ch, '');
    }
    return out.trim().replaceAll(RegExp(r'[ \t]+'), ' ');
  }
}
