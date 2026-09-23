/// Protected-Data Access via Input-Validation Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-863 / CWE-180): untrusted input flows
/// through a security-sensitive normalizer whose RESULT authorizes access to a
/// protected resource. Because the vulnerable path either normalizes AFTER the
/// deny check or checks a raw form naively, an encoded / `..` / mixed-case /
/// unicode variant of a PROTECTED identifier slips past the deny rule and the
/// resource is returned. The flaw is the authorization decision made on
/// insufficiently-validated input - not the parser itself (the Apple
/// protected-data-via-input-sanitization CVE-2026-43714 class).
///
/// This is an offline + deterministic SIMULATION. [ResourceAuthorizer] holds
/// protected records keyed by a CANONICAL id and a deny-set of protected ids.
/// The vulnerable [authorize] runs a naive deny check on the RAW input and only
/// then canonicalizes for lookup, so `%2e`/`..`/case/unicode variants evade the
/// deny rule. The secure [authorizeSafe] canonicalizes FIRST and checks the
/// canonical form against the deny-set.
library;

import 'package:shared_preferences/shared_preferences.dart';

/// The outcome of an authorization attempt for some input identifier.
class AuthzResult {
  const AuthzResult({
    required this.rawInput,
    required this.canonical,
    required this.granted,
    required this.protectedLeaked,
    this.data,
    this.denyReason,
  });

  /// The raw, untrusted identifier as supplied.
  final String rawInput;

  /// The canonical form the authorizer resolved it to.
  final String canonical;

  /// Whether access was granted and data returned.
  final bool granted;

  /// True when a PROTECTED resource was returned to an unauthorized caller via
  /// an input-validation confusion - the hit.
  final bool protectedLeaked;

  /// The protected data returned (null when refused).
  final String? data;

  /// Why the safe authorizer refused.
  final String? denyReason;
}

/// An in-memory model of a resource authorizer keyed by a canonical id.
class ResourceAuthorizer {
  ResourceAuthorizer(Map<String, String> records)
    : _records = Map<String, String>.from(records);

  final Map<String, String> _records;

  /// The canonical id of the protected resource.
  static const String protectedId = 'users/admin/ssn';

  /// The protected data behind it.
  static const String protectedData = 'SSN 512-88-0417; DOB 1984-02-11';

  /// A public resource anyone may read.
  static const String publicId = 'users/self/theme';

  /// An encoded / traversal / case variant of [protectedId] that a naive deny
  /// check on the RAW input fails to recognize but which canonicalizes back to
  /// the protected id.
  static const String evasiveInput = 'users/./admin/%2E%2E/admin/SSN';

  factory ResourceAuthorizer.seeded() {
    return ResourceAuthorizer({
      protectedId: protectedData,
      publicId: 'theme=dark',
    });
  }

  /// The deny-set of protected canonical ids that require authorization.
  static const Set<String> _denySet = {protectedId};

  /// Canonicalize an identifier: percent-decode, lowercase, collapse `.`/`..`
  /// segments and redundant separators. This is the STRICT canonicalizer the
  /// secure path applies BEFORE any decision.
  static String canonicalize(String input) {
    var s = input;
    // Percent-decode (repeatedly, to defeat double-encoding).
    for (var i = 0; i < 3; i++) {
      final decoded = _percentDecode(s);
      if (decoded == s) break;
      s = decoded;
    }
    s = s.toLowerCase();
    final segments = <String>[];
    for (final seg in s.split('/')) {
      if (seg.isEmpty || seg == '.') continue;
      if (seg == '..') {
        if (segments.isNotEmpty) segments.removeLast();
      } else {
        segments.add(seg);
      }
    }
    return segments.join('/');
  }

  static String _percentDecode(String s) {
    final b = StringBuffer();
    for (var i = 0; i < s.length; i++) {
      if (s[i] == '%' && i + 2 < s.length) {
        final hex = s.substring(i + 1, i + 3);
        final code = int.tryParse(hex, radix: 16);
        if (code != null) {
          b.writeCharCode(code);
          i += 2;
          continue;
        }
      }
      b.write(s[i]);
    }
    return b.toString();
  }

  /// VULN: run the deny check on the RAW input (a naive equality / prefix
  /// test), then canonicalize only for the LOOKUP. An encoded/traversal/case
  /// variant is not literally equal to the protected id, so it slips past the
  /// deny rule, yet canonicalizes to the protected id and returns its data.
  AuthzResult authorize(String input) {
    // Naive deny: only blocks the exact literal protected id.
    final denied = _denySet.contains(input);
    final canonical = canonicalize(input);
    if (denied) {
      return AuthzResult(
        rawInput: input,
        canonical: canonical,
        granted: false,
        protectedLeaked: false,
        denyReason: 'raw input matched deny-set',
      );
    }
    // Lookup uses the canonical form -> resolves to the protected record.
    final data = _records[canonical];
    final isProtected = _denySet.contains(canonical);
    return AuthzResult(
      rawInput: input,
      canonical: canonical,
      granted: data != null,
      protectedLeaked: data != null && isProtected,
      data: data,
    );
  }

  /// SECURE contrast: canonicalize FIRST with the strict canonicalizer, then
  /// check the CANONICAL form against the deny-set. The evasive variant
  /// resolves to the protected id and is refused.
  AuthzResult authorizeSafe(String input) {
    final canonical = canonicalize(input);
    if (_denySet.contains(canonical)) {
      return AuthzResult(
        rawInput: input,
        canonical: canonical,
        granted: false,
        protectedLeaked: false,
        denyReason:
            'canonical form "$canonical" is a protected resource; '
            'authorization required',
      );
    }
    final data = _records[canonical];
    return AuthzResult(
      rawInput: input,
      canonical: canonical,
      granted: data != null,
      protectedLeaked: false,
      data: data,
    );
  }

  /// SharedPreferences key prefix the protected records are written under.
  static const String _storeKeyPrefix = 'resource:';

  /// Seed a real on-disk record store (SharedPreferences), writing the
  /// protected + public records keyed by their canonical ids. Returns the
  /// backing key names actually written, so a caller can point the harness at
  /// them. The protected record now lives on disk, not just in memory.
  static Future<List<String>> seedStore() async {
    final prefs = await SharedPreferences.getInstance();
    final writes = <String, String>{
      protectedId: protectedData,
      publicId: 'theme=dark',
    };
    final keys = <String>[];
    for (final entry in writes.entries) {
      final key = '$_storeKeyPrefix${entry.key}';
      await prefs.setString(key, entry.value);
      keys.add(key);
    }
    return keys;
  }

  /// VULN (real): the naive deny check runs on the RAW input, then the LOOKUP
  /// reads the record from the real SharedPreferences store using the canonical
  /// form. An encoded/traversal/case variant evades the deny rule yet
  /// canonicalizes to the protected id and reads the protected record off disk.
  static Future<AuthzResult> authorizeFromStore(String input) async {
    final prefs = await SharedPreferences.getInstance();
    // Naive deny: only blocks the exact literal protected id.
    final denied = _denySet.contains(input);
    final canonical = canonicalize(input);
    if (denied) {
      return AuthzResult(
        rawInput: input,
        canonical: canonical,
        granted: false,
        protectedLeaked: false,
        denyReason: 'raw input matched deny-set',
      );
    }
    // Lookup hits the real on-disk store via the canonical form.
    final data = prefs.getString('$_storeKeyPrefix$canonical');
    final isProtected = _denySet.contains(canonical);
    return AuthzResult(
      rawInput: input,
      canonical: canonical,
      granted: data != null,
      protectedLeaked: data != null && isProtected,
      data: data,
    );
  }

  /// SECURE contrast (real store): canonicalize FIRST, deny-check the canonical
  /// form, and only then read the on-disk record. The evasive variant resolves
  /// to the protected id and is refused before any read.
  static Future<AuthzResult> authorizeSafeFromStore(String input) async {
    final canonical = canonicalize(input);
    if (_denySet.contains(canonical)) {
      return AuthzResult(
        rawInput: input,
        canonical: canonical,
        granted: false,
        protectedLeaked: false,
        denyReason:
            'canonical form "$canonical" is a protected resource; '
            'authorization required',
      );
    }
    final prefs = await SharedPreferences.getInstance();
    final data = prefs.getString('$_storeKeyPrefix$canonical');
    return AuthzResult(
      rawInput: input,
      canonical: canonical,
      granted: data != null,
      protectedLeaked: false,
      data: data,
    );
  }
}
