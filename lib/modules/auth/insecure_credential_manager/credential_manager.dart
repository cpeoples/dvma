/// Insecure Credential Manager / Autofill integration.
///
/// INTENTIONALLY VULNERABLE (CWE-522 / CWE-524): this simulates misuse of the
/// Android Credential Manager / iOS AutoFill association model. A password
/// credential should only be offered to an origin that is cryptographically
/// associated with the app via Digital Asset Links (Android `assetlinks.json`)
/// or an Apple App Site Association (AASA) file. Here the manager:
///
///  * [associate]s a credential with ANY requested domain, skipping the
///    asset-links / AASA verification entirely, and
///  * [autofill]s the secret into a field even when that field is marked
///    insecure (plaintext, not `secureTextEntry`, keyboard-cacheable).
///
/// Deterministic + offline so a test can assert an unverified domain is
/// accepted and autofill proceeds into an insecure field.
class InsecureCredentialManager {
  final List<StoredCredential> _store = [];

  List<StoredCredential> get store => List.unmodifiable(_store);

  /// Domains the app has actually verified via asset-links / AASA. In this demo
  /// only the genuine origin is verified; everything else is unverified.
  static const Set<String> verifiedDomains = {'dvma.training'};

  /// VULN: associates the credential with [domain] without checking whether the
  /// domain is verified. A phishing origin (e.g. `dvma-training.attacker.com`)
  /// is accepted just like the real one.
  bool associate({
    required String domain,
    required String username,
    required String password,
  }) {
    _store.add(
      StoredCredential(domain: domain, username: username, password: password),
    );
    return true; // always accepted - no verification
  }

  /// What a secure Credential Manager integration would decide: only associate
  /// with domains proven via Digital Asset Links / AASA.
  bool secureWouldAssociate(String domain) => verifiedDomains.contains(domain);

  /// VULN: autofills the stored secret into a field described by [fieldSecure]
  /// even when the field is insecure (plaintext / cacheable), returning the
  /// credential that would be typed in.
  StoredCredential? autofill({
    required String domain,
    required bool fieldSecure,
  }) {
    // No check that the field is secure, and no re-verification of the domain.
    for (final c in _store) {
      if (c.domain == domain) return c;
    }
    return null;
  }
}

/// A stored username/password credential.
class StoredCredential {
  StoredCredential({
    required this.domain,
    required this.username,
    required this.password,
  });

  final String domain;
  final String username;
  final String password;

  @override
  String toString() => '$username:$password @ $domain';
}
