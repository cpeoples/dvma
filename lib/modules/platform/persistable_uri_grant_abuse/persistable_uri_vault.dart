/// Persistent URI-Grant Capability Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-284 improper access control / CWE-266
/// incorrect privilege assignment / CWE-668 exposure of resource to wrong
/// sphere, Android persistable-grant class): an exported component receives an
/// attacker-controlled `content://` URI carrying
/// `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` and calls
/// `ContentResolver.takePersistableUriPermission()`. That converts a one-shot,
/// intent-scoped grant into a LONG-LIVED capability that outlives the delivering
/// intent and survives normal revocation. Because the URI points at the
/// ATTACKER'S provider, the attacker can later swap the data returned for the
/// same URI - so a transient "read this once" becomes durable, mutable,
/// revocation-resistant access. The distinguishing bug is the PERSISTENCE, not
/// the grant itself.
///
/// This is an offline + deterministic SIMULATION. [PersistableUriVault] models
/// the receiving app's persisted-grant set plus an attacker-controlled provider
/// whose backing data can change. The vulnerable [receiveGrant] persists the
/// grant, so [readLater] still succeeds after the original intent ended and
/// returns attacker-swapped data. The secure [receiveGrantSafe] refuses to
/// persist grants for untrusted URIs and re-validates the provider on each use.
library;

/// A one-shot vs persistable URI grant arriving on an intent.
class UriGrant {
  const UriGrant({
    required this.uri,
    required this.providerAuthority,
    required this.persistable,
  });

  /// The `content://` URI whose read capability is being granted.
  final String uri;

  /// The authority (provider) that backs [uri]. For the attack this is the
  /// attacker's own provider, so it controls the bytes returned.
  final String providerAuthority;

  /// Whether the intent carried `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`.
  final bool persistable;
}

/// The outcome of receiving a grant and attempting a later read.
class PersistGrantResult {
  const PersistGrantResult({
    required this.uri,
    required this.persisted,
    required this.survivesRevocation,
    required this.dataSwapped,
    required this.readSucceeded,
    this.dataRead,
    this.denyReason,
  });

  /// The granted URI.
  final String uri;

  /// Whether the grant was durably persisted (took a persistable permission).
  final bool persisted;

  /// Whether the later read still worked after the intent ended / a revoke.
  final bool survivesRevocation;

  /// Whether the attacker provider returned different data on the later read.
  final bool dataSwapped;

  /// Whether the later read returned data at all.
  final bool readSucceeded;

  /// The bytes read on the later read (attacker-controlled when swapped).
  final String? dataRead;

  /// Why the secure path refused to persist / read.
  final String? denyReason;
}

class PersistableUriVault {
  /// The attacker's provider authority - it backs the granted URI and can swap
  /// the bytes it serves for the same URI at any time.
  static const String attackerAuthority = 'com.evil.docs.provider';

  /// The attacker-controlled URI delivered to the exported component.
  static const String attackerUri =
      'content://com.evil.docs.provider/report/42';

  /// Authorities the receiving app actually trusts to persist grants for.
  static const Set<String> trustedAuthorities = {'com.dvma.app.documents'};

  /// What the provider returns on the FIRST read (bait, looks benign).
  static const String initialData = 'invoice-2026-Q1.pdf (benign preview)';

  /// What the attacker provider serves on LATER reads once the grant persists.
  static const String swappedData =
      'session-cookie=SID-77af23; totp-seed=JBSWY3DPEHPK3PXP';

  /// Durable set of persisted URI grants (mirrors the persisted-permission
  /// list the platform keeps across process death and reboots).
  final Set<String> _persistedGrants = <String>{};

  /// Whether the delivering intent is still in scope. Once it ends, only
  /// PERSISTED grants remain usable.
  bool _intentInScope = true;

  /// Simulate the delivering intent ending and a subsequent explicit revoke of
  /// the transient grant. Persisted grants are unaffected - that is the bug.
  void endIntentAndRevokeTransient() {
    _intentInScope = false;
  }

  bool _canReadNow(String uri) =>
      _intentInScope || _persistedGrants.contains(uri);

  /// Read the URI through its backing provider. When the grant has persisted,
  /// the attacker provider serves swapped (sensitive-looking exfil) data.
  String _readThroughProvider(UriGrant grant) {
    // The attacker swaps bytes once the capability is durable.
    if (grant.providerAuthority == attackerAuthority &&
        _persistedGrants.contains(grant.uri)) {
      return swappedData;
    }
    return initialData;
  }

  /// VULN: unconditionally call `takePersistableUriPermission()` on the
  /// incoming grant, converting a transient read into a durable capability -
  /// even though the URI is backed by an untrusted (attacker) provider.
  PersistGrantResult receiveGrant(UriGrant grant) {
    if (grant.persistable) {
      _persistedGrants.add(grant.uri);
    }
    return PersistGrantResult(
      uri: grant.uri,
      persisted: _persistedGrants.contains(grant.uri),
      survivesRevocation: _persistedGrants.contains(grant.uri),
      dataSwapped: false,
      readSucceeded: true,
      dataRead: _readThroughProvider(grant),
    );
  }

  /// Attempt to read the URI later, after the delivering intent has ended and
  /// the transient grant was revoked. Success here proves durability.
  PersistGrantResult readLater(UriGrant grant) {
    if (!_canReadNow(grant.uri)) {
      return PersistGrantResult(
        uri: grant.uri,
        persisted: false,
        survivesRevocation: false,
        dataSwapped: false,
        readSucceeded: false,
        denyReason: 'grant not persisted - later read blocked',
      );
    }
    final data = _readThroughProvider(grant);
    return PersistGrantResult(
      uri: grant.uri,
      persisted: _persistedGrants.contains(grant.uri),
      survivesRevocation: _persistedGrants.contains(grant.uri),
      dataSwapped: data == swappedData,
      readSucceeded: true,
      dataRead: data,
    );
  }

  /// SECURE contrast: never take a persistable permission for a URI backed by
  /// an untrusted authority. Only trusted authorities may persist, and even
  /// then the provider is re-validated on every use (transient reads only for
  /// untrusted sources).
  PersistGrantResult receiveGrantSafe(UriGrant grant) {
    if (grant.persistable &&
        !trustedAuthorities.contains(grant.providerAuthority)) {
      return PersistGrantResult(
        uri: grant.uri,
        persisted: false,
        survivesRevocation: false,
        dataSwapped: false,
        readSucceeded: false,
        denyReason:
            'refused to persist grant for untrusted authority '
            '${grant.providerAuthority} - transient read only',
      );
    }
    if (grant.persistable) {
      _persistedGrants.add(grant.uri);
    }
    return PersistGrantResult(
      uri: grant.uri,
      persisted: _persistedGrants.contains(grant.uri),
      survivesRevocation: _persistedGrants.contains(grant.uri),
      dataSwapped: false,
      readSucceeded: true,
      dataRead: _readThroughProvider(grant),
    );
  }
}
