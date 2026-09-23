/// Credential-Provider Release Authorization helper.
///
/// INTENTIONALLY VULNERABLE (CWE-287 / CWE-346 / CWE-863): a credential-provider
/// / password-manager extension releases a stored credential / passkey
/// assertion WITHOUT validating the calling app's identity, the relying-party
/// (rpId) binding, or the user-verification (UV) state. A spoofed calling app
/// (or an rpId mismatch) therefore extracts a credential it should never
/// receive, and the API even allows enumeration of stored credentials (Apple /
/// Android credential-provider release-boundary class).
///
/// This is an offline + deterministic SIMULATION. [CredentialProviderService]
/// holds credentials keyed by relying-party (rpId) plus the calling-app package
/// bound to that rpId (digital-asset-links / associated-domains style). The
/// vulnerable [getCredential] releases on rpId/calling-app MISMATCH or with UV
/// not performed, and allows enumeration; the secure [getCredentialSafe]
/// validates the binding, requires UV, and refuses enumeration.
library;

/// A stored credential / passkey for a relying party.
class StoredCredential {
  const StoredCredential({
    required this.rpId,
    required this.userName,
    required this.secret,
    required this.boundCallingApp,
  });

  /// The relying party (e.g. "bank.example").
  final String rpId;

  final String userName;

  /// The releasable secret (passkey assertion / password).
  final String secret;

  /// The app package that is legitimately associated with [rpId]
  /// (asset-links / associated-domains).
  final String boundCallingApp;
}

/// The outcome of a credential-release request.
class ReleaseResult {
  const ReleaseResult({
    required this.released,
    required this.rpId,
    required this.callingApp,
    required this.spoofedRelease,
    this.secret,
    this.denyReason,
  });

  /// Whether a credential was handed to the caller.
  final bool released;

  final String rpId;
  final String callingApp;

  /// True when a credential was released to a caller not bound to the rpId, or
  /// without user verification - the release-boundary hit.
  final bool spoofedRelease;

  /// The released secret (vuln path).
  final String? secret;

  /// Why the secure service refused.
  final String? denyReason;
}

class CredentialProviderService {
  CredentialProviderService(Iterable<StoredCredential> seed)
    : _creds = {for (final c in seed) c.rpId: c};

  final Map<String, StoredCredential> _creds;

  /// The relying party whose credential is contested.
  static const String bankRpId = 'bank.example';

  /// The app legitimately bound to the bank rpId.
  static const String legitApp = 'com.bank.example';

  /// A malicious app spoofing the calling identity.
  static const String spoofedApp = 'com.evil.phish';

  factory CredentialProviderService.seeded() {
    return CredentialProviderService(const [
      StoredCredential(
        rpId: bankRpId,
        userName: 'alice',
        secret: 'passkey-assertion:sig-bank-4f2a',
        boundCallingApp: legitApp,
      ),
      StoredCredential(
        rpId: 'mail.example',
        userName: 'alice',
        secret: 'passkey-assertion:sig-mail-9c1d',
        boundCallingApp: 'com.mail.example',
      ),
    ]);
  }

  /// Enumerate every stored rpId (vuln path exposes this to any caller).
  List<String> enumerateRpIds() => _creds.keys.toList();

  /// VULN: release the credential for [rpId] to [callingApp] with no validation
  /// of the calling-app binding, the rpId, or the UV state.
  ReleaseResult getCredential(
    String rpId,
    String callingApp, {
    bool userVerified = false,
  }) {
    final cred = _creds[rpId];
    if (cred == null) {
      return ReleaseResult(
        released: false,
        rpId: rpId,
        callingApp: callingApp,
        spoofedRelease: false,
        denyReason: 'no credential for $rpId',
      );
    }
    // Released regardless of who is asking or whether UV happened.
    return ReleaseResult(
      released: true,
      rpId: rpId,
      callingApp: callingApp,
      spoofedRelease: cred.boundCallingApp != callingApp || !userVerified,
      secret: cred.secret,
    );
  }

  /// SECURE contrast: the calling app must be the one bound to the rpId
  /// (asset-links / associated-domains), user-verification must have been
  /// performed, and enumeration is refused (a caller only ever probes a single
  /// rpId it can prove association with).
  ReleaseResult getCredentialSafe(
    String rpId,
    String callingApp, {
    bool userVerified = false,
  }) {
    final cred = _creds[rpId];
    if (cred == null) {
      return ReleaseResult(
        released: false,
        rpId: rpId,
        callingApp: callingApp,
        spoofedRelease: false,
        denyReason: 'no credential for $rpId',
      );
    }
    if (cred.boundCallingApp != callingApp) {
      return ReleaseResult(
        released: false,
        rpId: rpId,
        callingApp: callingApp,
        spoofedRelease: false,
        denyReason:
            'calling app $callingApp is not bound to $rpId '
            '(asset-links mismatch)',
      );
    }
    if (!userVerified) {
      return ReleaseResult(
        released: false,
        rpId: rpId,
        callingApp: callingApp,
        spoofedRelease: false,
        denyReason: 'user verification not performed',
      );
    }
    return ReleaseResult(
      released: true,
      rpId: rpId,
      callingApp: callingApp,
      spoofedRelease: false,
      secret: cred.secret,
    );
  }
}
