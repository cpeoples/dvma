/// URI Permission / GRANT_URI_PERMISSIONS abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-266 / CWE-668 / CWE-927): the app receives an
/// Intent from an untrusted caller and forwards/redirects it onward WITHOUT
/// stripping the grant flags. Because the forwarded Intent still carries
/// FLAG_GRANT_READ/WRITE_URI_PERMISSION pointing at a PRIVATE `content://` URI
/// the app has access to, the transitive grant reaches the untrusted target -
/// so a malicious app is handed read/write access to files it should never be
/// able to reach (Pixel CVE-2024-27222 Intent-redirect + grant-URI class).
///
/// This is an offline + deterministic simulation. [GrantUriBroker] models the
/// forwarding step and returns which package ended up holding a grant on the
/// private URI. Tests can assert the malicious app gains access on the vuln
/// path and is denied on the secure path (grant flags stripped + target
/// allowlist).
library;

/// Grant flags that can ride along on an Intent.
class UriGrantFlags {
  const UriGrantFlags({this.read = false, this.write = false});

  final bool read;
  final bool write;

  bool get any => read || write;

  @override
  String toString() {
    final parts = <String>[
      if (read) 'FLAG_GRANT_READ_URI_PERMISSION',
      if (write) 'FLAG_GRANT_WRITE_URI_PERMISSION',
    ];
    return parts.isEmpty ? '(none)' : parts.join(' | ');
  }
}

/// A forwarded/redirected Intent.
class ForwardedIntent {
  const ForwardedIntent({
    required this.callerPackage,
    required this.targetPackage,
    required this.dataUri,
    required this.flags,
  });

  /// The untrusted app that originally sent the Intent to us.
  final String callerPackage;

  /// The component the Intent is (re)directed to - here, attacker-chosen.
  final String targetPackage;

  /// The private content:// URI referenced by the Intent.
  final String dataUri;

  /// The grant flags riding on the Intent.
  final UriGrantFlags flags;
}

/// The result of the app forwarding an Intent onward.
class GrantOutcome {
  const GrantOutcome({
    required this.grantedTo,
    required this.uri,
    required this.effectiveFlags,
    required this.blocked,
    this.blockReason,
  });

  /// The package that ended up holding a grant on [uri] (null if none).
  final String? grantedTo;

  /// The private URI in question.
  final String uri;

  /// The flags that were actually forwarded.
  final UriGrantFlags effectiveFlags;

  /// Whether the redirect was refused before any grant leaked.
  final bool blocked;

  final String? blockReason;

  /// True when an UNTRUSTED package was transitively granted access.
  bool get leakedToAttacker => !blocked && grantedTo != null;
}

class GrantUriBroker {
  const GrantUriBroker._();

  /// A private URI the app is allowed to read, but must never re-share.
  static const String privateUri =
      'content://com.dvma.app.provider/private/patient_records.db';

  /// Packages the app trusts to receive forwarded content grants.
  static const Set<String> _trustedTargets = {
    'com.dvma.app',
    'com.dvma.companion',
  };

  /// VULN: forward the caller's Intent onward verbatim. The grant flags are
  /// not stripped and the target is not checked, so the private-URI grant is
  /// transitively handed to whatever package the (untrusted) caller named.
  static GrantOutcome forward(ForwardedIntent intent) {
    return GrantOutcome(
      grantedTo: intent.flags.any ? intent.targetPackage : null,
      uri: intent.dataUri,
      effectiveFlags: intent.flags,
      blocked: false,
    );
  }

  /// SECURE contrast: strip inbound grant flags on redirect and only forward to
  /// a trusted target. An untrusted app never obtains a grant on the private
  /// URI.
  static GrantOutcome forwardSafe(ForwardedIntent intent) {
    if (!_trustedTargets.contains(intent.targetPackage)) {
      return GrantOutcome(
        grantedTo: null,
        uri: intent.dataUri,
        effectiveFlags: const UriGrantFlags(),
        blocked: true,
        blockReason:
            'target ${intent.targetPackage} not on allowlist; '
            'grant flags stripped on redirect',
      );
    }
    // Even for a trusted target, re-grant explicitly rather than forwarding the
    // caller-supplied flags; here we simply pass through for the trusted case.
    return GrantOutcome(
      grantedTo: intent.targetPackage,
      uri: intent.dataUri,
      effectiveFlags: intent.flags,
      blocked: false,
    );
  }
}
