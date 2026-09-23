/// ClipData URI-Grant Leakage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 exposure of sensitive information /
/// CWE-668 exposure of resource to wrong sphere / CWE-927 use of implicit
/// intent for sensitive communication, Android ClipData-grant class): the app
/// attaches a PRIVATE `content://` URI (backed by its own provider) to an
/// Intent's `ClipData` together with `FLAG_GRANT_READ_URI_PERMISSION` and fires
/// the intent to an IMPLICIT / untrusted target. Android propagates the read
/// grant to every URI carried in the ClipData - not just the intent's data
/// field - so whichever app catches the implicit intent silently inherits a
/// read capability over the app's private provider data. The grant rides on the
/// ClipData rather than the visible data URI, which makes it easy to miss. This
/// leaks a CAPABILITY (durable read access), not merely a copied value.
///
/// This is an offline + deterministic SIMULATION. [ClipDataForwarder] builds an
/// intent with a data field, a ClipData URI list, and grant flags, then
/// "sends" it to either an explicit pinned package or an implicit action any
/// resolver can catch. The vulnerable [send] forwards the grant to a
/// co-resident attacker resolver, which can then read the private URI. The
/// secure [sendSafe] uses an explicit intent to a pinned package and never
/// attaches read grants to ClipData bound for an untrusted resolver.
library;

/// A minimal intent model: an action, an optional explicit target, a data
/// field, a ClipData URI list, and grant flags.
class ForwardedIntent {
  const ForwardedIntent({
    required this.action,
    required this.explicitPackage,
    required this.dataUri,
    required this.clipUris,
    required this.grantRead,
  });

  /// The intent action (e.g. `android.intent.action.SEND`).
  final String action;

  /// The pinned target package for an explicit intent, or null when implicit.
  final String? explicitPackage;

  /// The visible data URI (often benign / public).
  final String? dataUri;

  /// URIs carried on the ClipData - the grant silently rides on these.
  final List<String> clipUris;

  /// Whether `FLAG_GRANT_READ_URI_PERMISSION` is set.
  final bool grantRead;

  bool get isImplicit => explicitPackage == null;
}

/// The outcome of forwarding an intent to a resolver.
class ClipForwardResult {
  const ClipForwardResult({
    required this.recipientPackage,
    required this.capabilityForwarded,
    required this.recipientCanRead,
    required this.leakedUris,
    this.leakedData,
    this.denyReason,
  });

  /// The app that received the intent.
  final String recipientPackage;

  /// Whether a read capability for the app's private provider was forwarded.
  final bool capabilityForwarded;

  /// Whether the recipient can actually read the private URI via the grant.
  final bool recipientCanRead;

  /// The private URIs whose read capability leaked via ClipData.
  final List<String> leakedUris;

  /// The private provider bytes the recipient read through the leaked grant.
  final String? leakedData;

  /// Why the secure path declined to forward a grant.
  final String? denyReason;
}

class ClipDataForwarder {
  /// A PRIVATE URI backed by the app's own (non-exported) provider.
  static const String privateContentUri =
      'content://com.dvma.app.vault/notes/personal';

  /// The private provider bytes the grant exposes.
  static const String privateData =
      'note: bank PIN 4471; recovery phrase orbit-cactus-velvet-9';

  /// A benign, public URI safe to share via an implicit intent.
  static const String publicShareUri = 'content://com.dvma.app.share/thumb/9';

  /// A co-resident third-party app that catches the implicit SEND intent.
  static const String attackerResolverPackage = 'com.evil.clipcatcher';

  /// The explicit, pinned first-party target used by the secure path.
  static const String trustedTargetPackage = 'com.dvma.app.viewer';

  /// Providers this app owns. A grant on any of these leaks its own data.
  static const Set<String> ownedProviderPrefixes = {
    'content://com.dvma.app.vault/',
  };

  bool _isPrivateOwnedUri(String uri) =>
      ownedProviderPrefixes.any(uri.startsWith);

  /// The resolver that catches an implicit intent (attacker wins) vs the pinned
  /// explicit package.
  String _resolveRecipient(ForwardedIntent intent) =>
      intent.explicitPackage ?? attackerResolverPackage;

  /// Read the private provider bytes for any leaked URI the recipient holds a
  /// grant for.
  String? _readLeaked(List<String> grantedUris) {
    for (final uri in grantedUris) {
      if (_isPrivateOwnedUri(uri)) return privateData;
    }
    return null;
  }

  /// VULN: fire an IMPLICIT intent with the private URI on the ClipData and
  /// `FLAG_GRANT_READ_URI_PERMISSION` set. Android forwards the read grant for
  /// every ClipData URI to whichever app catches the intent - here a
  /// co-resident attacker resolver that can now read the private provider.
  ClipForwardResult send(ForwardedIntent intent) {
    final recipient = _resolveRecipient(intent);
    final grantedUris = <String>[
      if (intent.dataUri != null) intent.dataUri!,
      ...intent.clipUris,
    ];
    final leakedUris = intent.grantRead
        ? grantedUris.where(_isPrivateOwnedUri).toList()
        : const <String>[];
    final canRead = leakedUris.isNotEmpty;
    return ClipForwardResult(
      recipientPackage: recipient,
      capabilityForwarded: canRead,
      recipientCanRead: canRead,
      leakedUris: leakedUris,
      leakedData: canRead ? _readLeaked(grantedUris) : null,
    );
  }

  /// SECURE contrast: build an EXPLICIT intent to a pinned first-party package
  /// and never attach a read grant for a private/owned URI on ClipData bound
  /// for an untrusted resolver. Only a benign public URI is ever shared
  /// implicitly, and without a grant on private data.
  ClipForwardResult sendSafe(ForwardedIntent intent) {
    final grantedUris = <String>[
      if (intent.dataUri != null) intent.dataUri!,
      ...intent.clipUris,
    ];
    final privateInClip = grantedUris.any(_isPrivateOwnedUri);
    if (intent.isImplicit && intent.grantRead && privateInClip) {
      return ClipForwardResult(
        recipientPackage: attackerResolverPackage,
        capabilityForwarded: false,
        recipientCanRead: false,
        leakedUris: const [],
        denyReason:
            'refused to forward read grant for private provider URI '
            'to an implicit/untrusted resolver - send explicit + no grant',
      );
    }
    return ClipForwardResult(
      recipientPackage: intent.explicitPackage ?? trustedTargetPackage,
      capabilityForwarded: false,
      recipientCanRead: false,
      leakedUris: const [],
    );
  }
}
