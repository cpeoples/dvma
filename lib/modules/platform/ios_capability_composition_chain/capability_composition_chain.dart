library;

/// iOS capability-composition chain.
///
/// The vulnerability is the CHAIN, not any one API. A Universal Link resolves
/// to an App Intent, whose `perform()` reads its parameter as a security-scoped
/// file reference, resolves a persisted bookmark, and reads + exports Contacts.
/// Each hop inherits trust from the previous one rather than re-authorizing the
/// untrusted link, so a crafted link drives a full contacts export with no user
/// authorization - even though matching a link, running an App Intent,
/// resolving a bookmark, and reading Contacts are each individually legitimate
/// (CWE-441 confused deputy, CWE-862 missing authorization, CWE-668 exposure).

/// A single hop in the iOS chain, recorded for evidence.
class IosChainHop {
  const IosChainHop(this.name, {this.reauthorized = false});

  final String name;

  /// Whether this hop required fresh user authorization for the untrusted link
  /// before proceeding (the fix).
  final bool reauthorized;
}

class IosChainResult {
  const IosChainResult({
    required this.hops,
    required this.contactsExported,
    required this.userAuthorized,
    required this.exportedCount,
    this.denyReason,
  });

  final List<IosChainHop> hops;

  /// Whether the privileged sink (contacts export) ran.
  final bool contactsExported;

  /// Whether fresh user authorization gated the protected-data action.
  final bool userAuthorized;

  final int exportedCount;
  final String? denyReason;

  /// The composed vulnerability fired: a crafted link exported contacts with
  /// no user authorization.
  bool get chainExploited => contactsExported && !userAuthorized;
}

class IosCapabilityCompositionChain {
  /// A crafted Universal Link that resolves to the export App Intent.
  static const String craftedLink =
      'https://app.dvma.example/intent/exportContacts?scope=all';

  /// A benign link that the genuine user flow would open.
  static const String genuineLink =
      'https://app.dvma.example/contacts/view?id=self';

  /// Contact count reported by the offline-fallback model (the real device
  /// path drives the exported App Intent natively via `AppIntentBridge`).
  static const int contactCount = 342;

  bool _isExportIntent(String link) => link.contains('exportContacts');

  /// VULN: walk the chain. The App Intent inherits trust from the link, reads
  /// the security-scoped bookmark, and exports Contacts with no fresh
  /// authorization for the protected-data action.
  IosChainResult run(String link) {
    final export = _isExportIntent(link);
    final hops = <IosChainHop>[
      const IosChainHop('Universal Link matched associated domain'),
      const IosChainHop('App Intent perform() (trusts link parameter)'),
      const IosChainHop('security-scoped bookmark resolved'),
      const IosChainHop('Contacts read + exported'),
    ];
    return IosChainResult(
      hops: hops,
      contactsExported: export,
      userAuthorized: false,
      exportedCount: export ? contactCount : 0,
    );
  }

  /// SECURE: treat the link as untrusted; the App Intent requires fresh user
  /// authorization for the destructive/protected-data action and re-validates
  /// the bookmark scope before the sink. A crafted link is refused.
  IosChainResult runSafe(String link, {bool userApproved = false}) {
    final export = _isExportIntent(link);
    final hops = <IosChainHop>[
      const IosChainHop('Universal Link treated as untrusted input'),
      const IosChainHop(
        'App Intent perform() requires fresh authorization',
        reauthorized: true,
      ),
      const IosChainHop('bookmark scope re-validated'),
      const IosChainHop('Contacts export gated on user consent'),
    ];
    if (export && !userApproved) {
      return IosChainResult(
        hops: hops,
        contactsExported: false,
        userAuthorized: true,
        exportedCount: 0,
        denyReason:
            'protected-data export from an unauthenticated Universal '
            'Link requires explicit user authorization; the link cannot '
            'inherit full-app trust across the chain',
      );
    }
    return IosChainResult(
      hops: hops,
      contactsExported: export,
      userAuthorized: true,
      exportedCount: export ? contactCount : 0,
    );
  }
}
