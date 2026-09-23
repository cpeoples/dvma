/// content:// URI -> ContentResolver Confused Deputy helper.
///
/// INTENTIONALLY VULNERABLE (CWE-441 / CWE-284 / CWE-668): the app accepts an
/// ATTACKER-SUPPLIED `content://` URI (e.g. from an intent extra) and reads it
/// through its own ContentResolver. Because the resolver runs with the APP's
/// identity/permissions, the app becomes a confused-deputy proxy for a
/// privileged provider the untrusted caller could never reach directly - with
/// no owner/permission validation on the URI (the Android DownloadProvider
/// CVE-2025-26417 class).
///
/// This is an offline + deterministic simulation. [ContentResolverProxy] holds
/// a set of in-memory providers keyed by authority, some marked app-private /
/// privileged (e.g. `content://com.dvma.private/tokens`). The vulnerable
/// [openUri] resolves ANY authority with the APP's privileges and returns the
/// data; the secure [openUriSafe] validates that the caller is allowed to reach
/// that authority (allowlisted authority + a granted read permission), refusing
/// the privileged read for an untrusted caller.
library;

/// A simulated content provider registered under an authority.
class ContentProvider {
  const ContentProvider({
    required this.authority,
    required this.data,
    this.privileged = false,
    this.requiredPermission,
  });

  /// The provider authority, e.g. `com.dvma.private`.
  final String authority;

  /// The data the provider would return for a read.
  final String data;

  /// Whether this provider is app-private / privileged (not meant to be
  /// reachable by arbitrary callers).
  final bool privileged;

  /// The permission a caller must have been GRANTED to read this provider.
  final String? requiredPermission;
}

/// The result of resolving a `content://` URI through the proxy.
class ResolveResult {
  const ResolveResult({
    required this.opened,
    required this.blocked,
    required this.caller,
    required this.uri,
    this.authority,
    this.data,
    this.privileged = false,
    this.denyReason,
  });

  /// Whether the read succeeded and data was returned.
  final bool opened;

  /// Whether the secure resolver refused (secure path).
  final bool blocked;

  /// The uid of the caller that supplied the URI.
  final int caller;

  /// The attacker-supplied `content://` URI.
  final String uri;

  /// The authority parsed out of the URI.
  final String? authority;

  /// The data returned to the caller (the leaked bytes on the vuln path).
  final String? data;

  /// Whether the resolved provider was a privileged / app-private one.
  final bool privileged;

  /// Why the secure resolver refused.
  final String? denyReason;

  /// True when the proxy handed a privileged provider's data to an untrusted
  /// caller - the confused-deputy hit.
  bool get confusedDeputy => opened && privileged;
}

/// An in-memory model of the app acting as a ContentResolver proxy.
class ContentResolverProxy {
  ContentResolverProxy(Iterable<ContentProvider> providers)
    : _providers = {for (final p in providers) p.authority: p};

  final Map<String, ContentProvider> _providers;

  /// The uid the APP itself runs as (its ContentResolver has these rights).
  static const int appUid = 10110;

  /// An untrusted co-resident caller that supplies the crafted URI.
  static const int attackerUid = 10250;

  /// The privileged, app-private authority holding secrets.
  static const String privateAuthority = 'com.dvma.private';

  /// The permission required to read the private provider.
  static const String privatePermission = 'com.dvma.permission.READ_TOKENS';

  /// A benign, publicly-shareable authority.
  static const String publicAuthority = 'com.dvma.public';

  /// The crafted URI an attacker hands the app to proxy on its behalf.
  static const String privilegedUri = 'content://com.dvma.private/tokens';

  /// A benign URI the app is genuinely meant to open.
  static const String benignUri = 'content://com.dvma.public/shared/report.txt';

  /// The secret bytes behind the privileged provider.
  static const String privateData =
      'oauth_refresh_token=rt_9f83c1a27b64e0d5; session=admin';

  /// A realistic proxy: a private token provider plus a public one.
  factory ContentResolverProxy.seeded() {
    return ContentResolverProxy(const [
      ContentProvider(
        authority: privateAuthority,
        data: privateData,
        privileged: true,
        requiredPermission: privatePermission,
      ),
      ContentProvider(
        authority: publicAuthority,
        data: 'quarterly report: revenue up 4%',
      ),
    ]);
  }

  /// Parse the authority segment out of a `content://<authority>/...` URI.
  static String? authorityOf(String uri) {
    const scheme = 'content://';
    if (!uri.startsWith(scheme)) return null;
    final rest = uri.substring(scheme.length);
    final slash = rest.indexOf('/');
    return slash == -1 ? rest : rest.substring(0, slash);
  }

  ContentProvider? providerFor(String authority) => _providers[authority];

  /// VULN: open the attacker-supplied [uri] through the app's ContentResolver.
  /// The proxy resolves WHATEVER authority the URI names, using the APP's
  /// privileges, and returns the data - never checking whether [callerUid] is
  /// actually allowed to reach that provider. An untrusted caller thus proxies
  /// a privileged read through the app (confused deputy).
  ResolveResult openUri(int callerUid, String uri) {
    final authority = authorityOf(uri);
    final provider = authority == null ? null : _providers[authority];
    if (provider == null) {
      return ResolveResult(
        opened: false,
        blocked: false,
        caller: callerUid,
        uri: uri,
        authority: authority,
        denyReason: 'no provider for authority',
      );
    }
    // No caller/permission validation: resolve with the APP's identity.
    return ResolveResult(
      opened: true,
      blocked: false,
      caller: callerUid,
      uri: uri,
      authority: authority,
      data: provider.data,
      privileged: provider.privileged,
    );
  }

  /// SECURE contrast: before proxying the read, verify the caller is actually
  /// permitted to reach that authority. A privileged provider is only served
  /// when the caller has been GRANTED its required permission (present in
  /// [grantedPermissions]); untrusted callers are refused so the app never
  /// lends its privileges as a deputy. A non-privileged, allowlisted authority
  /// is still served.
  ResolveResult openUriSafe(
    int callerUid,
    String uri, {
    Set<String> grantedPermissions = const {},
  }) {
    final authority = authorityOf(uri);
    final provider = authority == null ? null : _providers[authority];
    if (provider == null) {
      return ResolveResult(
        opened: false,
        blocked: true,
        caller: callerUid,
        uri: uri,
        authority: authority,
        denyReason: 'no provider for authority',
      );
    }
    if (provider.privileged) {
      final perm = provider.requiredPermission;
      final hasPerm = perm != null && grantedPermissions.contains(perm);
      if (!hasPerm) {
        return ResolveResult(
          opened: false,
          blocked: true,
          caller: callerUid,
          uri: uri,
          authority: authority,
          privileged: true,
          denyReason:
              'caller uid $callerUid not granted $perm for privileged '
              'authority $authority - refusing to proxy the read',
        );
      }
    }
    return ResolveResult(
      opened: true,
      blocked: false,
      caller: callerUid,
      uri: uri,
      authority: authority,
      data: provider.data,
      privileged: provider.privileged,
    );
  }
}
