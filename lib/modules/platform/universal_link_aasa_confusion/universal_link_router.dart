/// Universal Link / AASA associated-domain confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-939 / CWE-20 / CWE-601): the app trusts an
/// incoming Universal Link because it matched an associated domain, but the
/// AASA (`apple-app-site-association`) deployment is weak: overly broad path
/// wildcards, an open redirect on the domain, or a parked/look-alike host that
/// still matches the broad pattern. An attacker crafts a URL that routes to a
/// sensitive in-app handler (e.g. resetPassword / transfer) with
/// attacker-controlled parameters. The whole app -> associated-domain -> AASA
/// -> web-server chain is the trust boundary, not just link parsing.
///
/// This now routes against a real, bundled association file: the incoming URL
/// (a TextField value or the crafted constant) is parsed with `Uri.parse` and
/// matched against the components of `assets/aasa/apple-app-site-association.json`
/// (loaded + `jsonDecode`d via [AasaLoader]) using Apple's real glob matcher.
/// The vulnerable [openUniversalLink] uses the loose wildcard match + follows an
/// open redirect; the secure [openUniversalLinkSafe] uses exact-path matching,
/// refuses redirects, and re-validates params. Synchronous entry points route
/// against the embedded fallback so the demo stays deterministic under
/// `flutter test`; the async [routeReal] loads the real on-disk asset.
library;

import '../../../core/aasa_loader.dart';

/// Outcome of routing an incoming Universal Link.
class UniversalLinkRoute {
  const UniversalLinkRoute({
    required this.url,
    required this.handler,
    required this.params,
    required this.routed,
    required this.reachedSensitiveHandler,
    required this.pathMatchTooBroad,
    this.matchedPattern,
    this.matchComment,
    this.denyReason,
  });

  /// The incoming URL (possibly after following a redirect).
  final String url;

  /// The in-app handler the URL dispatched to.
  final String handler;

  /// Parameters passed to the handler.
  final Map<String, String> params;

  /// Whether a handler was invoked at all.
  final bool routed;

  /// Whether a sensitive handler was reached.
  final bool reachedSensitiveHandler;

  /// Whether the match relied on an over-broad wildcard pattern.
  final bool pathMatchTooBroad;

  /// The real AASA component pattern (`/`) that matched.
  final String? matchedPattern;

  /// The matched component's developer comment (surfaces the "broad" intent).
  final String? matchComment;

  /// Why the secure path refused to route.
  final String? denyReason;
}

class UniversalLinkRouter {
  UniversalLinkRouter({AasaAssociation? aasa})
    : _aasa = aasa ?? AasaLoader.embedded();

  /// The parsed association this router matches against (real asset on device,
  /// embedded fallback under test).
  final AasaAssociation _aasa;

  /// Builds a router backed by the real bundled association file.
  static Future<UniversalLinkRouter> real() async =>
      UniversalLinkRouter(aasa: await AasaLoader.load());

  /// The genuine associated domain.
  static const String associatedDomain = 'app.dvma.example';

  /// The sensitive in-app handler an attacker wants to reach.
  static const String sensitiveHandler = 'resetPassword';

  /// A legitimate, benign deep link that should always work.
  static const String genuineLink = 'https://app.dvma.example/promo/summer2026';

  /// Crafted link relying on an over-broad `/*` wildcard to hit resetPassword.
  static const String craftedWildcardLink =
      'https://app.dvma.example/account/resetPassword?user=victim&token=attacker';

  /// Crafted link using an open redirect on the associated domain.
  static const String craftedRedirectLink =
      'https://app.dvma.example/go?redirect=https://app.dvma.example/account/resetPassword%3Fuser%3Dvictim';

  /// Sensitive handlers that a Universal Link must never be able to trigger.
  static const Set<String> _sensitiveHandlers = {'resetPassword', 'transfer'};

  String _handlerFor(String path) {
    // Last non-empty path segment names the handler.
    final segs = path.split('/').where((s) => s.isNotEmpty).toList();
    return segs.isEmpty ? 'home' : segs.last;
  }

  /// VULN: parse the incoming URL, follow any `redirect=` param blindly, then
  /// match the resulting path against the real AASA components with the loose
  /// wildcard matcher and dispatch to the resolved handler with raw query
  /// params. A crafted URL therefore reaches a sensitive handler because the
  /// association's `/account/*` or `/*` component matches it.
  UniversalLinkRoute openUniversalLink(String url) {
    var effective = url;
    var followedRedirect = false;

    // Open redirect: blindly follow a `redirect=` param on the domain.
    final firstUri = Uri.parse(effective);
    final redirect = firstUri.queryParameters['redirect'];
    if (redirect != null) {
      effective = Uri.decodeFull(redirect);
      followedRedirect = true;
    }

    final uri = Uri.parse(effective);
    // Real AASA component match (Apple glob) against the parsed path.
    final component = _aasa.match(uri.path, query: uri.queryParameters);
    if (component == null) {
      return UniversalLinkRoute(
        url: effective,
        handler: 'none',
        params: const {},
        routed: false,
        reachedSensitiveHandler: false,
        pathMatchTooBroad: false,
        denyReason: 'no AASA component matched',
      );
    }
    final handler = _handlerFor(uri.path);
    // Over-broad if a wildcard component covered this path, or a redirect was
    // followed to reach it.
    final broad = followedRedirect || component.isBroad;
    return UniversalLinkRoute(
      url: effective,
      handler: handler,
      params: uri.queryParameters,
      routed: true,
      reachedSensitiveHandler: _sensitiveHandlers.contains(handler),
      pathMatchTooBroad: broad,
      matchedPattern: component.path,
      matchComment: component.comment,
    );
  }

  /// SECURE contrast: parse the URL, refuse any domain-hosted redirect, require
  /// an EXACT (non-wildcard) AASA component match, and never treat a matched
  /// link as authorization for a sensitive handler. The genuine benign link
  /// still routes because its exact `/promo/summer2026` component matches.
  UniversalLinkRoute openUniversalLinkSafe(String url) {
    final uri = Uri.parse(url);

    // Never follow domain-hosted redirects for a Universal Link.
    if (uri.queryParameters.containsKey('redirect')) {
      return UniversalLinkRoute(
        url: url,
        handler: 'none',
        params: const {},
        routed: false,
        reachedSensitiveHandler: false,
        pathMatchTooBroad: false,
        denyReason: 'redirect parameter refused',
      );
    }

    // Exact, non-wildcard AASA component only.
    final component = _aasa.matchExact(uri.path, query: uri.queryParameters);
    if (component == null) {
      return UniversalLinkRoute(
        url: url,
        handler: 'none',
        params: const {},
        routed: false,
        reachedSensitiveHandler: false,
        pathMatchTooBroad: false,
        denyReason: 'path ${uri.path} has no exact AASA component',
      );
    }

    final handler = _handlerFor(uri.path);
    // A matched Universal Link is not an authorization decision.
    if (_sensitiveHandlers.contains(handler)) {
      return UniversalLinkRoute(
        url: url,
        handler: 'none',
        params: const {},
        routed: false,
        reachedSensitiveHandler: false,
        pathMatchTooBroad: false,
        denyReason: 'sensitive handler $handler not reachable via link',
      );
    }

    return UniversalLinkRoute(
      url: url,
      handler: handler,
      params: uri.queryParameters,
      routed: true,
      reachedSensitiveHandler: false,
      pathMatchTooBroad: false,
      matchedPattern: component.path,
      matchComment: component.comment,
    );
  }
}
