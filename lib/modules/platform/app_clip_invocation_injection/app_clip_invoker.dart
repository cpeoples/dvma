/// App Clip invocation injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-862 / CWE-501): an App Clip acts on
/// its invocation parameters (invocation URL / NFC / QR / associated-domain
/// payload) - performing a purchase/order/account action - while TRUSTING that
/// the invocation came from a legitimate physical trigger and INHERITING
/// authentication state as if it were the full app. A crafted invocation URL
/// therefore drives a privileged action without the auth the full app would
/// require. The invocation payload is attacker-controllable.
///
/// This now validates against the SAME real association file as the Universal
/// Link module: the invocation URL is parsed with `Uri.parse` and its host/path
/// checked against `assets/aasa/apple-app-site-association.json` (loaded +
/// parsed via [AasaLoader], reusing the shared loader). The vulnerable [invoke]
/// acts on params trusting the source; the secure [invokeSafe] validates the
/// invocation URL against the associated domain + AASA components and
/// re-authenticates sensitive actions. Synchronous entry points use the
/// embedded fallback so the demo stays deterministic under `flutter test`; the
/// async [real] factory loads the real on-disk asset.
library;

import '../../../core/aasa_loader.dart';

/// How the App Clip was invoked.
enum AppClipSource { url, nfc, qr, banner }

/// A modeled App Clip invocation.
class AppClipInvocation {
  const AppClipInvocation({
    required this.url,
    required this.source,
    required this.params,
  });

  /// The invocation URL (attacker-controllable across all sources).
  final String url;

  /// The claimed physical trigger.
  final AppClipSource source;

  /// Parameters driving the action (attacker-controllable).
  final Map<String, String> params;
}

/// Outcome of handling an App Clip invocation.
class AppClipInvocationOutcome {
  const AppClipInvocationOutcome({
    required this.action,
    required this.params,
    required this.actionPerformed,
    required this.invocationValidated,
    required this.reauthenticated,
    this.host,
    this.matchedPattern,
    this.denyReason,
  });

  /// The privileged action requested (e.g. "pay").
  final String action;

  /// Parameters the action was performed with.
  final Map<String, String> params;

  /// Whether the privileged action actually executed.
  final bool actionPerformed;

  /// Whether the invocation URL was validated against the associated domain.
  final bool invocationValidated;

  /// Whether the sensitive action was re-authenticated (not inherited).
  final bool reauthenticated;

  /// Host parsed from the invocation URL via `Uri.parse`.
  final String? host;

  /// The real AASA component pattern the invocation path matched (if any).
  final String? matchedPattern;

  /// Why the secure path blocked the invocation.
  final String? denyReason;
}

class AppClipInvoker {
  AppClipInvoker({AasaAssociation? aasa})
    : _aasa = aasa ?? AasaLoader.embedded();

  /// The parsed association this invoker validates against (real asset on
  /// device, embedded fallback under test).
  final AasaAssociation _aasa;

  /// Builds an invoker backed by the real bundled association file.
  static Future<AppClipInvoker> real() async =>
      AppClipInvoker(aasa: await AasaLoader.load());

  /// The domain the App Clip's association file is published on. The invocation
  /// URL host must equal this associated domain to be trusted.
  static const String associatedDomain = 'app.dvma.example';

  /// The privileged action a crafted invocation targets.
  static const String privilegedAction = 'pay';

  /// A legitimate invocation URL from a real physical trigger (host is the
  /// associated domain; path is a benign AASA component).
  static const String legitInvocationUrl =
      'https://app.dvma.example/promo/summer2026?item=coffee';

  /// A crafted invocation URL from an attacker-hosted look-alike domain that
  /// drives a high-value payment.
  static const AppClipInvocation craftedInvocation = AppClipInvocation(
    url: 'https://app.dvma.example.attacker.test/account/pay?amount=999&merchant=evil',
    source: AppClipSource.url,
    params: {'amount': '999', 'merchant': 'evil'},
  );

  /// Actions that require full re-authentication in the real app.
  static const Set<String> _sensitiveActions = {'pay', 'linkAccount'};

  String _action(String url) {
    final segs = Uri.parse(url).path
        .split('/')
        .where((s) => s.isNotEmpty)
        .toList();
    return segs.isEmpty ? 'open' : segs.last;
  }

  /// VULN: acts on the invocation params trusting the source, and behaves as if
  /// authenticated like the full app. The URL is parsed for real, but neither
  /// its host nor its path is validated against the association, so a crafted
  /// look-alike URL performs the privileged action with attacker parameters and
  /// no re-auth.
  AppClipInvocationOutcome invoke(AppClipInvocation invocation) {
    final uri = Uri.parse(invocation.url);
    final action = _action(invocation.url);
    return AppClipInvocationOutcome(
      action: action,
      params: invocation.params,
      actionPerformed: true,
      invocationValidated: false,
      reauthenticated: false,
      host: uri.host,
    );
  }

  /// SECURE contrast: parse the invocation URL, require its host to equal the
  /// associated domain the AASA is published on AND its path to match a real
  /// AASA component, require re-authentication for sensitive actions, and never
  /// inherit full-app trust.
  AppClipInvocationOutcome invokeSafe(
    AppClipInvocation invocation, {
    bool freshUserAuth = false,
  }) {
    final uri = Uri.parse(invocation.url);
    final host = uri.host;
    final action = _action(invocation.url);

    if (host != associatedDomain) {
      return AppClipInvocationOutcome(
        action: 'none',
        params: const {},
        actionPerformed: false,
        invocationValidated: false,
        reauthenticated: false,
        host: host,
        denyReason: 'host $host is not the associated domain $associatedDomain',
      );
    }

    // Path must match a real AASA component (reuse the shared association).
    final component = _aasa.match(uri.path, query: uri.queryParameters);
    if (component == null) {
      return AppClipInvocationOutcome(
        action: 'none',
        params: const {},
        actionPerformed: false,
        invocationValidated: false,
        reauthenticated: false,
        host: host,
        denyReason: 'invocation path ${uri.path} not in the association',
      );
    }

    if (_sensitiveActions.contains(action) && !freshUserAuth) {
      return AppClipInvocationOutcome(
        action: action,
        params: const {},
        actionPerformed: false,
        invocationValidated: true,
        reauthenticated: false,
        host: host,
        matchedPattern: component.path,
        denyReason:
            'sensitive action $action requires fresh authentication; '
            'full-app trust is not inherited',
      );
    }

    return AppClipInvocationOutcome(
      action: action,
      params: invocation.params,
      actionPerformed: true,
      invocationValidated: true,
      reauthenticated: _sensitiveActions.contains(action),
      host: host,
      matchedPattern: component.path,
    );
  }
}
