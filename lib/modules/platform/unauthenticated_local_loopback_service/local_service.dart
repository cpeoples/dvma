/// Unauthenticated Local / Loopback Service helper.
///
/// INTENTIONALLY VULNERABLE (CWE-306 / CWE-668 / CWE-350): the app opens a
/// local HTTP/TCP service on the loopback interface (an IPC bridge, debug
/// bridge, companion SDK, or WebView bridge) exposing privileged operations,
/// but performs no authentication and no origin/host validation. Because the
/// socket is "only local", the app trusts every caller - so any co-resident
/// app can invoke privileged operations, and remote web content can reach
/// 127.0.0.1 via DNS rebinding (a public hostname re-pointed at loopback so the
/// browser still treats the page as same-origin) and drive the service too.
///
/// This is an offline + deterministic SIMULATION. [LocalService] receives a
/// [LocalRequest] carrying the caller's origin and an optional session token.
/// The vulnerable [handle] serves any request that hits the port; the secure
/// [handleSafe] requires an unpredictable per-session token AND an allowlisted
/// same-app origin/host, rejecting untokened callers and rebinding origins.
library;

/// A request arriving at the loopback service.
class LocalRequest {
  const LocalRequest({
    required this.callerOrigin,
    required this.hostHeader,
    required this.operation,
    this.sessionToken,
  });

  /// The caller's origin: the app's own WebView, a co-resident app, or a remote
  /// web page performing DNS rebinding.
  final String callerOrigin;

  /// The HTTP Host header presented by the caller.
  final String hostHeader;

  /// The privileged operation being invoked (e.g. `getSecrets`, `runCommand`).
  final String operation;

  /// The per-session bearer token, if the caller supplied one.
  final String? sessionToken;
}

/// The result of handling a loopback request.
class LocalServiceResult {
  const LocalServiceResult({
    required this.served,
    required this.authChecked,
    required this.dataExposed,
    required this.responseData,
    required this.callerOrigin,
    this.denyReason,
  });

  /// Whether the service executed the requested privileged operation.
  final bool served;

  /// Whether the service actually validated a token/origin before serving.
  final bool authChecked;

  /// True when privileged data/functionality was exposed to an untrusted
  /// caller - the hit.
  final bool dataExposed;

  /// The data returned to the caller (empty when denied).
  final String responseData;

  /// The origin the request claimed to come from.
  final String callerOrigin;

  /// Why the request was denied (secure path); null when served.
  final String? denyReason;
}

class LocalService {
  /// The loopback port the service listens on.
  static const int loopbackPort = 8317;

  /// The app's own trusted origin (its in-app WebView bridge).
  static const String trustedOrigin = 'https://app.local.example';

  /// The Host header the app expects for its own loopback bridge.
  static const String expectedHost = '127.0.0.1:$loopbackPort';

  /// An unpredictable per-session token the app hands to its own WebView only.
  static const String validSessionToken = 'sess-9d4f2a7c1b8e30f5';

  /// The privileged data guarded by the service.
  static const String privilegedData =
      'wallet_seed=zoo-lava-echo-north; api_key=sk_live_7c1b8e30f5';

  /// An attacker request: a co-resident app / rebinding web page with no token
  /// and a rebinding Host header pointing a public name at loopback.
  static const LocalRequest attackerRequest = LocalRequest(
    callerOrigin: 'https://rebind.attacker.example',
    hostHeader: 'rebind.attacker.example',
    operation: 'getSecrets',
    sessionToken: null,
  );

  /// A legitimate request from the app's own WebView with the correct token
  /// and the expected loopback Host.
  static const LocalRequest legitimateRequest = LocalRequest(
    callerOrigin: trustedOrigin,
    hostHeader: expectedHost,
    operation: 'getSecrets',
    sessionToken: validSessionToken,
  );

  String _execute(String operation) {
    switch (operation) {
      case 'getSecrets':
        return privilegedData;
      case 'runCommand':
        return 'command executed with app privileges';
      default:
        return 'unknown operation: $operation';
    }
  }

  /// VULN: serve any request that reaches the port. No token is checked and the
  /// Origin/Host is ignored, so a co-resident app or a DNS-rebinding web page
  /// invokes privileged operations and reads the app's secrets.
  LocalServiceResult handle(LocalRequest request) {
    final data = _execute(request.operation);
    return LocalServiceResult(
      served: true,
      authChecked: false,
      dataExposed: true,
      responseData: data,
      callerOrigin: request.callerOrigin,
    );
  }

  /// SECURE contrast: require an unpredictable per-session token AND validate
  /// the Origin/Host against the app's own bridge. Rebinding origins and
  /// untokened callers are rejected; only the app's own WebView, presenting the
  /// correct token and loopback Host, is served.
  LocalServiceResult handleSafe(LocalRequest request) {
    // Constant-time-ish token comparison; a missing/wrong token is rejected.
    if (request.sessionToken != validSessionToken) {
      return LocalServiceResult(
        served: false,
        authChecked: true,
        dataExposed: false,
        responseData: '',
        callerOrigin: request.callerOrigin,
        denyReason: 'missing or invalid session token',
      );
    }
    // Anti-rebinding: the Host must be the expected loopback authority and the
    // Origin must be the app's own trusted origin.
    if (request.hostHeader != expectedHost ||
        request.callerOrigin != trustedOrigin) {
      return LocalServiceResult(
        served: false,
        authChecked: true,
        dataExposed: false,
        responseData: '',
        callerOrigin: request.callerOrigin,
        denyReason: 'untrusted origin/host (possible DNS rebinding)',
      );
    }
    final data = _execute(request.operation);
    return LocalServiceResult(
      served: true,
      authChecked: true,
      dataExposed:
          false, // served, but only to the authenticated same-app WebView.
      responseData: data,
      callerOrigin: request.callerOrigin,
    );
  }
}
