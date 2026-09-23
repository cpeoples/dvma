/// WebView Remote Debugging Enabled helper.
///
/// INTENTIONALLY VULNERABLE (CWE-489 / CWE-215 / CWE-200): the app leaves
/// `WebView.setWebContentsDebuggingEnabled(true)` on in a RELEASE build. That
/// flag exposes the WebView over the Chrome DevTools Protocol, so anyone with
/// adb access (or a shared USB session) can open `chrome://inspect`, attach
/// DevTools to the app's web context, inspect the live DOM/JS, and evaluate
/// arbitrary script - reading the session cookie/token and any auth material
/// held in the page. Debugging is a development convenience the release build
/// must turn off (Android WebView MASTG-TEST-0227 class).
///
/// This is an offline + deterministic SIMULATION. [DebuggableWebView] holds
/// `debuggingEnabled` and `isReleaseBuild` flags plus sensitive web-context
/// state (a session token). The vulnerable [attachInspector] succeeds when
/// debugging is on in a release build and dumps the secrets; the secure
/// [configureSafe] disables debugging in release builds so the inspector fails
/// closed, while still permitting DevTools in debug builds.
library;

/// The outcome of an attempt to attach a remote DevTools inspector.
class InspectorAttachResult {
  const InspectorAttachResult({
    required this.debuggingEnabled,
    required this.isReleaseBuild,
    required this.inspectorAttached,
    required this.secretsExposed,
    this.exposedToken,
    this.denyReason,
  });

  /// Whether WebContents debugging was enabled for this build.
  final bool debuggingEnabled;

  /// Whether this is a production/release build.
  final bool isReleaseBuild;

  /// Whether a remote DevTools inspector successfully attached.
  final bool inspectorAttached;

  /// Whether the attacker read web-context secrets via DevTools.
  final bool secretsExposed;

  /// The session token dumped through the inspector (vuln path).
  final String? exposedToken;

  /// Why the secure configuration refused the inspector.
  final String? denyReason;

  /// True when a release build leaked secrets to a remote inspector - the hit.
  bool get releaseSecretsLeaked =>
      isReleaseBuild && inspectorAttached && secretsExposed;
}

class DebuggableWebView {
  DebuggableWebView({
    required this.debuggingEnabled,
    required this.isReleaseBuild,
  });

  /// Whether `setWebContentsDebuggingEnabled(true)` is in effect.
  bool debuggingEnabled;

  /// Whether the app is running as a release (production) build.
  final bool isReleaseBuild;

  /// The session token held in the WebView's JS/cookie context.
  static const String sessionToken =
      'session=wv-9f3c-7b21-AUTH; Bearer eyJhbGciOiJIUzI1NiJ9.devtools';

  /// VULN: attach a remote DevTools inspector. If debugging is enabled the
  /// inspector attaches regardless of build type and can read the live DOM/JS,
  /// dumping the session token from the web context.
  InspectorAttachResult attachInspector() {
    if (debuggingEnabled) {
      return InspectorAttachResult(
        debuggingEnabled: true,
        isReleaseBuild: isReleaseBuild,
        inspectorAttached: true,
        secretsExposed: true,
        exposedToken: sessionToken,
        denyReason: null,
      );
    }
    return const InspectorAttachResult(
      debuggingEnabled: false,
      isReleaseBuild: true,
      inspectorAttached: false,
      secretsExposed: false,
      exposedToken: null,
      denyReason: 'debugging disabled: no inspector endpoint exposed',
    );
  }

  /// SECURE contrast: configure debugging based on build type. In a release
  /// build debugging is forced OFF so a remote inspector cannot attach; debug
  /// builds may keep it on for local development. Returns the attach attempt
  /// after applying the policy.
  InspectorAttachResult configureSafe({required bool isReleaseBuild}) {
    // Fail closed in production: debugging is only allowed in debug builds.
    debuggingEnabled = !isReleaseBuild;
    if (isReleaseBuild) {
      return const InspectorAttachResult(
        debuggingEnabled: false,
        isReleaseBuild: true,
        inspectorAttached: false,
        secretsExposed: false,
        exposedToken: null,
        denyReason:
            'release build: setWebContentsDebuggingEnabled(false); '
            'remote inspector refused',
      );
    }
    // Debug build: developer tooling is expected, but this is not production.
    return InspectorAttachResult(
      debuggingEnabled: true,
      isReleaseBuild: false,
      inspectorAttached: true,
      secretsExposed: true,
      exposedToken: sessionToken,
      denyReason: 'debug build only: debugging permitted for local development',
    );
  }
}
