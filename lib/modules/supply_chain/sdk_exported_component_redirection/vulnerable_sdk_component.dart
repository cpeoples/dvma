/// Bundled SDK Ships a Vulnerable Exported Component helper.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-749): the vulnerability lives in a
/// BUNDLED third-party SDK's own exported component, not in the host app's
/// code. The SDK's component accepts a forwarded/nested intent and "redirects"
/// to the embedded target WITHOUT validating the destination. Because the SDK
/// runs with the HOST APP's identity and permissions, another app can route
/// the redirect at a PRIVATE component (e.g. an internal credentials provider)
/// and exfiltrate data the host app can reach. This is the intent-redirection
/// class as shipped by a widely-embedded SDK (EngageLab SDK, 50M+ installs):
/// updating the host app's own code does not fix it, the flaw is in the
/// dependency.
///
/// This is an offline + deterministic simulation: the forwarded "intent" is a
/// plain Map with a nested `forward` intent (`target` + optional `extras`), and
/// the private components are an in-memory map returning sensitive data. A test
/// can assert the vulnerable component redirects to the private target and
/// leaks data, while the safe component allowlists the SDK's own endpoints.
class VulnerableSdkComponent {
  VulnerableSdkComponent._();

  /// Private, in-process-only components the host app exposes. The SDK is
  /// running with the host's privileges, so it can reach these, but they must
  /// never be reachable via an externally-supplied redirect.
  static const Map<String, String> _privateComponents = {
    'AccountCredentialsProvider':
        'username=victim; password=Sup3rSecret!; api_key=sk_live_9f3a2b',
    'FinancialDataProvider':
        'balance=42000.00; iban=DE89 3704 0044 0532 0130 00',
  };

  /// The SDK's own public endpoints, the only legitimate redirect targets.
  static const Set<String> _sdkPublicEndpoints = {
    'EngageLabPushReceiver',
    'EngageLabDeepLinkHandler',
  };

  /// VULN: the SDK's exported component extracts the nested/forwarded intent
  /// and redirects to whatever `target` it names, with no validation. An
  /// attacker points it at a private component and the SDK, running with the
  /// host app's privileges, reaches it and returns the sensitive data.
  static RedirectResult handleForwardedIntent(Map<String, Object?> intent) {
    final forward = intent['forward'];
    if (forward is! Map) {
      return const RedirectResult(
        redirected: false,
        target: null,
        leakedData: null,
        reason: 'no forwarded intent present',
      );
    }
    final target = forward['target'] as String?;
    if (target == null || target.isEmpty) {
      return const RedirectResult(
        redirected: false,
        target: null,
        leakedData: null,
        reason: 'forwarded intent named no target',
      );
    }
    // No allowlist / no destination check: redirect anywhere the host can go.
    final leaked = _privateComponents[target];
    return RedirectResult(
      redirected: true,
      target: target,
      leakedData: leaked,
      reason: leaked != null
          ? 'SDK redirected to PRIVATE component "$target" with host '
                'privileges and returned its data'
          : 'SDK redirected to "$target"',
    );
  }

  /// SECURE contrast: the SDK validates the redirect target against an
  /// allowlist of its own public endpoints and refuses external/private
  /// targets before forwarding.
  static RedirectResult handleForwardedIntentSafe(Map<String, Object?> intent) {
    final forward = intent['forward'];
    if (forward is! Map) {
      return const RedirectResult(
        redirected: false,
        target: null,
        leakedData: null,
        reason: 'no forwarded intent present',
      );
    }
    final target = forward['target'] as String?;
    if (target == null || target.isEmpty) {
      return const RedirectResult(
        redirected: false,
        target: null,
        leakedData: null,
        reason: 'forwarded intent named no target',
      );
    }
    if (!_sdkPublicEndpoints.contains(target)) {
      return RedirectResult(
        redirected: false,
        target: target,
        leakedData: null,
        reason: 'rejected: "$target" is not one of the SDK\'s public endpoints',
      );
    }
    return RedirectResult(
      redirected: true,
      target: target,
      leakedData: null,
      reason: 'redirected to SDK public endpoint "$target"',
    );
  }
}

/// Outcome of a simulated SDK intent redirection.
class RedirectResult {
  const RedirectResult({
    required this.redirected,
    required this.target,
    required this.leakedData,
    required this.reason,
  });

  /// Whether the SDK component forwarded/redirected to the target.
  final bool redirected;

  /// The redirect destination named by the forwarded intent, or null.
  final String? target;

  /// Sensitive data returned by the reached private component, or null when
  /// nothing was leaked.
  final String? leakedData;

  /// Human-readable explanation of what happened.
  final String reason;
}
