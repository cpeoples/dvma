import '../../ai_ml/mock_llm.dart';

/// AI Output Used as Intent / URL helper.
///
/// INTENTIONALLY VULNERABLE (CWE-601 / CWE-441 / CWE-20, OWASP LLM05,
/// MASVS-PLATFORM-1): the assistant's (attacker-influenced) output is fed
/// directly into `startActivity()` / a URL launcher with no allowlist and no
/// user confirmation. A prompt-injected model can therefore drive navigation
/// to an attacker host, an open redirect, a `javascript:` URI, or a privileged
/// deep link entirely on the user's behalf.
///
/// The secure contrast requires BOTH an https allowlist (scheme + host) AND an
/// explicit user confirmation before anything launches, so model output alone
/// can never navigate the app.
///
/// Offline + deterministic: [IntentLauncher] is an in-memory launcher that
/// records what it "launched" instead of touching the platform. A test can
/// assert the vulnerable path launches the attacker URL while the secure path
/// refuses it.
class AiIntentLauncher {
  AiIntentLauncher({MockLlm? llm}) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  /// Hosts the app legitimately navigates to.
  static const Set<String> allowedHosts = {'dvma.example', 'www.dvma.example'};

  /// VULN: pull a URL out of the model output and launch it immediately, no
  /// allowlist, no confirmation.
  LaunchOutcome launchInsecure(String userRequest) {
    final url = extractUrl(_llm.run(userRequest).text);
    final launcher = IntentLauncher();
    if (url == null) {
      return LaunchOutcome(
        url: null,
        launched: false,
        reason: 'no url in model output',
        launcher: launcher,
      );
    }
    launcher.launch(url); // fired with zero validation
    return LaunchOutcome(
      url: url,
      launched: true,
      reason: 'launched verbatim from model output (no allowlist/confirm)',
      launcher: launcher,
    );
  }

  /// LIVE VULN: the URL is chosen by a real model via [MockLlm.complete] and
  /// returned so the caller can navigate to it through a genuine platform sink
  /// (`WebViewController.loadRequest`), a real on-device navigation to the
  /// attacker host with no allowlist/confirmation. Degrades to the offline mock
  /// when no backend answers.
  Future<LaunchOutcome> launchInsecureLive(String userRequest) async {
    final url = extractUrl((await _llm.complete(userRequest)).text);
    final launcher = IntentLauncher();
    if (url == null) {
      return LaunchOutcome(
        url: null,
        launched: false,
        reason: 'no url in model output',
        launcher: launcher,
      );
    }
    launcher.launch(url);
    return LaunchOutcome(
      url: url,
      launched: true,
      reason: 'launched verbatim from model output (no allowlist/confirm)',
      launcher: launcher,
    );
  }

  /// SECURE contrast: only launch when the URL is an https URL to an allowlisted
  /// host AND the user explicitly confirmed. Everything else is refused.
  LaunchOutcome launchSecure(
    String userRequest, {
    required bool userConfirmed,
  }) {
    final url = extractUrl(_llm.run(userRequest).text);
    final launcher = IntentLauncher();
    if (url == null) {
      return LaunchOutcome(
        url: null,
        launched: false,
        reason: 'no url in model output',
        launcher: launcher,
      );
    }
    final uri = Uri.tryParse(url);
    if (uri == null || uri.scheme.toLowerCase() != 'https') {
      return LaunchOutcome(
        url: url,
        launched: false,
        reason: 'refused: non-https / unparseable scheme',
        launcher: launcher,
      );
    }
    if (!allowedHosts.contains(uri.host.toLowerCase())) {
      return LaunchOutcome(
        url: url,
        launched: false,
        reason: 'refused: host not on allowlist',
        launcher: launcher,
      );
    }
    if (!userConfirmed) {
      return LaunchOutcome(
        url: url,
        launched: false,
        reason: 'refused: awaiting explicit user confirmation',
        launcher: launcher,
      );
    }
    launcher.launch(url);
    return LaunchOutcome(
      url: url,
      launched: true,
      reason: 'launched after allowlist + confirmation',
      launcher: launcher,
    );
  }

  /// Extracts the first URL/URI-like token from model [text]. Recognizes
  /// http(s), javascript:, and custom app schemes (e.g. `dvma://`).
  static String? extractUrl(String text) {
    final match = RegExp(
      r'((?:https?|javascript|dvma|intent):[^\s"<>]+)',
      caseSensitive: false,
    ).firstMatch(text);
    return match?.group(1);
  }
}

/// An in-memory stand-in for a platform URL launcher / `startActivity`.
class IntentLauncher {
  final List<String> launched = [];

  void launch(String url) => launched.add(url);
}

/// Result of attempting to launch a model-produced URL.
class LaunchOutcome {
  LaunchOutcome({
    required this.url,
    required this.launched,
    required this.reason,
    required this.launcher,
  });

  /// The URL extracted from the model output (if any).
  final String? url;

  /// Whether the URL was actually launched.
  final bool launched;

  /// Human-readable explanation of the decision.
  final String reason;

  /// The launcher that recorded any navigation.
  final IntentLauncher launcher;
}
