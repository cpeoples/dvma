import 'package:http/http.dart' as http;

import '../../../core/config/dvma_env.dart';
import '../../ai_ml/mock_llm.dart';
import '../agent_core.dart';

/// Confused-deputy agent tool.
///
/// INTENTIONALLY VULNERABLE (CWE-441 / CWE-862, OWASP ASI03): the agent holds a
/// tool that acts with the APP's own ambient authority (a logged-in session /
/// stored credential). When untrusted input contains a directive, the agent
/// invokes the privileged tool on the user's behalf with no re-authentication
/// and no authorization check - a classic confused deputy. The attacker cannot
/// use the credential directly, but the trusted agent will.
class ConfusedDeputyAgent {
  ConfusedDeputyAgent({
    this.appSessionToken = 'app-ambient-session-abc123',
    MockLlm? llm,
  }) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  /// The app's own ambient credential the privileged tool rides on.
  final String appSessionToken;

  final List<String> performedActions = [];

  /// A privileged tool bound to the app's ambient credential.
  late final AgentTool bankTransfer = AgentTool(
    name: 'bank_transfer',
    description: 'Transfers funds from the signed-in user\'s account.',
    usesAmbientCredential: true,
    onInvoke: (amount) => performedActions.add(
      'transfer \$$amount using $appSessionToken (no re-auth)',
    ),
  );

  /// Handles untrusted [input] (e.g. text from a shared document / web content
  /// the agent is asked to "process").
  ///
  /// VULN: a directive in the untrusted input triggers the privileged tool
  /// with the app's ambient credential and no confirmation / re-auth.
  AgentAction handleUntrustedInput(String input) {
    final directive = AgentPlanner.extractDirective(
      input,
      source: 'untrusted-input',
    );
    if (directive != null && directive.action == 'transfer') {
      bankTransfer.invoke(directive.argument);
      return AgentAction(
        summary:
            'Confused deputy: performed transfer with app credentials '
            '(no re-auth) -> $directive',
        directive: directive,
      );
    }
    return AgentAction(summary: 'No privileged action taken.');
  }

  /// LIVE VULN: the untrusted [input] is reasoned over by a real model via
  /// [MockLlm.complete]; if the model emits a transfer/tool call the privileged
  /// tool fires the transfer as a real authenticated request, the app's
  /// ambient session token is attached and the request is sent to the capture
  /// listener (the deputy genuinely acts with its credential over the wire).
  /// Degrades to [handleUntrustedInput] when the model emits no directive /
  /// is offline.
  Future<AgentAction> handleUntrustedInputLive(String input) async {
    final result = await _llm.complete(input);
    final directive = AgentPlanner.extractDirective(
      result.toolCall ?? result.text,
      source: 'untrusted-input',
    );
    if (directive == null || directive.action != 'transfer') {
      // No live directive, fall back to the deterministic extraction path.
      return handleUntrustedInput(input);
    }
    final wire = await _fireTransfer(directive.argument);
    performedActions.add(
      'transfer \$${directive.argument} using $appSessionToken (no re-auth); '
      '$wire',
    );
    return AgentAction(
      summary:
          'Confused deputy: performed transfer with app credentials '
          '(no re-auth) -> $directive',
      directive: directive,
    );
  }

  /// Sends the transfer as the app, attaching its ambient session token as a
  /// Bearer credential. Best effort so a missing listener never hard-fails.
  Future<String> _fireTransfer(String amount) async {
    final uri = Uri.parse('${DvmaEnv.network.captureBase}/bank/transfer');
    try {
      final resp = await http
          .post(
            uri,
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer $appSessionToken',
            },
            body: '{"amount":"$amount","to":"99-attacker"}',
          )
          .timeout(const Duration(seconds: 6));
      return 'POST ${uri.path} -> HTTP ${resp.statusCode}';
    } catch (_) {
      return 'POST ${uri.path} -> no response';
    }
  }

  /// A secure agent would require explicit user re-authorization before using
  /// ambient credentials for a sensitive action triggered by untrusted input.
  bool secureWouldPerform() => false;
}
