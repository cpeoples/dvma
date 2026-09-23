import 'package:http/http.dart' as http;

import '../../../core/config/dvma_env.dart';
import '../../ai_ml/mock_llm.dart';
import '../agent_core.dart';

/// A message exchanged between sub-agents on the bus.
class AgentMessage {
  AgentMessage({
    required this.claimedSender,
    required this.to,
    required this.body,
  });

  /// The sender identity as *claimed* by whoever posted the message. It is
  /// never verified, so it can be freely spoofed.
  final String claimedSender;

  final String to;
  final String body;
}

/// An unauthenticated inter-agent message bus.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-290, OWASP ASI07): sub-agents
/// exchange messages with no sender authentication. Any party can post a
/// message claiming to be a trusted agent, and the receiving agent acts on it.
/// There is no signing, no shared secret, and no identity verification.
class AgentMessageBus {
  AgentMessageBus({MockLlm? llm}) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  final List<AgentMessage> _log = [];

  List<AgentMessage> get log => List.unmodifiable(_log);

  /// Posts [message] to the bus. VULN: the claimed sender is accepted as-is.
  void send(AgentMessage message) => _log.add(message);

  /// Delivers pending messages addressed to [agentName] and lets the receiving
  /// agent act on them. VULN: the receiver trusts `claimedSender` and executes
  /// any directive in a message that appears to come from a trusted peer.
  List<AgentAction> deliverTo(String agentName, {required String trustedPeer}) {
    final actions = <AgentAction>[];
    for (final msg in _log.where((m) => m.to == agentName)) {
      // VULN: identity check is a plain string comparison against an
      // unauthenticated, attacker-controllable field.
      if (msg.claimedSender == trustedPeer) {
        final directive = AgentPlanner.extractDirective(
          msg.body,
          source: 'peer:${msg.claimedSender}',
        );
        actions.add(
          AgentAction(
            summary: directive != null
                ? 'Accepted message from "${msg.claimedSender}" and executed: '
                      '$directive'
                : 'Accepted message from "${msg.claimedSender}": ${msg.body}',
            directive: directive,
          ),
        );
      }
    }
    return actions;
  }

  /// LIVE delivery: for each message that passes the (spoofable) sender check,
  /// the receiving agent feeds the untrusted message BODY to a real model via
  /// [MockLlm.complete] and acts on whatever tool call the model emits, the
  /// emitted `send_message`/transfer is fired as a real request to the capture
  /// listener. Degrades to [deliverTo]'s deterministic extraction when the
  /// model emits no directive / is offline.
  Future<List<AgentAction>> deliverToLive(
    String agentName, {
    required String trustedPeer,
  }) async {
    final actions = <AgentAction>[];
    for (final msg in _log.where((m) => m.to == agentName)) {
      if (msg.claimedSender != trustedPeer) continue;
      final result = await _llm.complete(msg.body);
      final directive =
          AgentPlanner.extractDirective(
            result.toolCall ?? result.text,
            source: 'peer:${msg.claimedSender}',
          ) ??
          AgentPlanner.extractDirective(
            msg.body,
            source: 'peer:${msg.claimedSender}',
          );
      var summary = directive != null
          ? 'Accepted message from "${msg.claimedSender}" and executed: '
                '$directive'
          : 'Accepted message from "${msg.claimedSender}": ${msg.body}';
      if (directive != null) {
        final wire = await _act(directive);
        summary = '$summary; $wire';
      }
      actions.add(AgentAction(summary: summary, directive: directive));
    }
    return actions;
  }

  /// Fires the directive as a real request to the capture listener. Best
  /// effort so a missing listener never hard-fails the demo.
  Future<String> _act(AgentDirective directive) async {
    final uri = Uri.parse(
      '${DvmaEnv.network.captureBase}/agent/${directive.action}',
    );
    try {
      final resp = await http
          .post(
            uri,
            headers: const {'Content-Type': 'application/json'},
            body:
                '{"arg":"${directive.argument}","from":"${directive.source}"}',
          )
          .timeout(const Duration(seconds: 6));
      return 'POST ${uri.path} -> HTTP ${resp.statusCode}';
    } catch (_) {
      return 'POST ${uri.path} -> no response';
    }
  }

  /// What an authenticated bus would decide: a message is only trusted if it
  /// carries a valid signature from the peer (never true for a spoof).
  static bool secureWouldAccept(AgentMessage message) => false;
}
