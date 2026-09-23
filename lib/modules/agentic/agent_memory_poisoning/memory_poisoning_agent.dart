import 'package:http/http.dart' as http;

import '../../../core/config/dvma_env.dart';
import '../agent_core.dart';

/// Memory-poisoning agent.
///
/// INTENTIONALLY VULNERABLE (CWE-349 / CWE-77, OWASP ASI06 - MINJA-style): a
/// crafted user query causes the agent to write an attacker instruction into
/// its *long-term* memory. A later, unrelated session recalls that memory and
/// the naive planner obeys the stored instruction. Crucially, the app's
/// [resetSession] only clears short-term memory, so the poison survives a
/// "reset" and re-fires indefinitely - and when it re-fires the recalled
/// directive is dispatched as a real request to the capture listener, so the
/// replay is observable over the wire, not just narrated.
class MemoryPoisoningAgent {
  final AgentMemory memory = AgentMemory();

  /// Processes a user [query] in the current session.
  ///
  /// VULN: if the query asks the agent to "remember" something, the content is
  /// written to long-term memory with no sanitization or trust check - so an
  /// embedded instruction becomes persistent context.
  AgentAction handleQuery(String query) {
    final lower = query.toLowerCase();
    if (lower.contains('remember')) {
      // Persist the note (including any embedded directive) to long-term store.
      memory.remember(query, longTerm: true);
      return AgentAction(summary: 'Noted. I will remember that.');
    }
    return _actLocal(query, source: 'user-query');
  }

  /// Starts a fresh session and immediately reconsiders persisted memory,
  /// re-firing any poisoned directive that survived the reset. The recalled
  /// directive is dispatched as a real http request to the capture listener,
  /// so the replayed poison is observable (best-effort; never hard-fails).
  Future<AgentAction> startNewSession() async {
    // VULN: only short-term memory is cleared; long-term poison remains.
    memory.reset();
    for (final note in memory.recall()) {
      final directive = AgentPlanner.extractDirective(
        note,
        source: 'long-term-memory',
      );
      if (directive != null) {
        final fired = await _act(directive);
        return AgentAction(
          summary: 'Recalled from memory and executed: $directive ($fired)',
          directive: directive,
        );
      }
    }
    return AgentAction(summary: 'New session started. Nothing to do.');
  }

  /// Fires the recalled directive as a real request to the capture listener,
  /// so the memory-replay attack leaves an over-the-wire artifact.
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

  AgentAction _actLocal(String text, {required String source}) {
    final directive = AgentPlanner.extractDirective(text, source: source);
    if (directive != null) {
      return AgentAction(summary: 'Executed: $directive', directive: directive);
    }
    return AgentAction(summary: 'DVMA-Agent: acknowledged "$text".');
  }
}
