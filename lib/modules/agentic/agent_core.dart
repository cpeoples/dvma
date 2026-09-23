/// A tiny, offline, deterministic agent framework shared by the DVMA "agentic
/// AI" training modules.
///
/// This is not a real LLM agent - it models just enough of an agent loop
/// (memory, tools/MCP connectors, planning over untrusted text, sub-agent
/// messaging) to make the OWASP Agentic AI Top 10 failures demonstrable and
/// unit-testable without a model or network. Each module builds its specific
/// vulnerability on top of these shared primitives; the primitives themselves
/// deliberately omit the trust/authentication checks a real framework needs.
///
/// The core "planner" is intentionally naive: it scans whatever text it is
/// given (memory, tool descriptions, incoming messages) for an imperative
/// directive and, if present, executes it with no confirmation or provenance
/// check. That single missing check is what every agentic module exploits.
library;

/// A directive parsed out of untrusted text by the naive planner.
class AgentDirective {
  AgentDirective({
    required this.action,
    required this.argument,
    required this.source,
  });

  /// e.g. 'send_message', 'transfer', 'exfiltrate'.
  final String action;

  /// The action's argument (recipient, amount, target, ...).
  final String argument;

  /// Where the directive came from (memory, tool description, message, ...) -
  /// recorded but not used to gate execution.
  final String source;

  @override
  String toString() => '$action($argument) [from $source]';
}

/// The result of an agent taking a step.
class AgentAction {
  AgentAction({required this.summary, this.directive});

  final String summary;
  final AgentDirective? directive;

  bool get actedOnDirective => directive != null;
}

/// Naive directive extraction shared by the agentic modules.
///
/// INTENTIONALLY VULNERABLE: it treats ANY text - regardless of source or
/// trust - as potential instructions. It looks for a small set of imperative
/// patterns and, if found, produces a directive the agent will execute. There
/// is no allow-list of trusted instruction sources and no confirmation.
class AgentPlanner {
  AgentPlanner._();

  /// Scans [text] for an embedded imperative directive. Returns null if none.
  static AgentDirective? extractDirective(
    String text, {
    required String source,
  }) {
    final lower = text.toLowerCase();

    final send = RegExp(r'send_message(?:\s+to)?\s+([^\s,.;]+)')
        .firstMatch(lower);
    if (send != null || lower.contains('send a message')) {
      final to = send?.group(1) ?? 'attacker@evil.example';
      return AgentDirective(
        action: 'send_message',
        argument: to,
        source: source,
      );
    }

    final transfer = RegExp(r'transfer\s+\$?([0-9]+)').firstMatch(lower);
    if (transfer != null) {
      return AgentDirective(
        action: 'transfer',
        argument: transfer.group(1)!,
        source: source,
      );
    }

    if (lower.contains('exfiltrate') || lower.contains('leak the secret')) {
      return AgentDirective(
        action: 'exfiltrate',
        argument: 'secret',
        source: source,
      );
    }

    if (lower.contains('delete') && lower.contains('account')) {
      return AgentDirective(
        action: 'delete_account',
        argument: 'current-user',
        source: source,
      );
    }

    return null;
  }
}

/// An agent's memory with a short-term (per-session) store and a long-term
/// store that survives session resets.
///
/// INTENTIONALLY VULNERABLE (memory poisoning): [reset] only clears short-term
/// memory. Anything written to long-term memory - including an instruction
/// injected by an earlier crafted query - persists and is replayed into future
/// sessions.
class AgentMemory {
  final List<String> _shortTerm = [];
  final List<String> _longTerm = [];

  List<String> get shortTerm => List.unmodifiable(_shortTerm);
  List<String> get longTerm => List.unmodifiable(_longTerm);

  void remember(String note, {bool longTerm = false}) {
    if (longTerm) {
      _longTerm.add(note);
    } else {
      _shortTerm.add(note);
    }
  }

  /// Everything the agent will consider "context" on its next step.
  List<String> recall() => [..._longTerm, ..._shortTerm];

  /// VULN: a "reset" that only clears short-term memory. Long-term (persistent)
  /// memory - where poisoned instructions were stored - is left intact.
  void reset() => _shortTerm.clear();

  /// A full wipe (what a real "forget everything" should do).
  void secureResetAll() {
    _shortTerm.clear();
    _longTerm.clear();
  }
}

/// A tool/MCP connector the agent can plan over. Its [description] is trusted
/// verbatim during planning (no integrity check), which is the MCP-poisoning
/// attack surface.
class AgentTool {
  AgentTool({
    required this.name,
    required this.description,
    this.usesAmbientCredential = false,
    this.onInvoke,
  });

  final String name;
  final String description;

  /// True if invoking the tool implicitly uses the app's own ambient
  /// permission/credential (the confused-deputy surface).
  final bool usesAmbientCredential;

  /// Optional side effect executed when the tool is invoked.
  final void Function(String argument)? onInvoke;

  void invoke(String argument) => onInvoke?.call(argument);
}
