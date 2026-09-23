import '../../ai_ml/mock_llm.dart';
import '../agent_core.dart';

/// MCP / tool-description poisoning registry.
///
/// INTENTIONALLY VULNERABLE (CWE-829 / CWE-77, OWASP ASI04): the agent ingests
/// every connected tool's DESCRIPTION during planning and trusts it verbatim.
/// A malicious MCP server ships a benign-looking description with an appended
/// hidden directive; the naive planner reads it while "deciding which tool to
/// use" and obeys the embedded instruction. There is no description integrity
/// check, provenance pinning, or separation of tool metadata from instructions.
class McpToolRegistry {
  McpToolRegistry({MockLlm? llm}) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  final List<AgentTool> _tools = [];

  List<AgentTool> get tools => List.unmodifiable(_tools);

  /// Connects a tool/MCP server. No integrity or provenance check is performed
  /// on its description.
  void connect(AgentTool tool) => _tools.add(tool);

  /// The planning step: the agent reads all tool descriptions to decide what to
  /// do. VULN: a directive hidden inside any description is extracted and
  /// executed as if it were a trusted instruction.
  AgentAction planWithToolDescriptions() {
    for (final tool in _tools) {
      final directive = AgentPlanner.extractDirective(
        tool.description,
        source: 'tool:${tool.name}',
      );
      if (directive != null) {
        tool.invoke(directive.argument);
        return AgentAction(
          summary: 'While reading tool descriptions, executed: $directive',
          directive: directive,
        );
      }
    }
    return AgentAction(summary: 'Planning complete. No action taken.');
  }

  /// LIVE planning step: the concatenated tool descriptions are handed to a
  /// real model via [MockLlm.complete] as the planning prompt (exactly the MCP
  /// poisoning surface, metadata mixed with the model's instructions). A model
  /// that follows the hidden directive emits a tool call, which is executed
  /// against the matching tool's real [AgentTool.onInvoke] sink. Degrades to
  /// [planWithToolDescriptions] when the model emits no tool call / is offline.
  Future<AgentAction> planWithToolDescriptionsLive() async {
    final catalog = _tools
        .map((t) => '- ${t.name}: ${t.description}')
        .join('\n');
    final prompt =
        'You are an MCP agent. Available tools:\n$catalog\n'
        'Decide which tool to use to help the user and emit the tool call.';
    final result = await _llm.complete(prompt);
    final directive = AgentPlanner.extractDirective(
      result.toolCall ?? result.text,
      source: 'model-plan',
    );
    if (directive != null) {
      // Route the model-chosen call to a matching connected tool's real sink,
      // falling back to any send-capable tool (the poisoned notes-sync).
      final target = _tools.firstWhere(
        (t) => directive.action.contains(t.name) || t.onInvoke != null,
        orElse: () => _tools.last,
      );
      target.invoke(directive.argument);
      return AgentAction(
        summary:
            'Model planned over tool descriptions and executed: '
            '$directive',
        directive: directive,
      );
    }
    // No live tool call, fall back to the deterministic poisoned extraction.
    return planWithToolDescriptions();
  }

  /// What a secure planner would do: treat descriptions as inert metadata and
  /// refuse to execute any directive found inside them.
  bool secureWouldExecuteFromDescriptions() {
    for (final tool in _tools) {
      if (AgentPlanner.extractDirective(
            tool.description,
            source: 'tool:${tool.name}',
          ) !=
          null) {
        // A hidden directive exists, but a secure planner ignores it.
        return false;
      }
    }
    return false;
  }
}
