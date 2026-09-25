import '../../../core/config/dvma_env.dart';
import '../../ai_ml/mock_llm.dart';

import 'package:http/http.dart' as http;

/// AI Output -> Tool / Command Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-77 / CWE-88 / CWE-862, OWASP LLM06 / ASI03,
/// MASVS-CODE-4): the assistant maps model output to a tool/command invocation
/// and EXECUTES it with the app's privileges BEFORE any validation. A
/// prompt-injected model emits a tool call (e.g. `send_message`) whose args are
/// fully attacker-controlled, so the app performs a privileged operation -
/// exfiltrating the system-prompt secret to an attacker address - with no
/// allowlist, no argument validation, and no authorization check. This is the
/// Microsoft 365 Copilot iOS/Android CVE-2026-26133 command-injection class.
///
/// The secure contrast runs the model output through an allowlisted tool
/// registry AND validates arguments (the recipient must be an approved
/// contact) before dispatch, so the injected exfiltration call is refused.
///
/// Offline + deterministic: [ToolRuntime] records executed tools instead of
/// touching the platform. A test can assert the vulnerable dispatch executes
/// the attacker-controlled tool while the secure dispatch refuses it.
class AiToolDispatcher {
  AiToolDispatcher({MockLlm? llm}) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  /// Tools the assistant is actually authorized to invoke.
  static const Set<String> allowedTools = {'send_message', 'search_docs'};

  /// Recipients `send_message` is allowed to target (approved contacts only).
  static const Set<String> allowedRecipients = {
    'support@dvma.example',
    'me@dvma.example',
  };

  /// VULN: parse whatever tool call the model emitted and execute it with no
  /// validation whatsoever.
  ToolDispatch dispatchInsecure(String userRequest) {
    final result = _llm.run(userRequest);
    final runtime = ToolRuntime();
    final call = ToolCall.parse(result.toolCall);
    if (call == null) {
      return ToolDispatch(
        call: null,
        executed: false,
        reason: 'no tool call in model output',
        runtime: runtime,
      );
    }
    // Executed with the app's privileges, pre-validation.
    runtime.execute(call);
    return ToolDispatch(
      call: call,
      executed: true,
      reason: 'executed model tool call with no validation',
      runtime: runtime,
    );
  }

  /// LIVE VULN: the tool call comes from a real model via [MockLlm.complete],
  /// then the parsed call is executed with a real side effect, the
  /// attacker-controlled `send_message` is POSTed over the wire to the capture
  /// listener (the exfiltration actually leaves the app). Degrades gracefully:
  /// [MockLlm.complete] falls back to the offline mock, and the network send is
  /// best-effort so a missing listener never hard-fails the demo.
  Future<ToolDispatch> dispatchInsecureLive(String userRequest) async {
    final result = await _llm.complete(userRequest);
    final runtime = ToolRuntime();
    final call = ToolCall.parse(result.toolCall);
    if (call == null) {
      return ToolDispatch(
        call: null,
        executed: false,
        reason: 'no tool call in model output',
        runtime: runtime,
        backend: result.backend,
      );
    }
    // Executed with the app's privileges, pre-validation, over the wire.
    final sideEffect = await runtime.executeLive(call);
    return ToolDispatch(
      call: call,
      executed: true,
      reason: 'executed model tool call with no validation ($sideEffect)',
      runtime: runtime,
      backend: result.backend,
    );
  }

  /// SECURE contrast: only dispatch when the tool is on the allowlist AND its
  /// arguments pass validation (recipient must be an approved contact).
  ToolDispatch dispatchSecure(String userRequest) {
    final result = _llm.run(userRequest);
    final runtime = ToolRuntime();
    final call = ToolCall.parse(result.toolCall);
    if (call == null) {
      return ToolDispatch(
        call: null,
        executed: false,
        reason: 'no tool call in model output',
        runtime: runtime,
      );
    }
    if (!allowedTools.contains(call.name)) {
      return ToolDispatch(
        call: call,
        executed: false,
        reason: 'refused: tool "${call.name}" not on allowlist',
        runtime: runtime,
      );
    }
    if (call.name == 'send_message') {
      final to = call.args['to'];
      if (to == null || !allowedRecipients.contains(to)) {
        return ToolDispatch(
          call: call,
          executed: false,
          reason: 'refused: recipient "$to" not an approved contact',
          runtime: runtime,
        );
      }
    }
    runtime.execute(call);
    return ToolDispatch(
      call: call,
      executed: true,
      reason: 'executed after allowlist + argument validation',
      runtime: runtime,
    );
  }
}

/// A parsed tool call: name + named string arguments.
class ToolCall {
  ToolCall(this.name, this.args, this.raw);

  final String name;
  final Map<String, String> args;
  final String raw;

  /// Parses `name(key="value", key2="value2")` as MockLlm emits it. Returns
  /// null when [raw] is null/unparseable.
  static ToolCall? parse(String? raw) {
    if (raw == null) return null;
    final head = RegExp(r'^\s*([a-zA-Z_][\w]*)\s*\(').firstMatch(raw);
    if (head == null) return null;
    final name = head.group(1)!;
    final args = <String, String>{};
    for (final m in RegExp(r'(\w+)\s*=\s*"([^"]*)"').allMatches(raw)) {
      args[m.group(1)!] = m.group(2)!;
    }
    return ToolCall(name, args, raw);
  }
}

/// An in-memory stand-in for the app's privileged tool runtime.
class ToolRuntime {
  final List<ToolCall> executed = [];

  void execute(ToolCall call) => executed.add(call);

  /// Executes [call] with a real side effect for `send_message`: the recipient
  /// and body are POSTed over the wire to the capture listener (the app acts as
  /// a confused deputy and the exfiltration genuinely leaves the device).
  /// Returns a short description of what fired. Best-effort, a missing
  /// listener still records the executed call locally.
  Future<String> executeLive(ToolCall call) async {
    executed.add(call);
    if (call.name != 'send_message') {
      return 'executed ${call.name} (no network side effect)';
    }
    final uri = Uri.parse('${DvmaEnv.network.captureBase}/tool/send_message');
    try {
      final resp = await http
          .post(
            uri,
            headers: const {'Content-Type': 'application/json'},
            body:
                '{"to":"${call.args['to'] ?? ''}",'
                '"body":"${call.args['body'] ?? ''}"}',
          )
          .timeout(const Duration(seconds: 6));
      return 'POST ${uri.path} -> HTTP ${resp.statusCode}';
    } catch (_) {
      return 'POST ${uri.path} -> no response';
    }
  }
}

/// Result of attempting to dispatch a model-produced tool call.
class ToolDispatch {
  ToolDispatch({
    required this.call,
    required this.executed,
    required this.reason,
    required this.runtime,
    this.backend = 'offline-mock',
  });

  /// The parsed tool call (if any).
  final ToolCall? call;

  /// Whether the tool was actually executed.
  final bool executed;

  /// Human-readable explanation of the decision.
  final String reason;

  /// The runtime that recorded any execution.
  final ToolRuntime runtime;

  /// Which live backend produced the tool call (`offline-mock` offline).
  final String backend;
}
