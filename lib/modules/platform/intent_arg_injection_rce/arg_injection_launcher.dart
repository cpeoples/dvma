/// Intent Argument Injection -> Local Code Execution helper.
///
/// INTENTIONALLY VULNERABLE (CWE-88 / CWE-829): an exported "launcher"
/// component reads attacker-controlled intent extras / command-line args and
/// feeds them straight into an execution path. Because the component is
/// exported with no allowlist, another app can send an intent whose extras
/// select a privileged "op" (dump secrets, load an attacker-supplied library
/// path, etc.) which then runs with the victim app's privileges - the Unity
/// CVE-2025-59489 class.
///
/// This is an offline + deterministic simulation: the "Intent" is a plain
/// `Map<String, String>` of extras and the "executor" maps known op strings to
/// effects instead of doing real code loading. A test can assert that a
/// malicious extra (e.g. `cmd=dump_secrets`) executes on [handleIntent] but is
/// rejected by [handleIntentSecure].
class ArgInjectionLauncher {
  ArgInjectionLauncher._();

  /// App-private secrets that must never be reachable by another app.
  static const Map<String, String> _appSecrets = {
    'session_token': 'eyJhbGciOiJIUzI1NiJ9.dvma-session',
    'signing_key': 'MIIBVAIBADANBgkq-DVMA-PRIVATE',
  };

  /// Actions a legitimate caller is actually allowed to trigger.
  static const Set<String> _safeAllowlist = {'open_home', 'open_settings'};

  /// The simulated executor: maps a resolved op string to its effect. This is
  /// the "code execution with app privileges" sink.
  static ExecResult _execute(String op) {
    if (op == 'dump_secrets') {
      final dump = _appSecrets.entries
          .map((e) => '${e.key}=${e.value}')
          .join('; ');
      return ExecResult(
        executed: true,
        op: op,
        output: 'DUMPED app secrets with app privileges: $dump',
      );
    }
    if (op.startsWith('load:')) {
      final path = op.substring('load:'.length);
      return ExecResult(
        executed: true,
        op: op,
        output:
            'LOADED attacker-controlled library from $path '
            '(would execute native code in-process)',
      );
    }
    if (_safeAllowlist.contains(op)) {
      return ExecResult(executed: true, op: op, output: 'navigated to $op');
    }
    return ExecResult(executed: false, op: op, output: 'unknown op: $op');
  }

  /// Resolves the injected op from raw intent extras. Reads several
  /// attacker-influenced keys (`cmd`, `loadLibrary`, `-xrun`).
  static String? _resolveOp(Map<String, String> extras) {
    if (extras.containsKey('cmd')) return extras['cmd'];
    if (extras.containsKey('loadLibrary')) {
      return 'load:${extras['loadLibrary']}';
    }
    if (extras.containsKey('-xrun')) {
      // e.g. "-xrun/data/local/tmp/evil.so" style arg.
      return 'load:${extras['-xrun']}';
    }
    return extras['action'];
  }

  /// VULN: exported handler that trusts attacker-controlled extras and runs
  /// whatever op they select, with the app's privileges. No allowlist.
  static ExecResult handleIntent(Map<String, String> extras) {
    final op = _resolveOp(extras);
    if (op == null) {
      return const ExecResult(
        executed: false,
        op: '',
        output: 'no action supplied',
      );
    }
    return _execute(op);
  }

  /// SECURE contrast: only permit a small allowlist of safe navigation
  /// actions. Any injected execution arg (`cmd`, `loadLibrary`, `-xrun`) is
  /// ignored/rejected and never reaches the executor.
  static ExecResult handleIntentSecure(Map<String, String> extras) {
    final action = extras['action'];
    if (action == null || !_safeAllowlist.contains(action)) {
      return ExecResult(
        executed: false,
        op: action ?? '',
        output:
            'rejected: not an allowlisted action '
            '(execution args are ignored)',
      );
    }
    return _execute(action);
  }
}

/// Outcome of a simulated intent dispatch.
class ExecResult {
  const ExecResult({
    required this.executed,
    required this.op,
    required this.output,
  });

  /// Whether the executor actually ran the op.
  final bool executed;

  /// The resolved op string that was dispatched.
  final String op;

  /// Human-readable effect of the dispatch.
  final String output;
}
