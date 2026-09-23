/// Pure-Dart simulation of untrusted dynamic code loading.
///
/// INTENTIONALLY VULNERABLE (CWE-494 / CWE-829): a "plugin loader" maps a
/// module name supplied by an untrusted source (another app / external storage)
/// to an executable op and runs it with no signature or allowlist check. An
/// attacker names a dangerous op ("wipe_data", "exfiltrate") and the loader
/// executes it, achieving arbitrary code execution within the app.
///
/// This is a faithful Dart SIMULATION; the real exploit is native
/// (DexClassLoader / dlopen loading an unsigned .dex/.so from an untrusted
/// origin).
///
/// The vulnerable [loadAndRun] executes anything in the registry; the secure
/// [secureLoadAndRun] only runs signed ops on an allowlist.
class ModuleOp {
  ModuleOp({
    required this.name,
    required this.dangerous,
    required this.run,
    this.signed = false,
  });

  final String name;
  final bool dangerous;

  /// Whether the module carries a valid signature from a trusted publisher.
  final bool signed;

  /// The effect of "executing" the loaded module.
  final String Function() run;
}

class DynamicLoaderResult {
  DynamicLoaderResult({required this.executed, required this.output});

  final bool executed;
  final String output;
}

class UntrustedModuleLoader {
  UntrustedModuleLoader._();

  /// A registry of named ops, as if discovered from an untrusted plugin bundle.
  static final Map<String, ModuleOp> registry = {
    'greet': ModuleOp(
      name: 'greet',
      dangerous: false,
      signed: true,
      run: () => 'hello from a benign, signed module',
    ),
    // Attacker-supplied dangerous op, unsigned.
    'wipe_data': ModuleOp(
      name: 'wipe_data',
      dangerous: true,
      signed: false,
      run: () => 'EXECUTED: deleted /data/data/com.dvma/files/* (simulated)',
    ),
  };

  /// VULN: loads and executes whatever module name is supplied, with no
  /// signature/allowlist verification.
  static DynamicLoaderResult loadAndRun(String moduleName) {
    final op = registry[moduleName];
    if (op == null) {
      return DynamicLoaderResult(executed: false, output: 'module not found');
    }
    // No verification at all -> the untrusted op runs.
    return DynamicLoaderResult(executed: true, output: op.run());
  }

  /// SECURE contrast: only run modules that are both on an explicit allowlist
  /// AND carry a valid signature.
  static const Set<String> _allowlist = {'greet'};

  static DynamicLoaderResult secureLoadAndRun(String moduleName) {
    final op = registry[moduleName];
    if (op == null || !_allowlist.contains(moduleName) || !op.signed) {
      return DynamicLoaderResult(
        executed: false,
        output: 'BLOCKED (not allowlisted / unsigned)',
      );
    }
    return DynamicLoaderResult(executed: true, output: op.run());
  }
}
