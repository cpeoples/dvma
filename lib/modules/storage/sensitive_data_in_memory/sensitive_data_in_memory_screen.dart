import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'memory_secret_store.dart';

/// Sensitive Data in Memory.
///
/// Passwords/keys are held in long-lived, never-cleared objects, recoverable
/// from a process memory dump.
class SensitiveDataInMemoryScreen extends StatefulWidget {
  const SensitiveDataInMemoryScreen({super.key});

  static const String vulnId = 'sensitive_data_in_memory';

  @override
  State<SensitiveDataInMemoryScreen> createState() =>
      _SensitiveDataInMemoryScreenState();
}

class _SensitiveDataInMemoryScreenState
    extends State<SensitiveDataInMemoryScreen> {
  final _password = TextEditingController(text: 'hunter2-Sup3rSecret!');
  final _key = TextEditingController(text: 'AES-KEY:0f1e2d3c4b5a6978');
  String? _dump;
  String? _secureDump;

  void _run() {
    final store = InMemorySecretStore.instance..reset();
    // "Use" the secrets to log in / derive a key... and never clear them.
    store.useSecret('password', _password.text);
    store.useSecret('symmetric_key', _key.text);

    // The SECURE contrast: use the password inside a scope that wipes it.
    final scope = SecureSecretScope(_password.text);
    scope.useThenWipe((s) => s.length); // pretend we derived a key

    setState(() {
      _dump = store
          .dumpMemory()
          .entries
          .map((e) => '${e.key} -> ${e.value}')
          .join('\n');
      _secureDump = scope.dumpAfterUse().isEmpty
          ? '(nothing recoverable - buffer zeroized after use)'
          : scope.dumpAfterUse();
    });

    // Real leak: the secrets are retained on the process heap (never cleared),
    // so a memory dump recovers them. Mirror the recoverable dump.
    DvmaEvidence.record(
      SensitiveDataInMemoryScreen.vulnId,
      'memory-secret',
      'retained on heap (recoverable via memory dump): $_dump',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SensitiveDataInMemoryScreen.vulnId,
      title: 'Sensitive Data in Memory',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The password and symmetric key are copied into a process-global, '
          'never-cleared store when "used". Because those objects stay '
          'reachable for the life of the process, a heap/memory dump (fridump, '
          'objection, gdb/lldb) recovers the plaintext long after the login '
          'flow finished. A secure implementation holds the secret only for the '
          'duration of a use and zeroizes its buffer immediately after.',
      children: [
        TextField(
          controller: _password,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _key,
          decoration: const InputDecoration(labelText: 'Symmetric key'),
        ),
        DemoActionButton(
          label: 'Use secrets, then dump memory',
          onPressed: _run,
        ),
        if (_dump != null)
          EvidencePanel(label: 'memory dump (retained objects)', value: _dump!),
        if (_secureDump != null)
          EvidencePanel(label: 'secure scope after use', value: _secureDump!),
      ],
    );
  }
}
