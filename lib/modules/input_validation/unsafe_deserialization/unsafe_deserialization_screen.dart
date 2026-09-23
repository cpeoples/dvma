import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'unsafe_deserializer.dart';

/// Unsafe Deserialization.
///
/// Deserializes untrusted data into typed objects with no validation.
class UnsafeDeserializationScreen extends StatefulWidget {
  const UnsafeDeserializationScreen({super.key});

  static const String vulnId = 'unsafe_deserialization';

  @override
  State<UnsafeDeserializationScreen> createState() =>
      _UnsafeDeserializationScreenState();
}

class _UnsafeDeserializationScreenState
    extends State<UnsafeDeserializationScreen> {
  final _payload = TextEditingController(
    text:
        '{"username":"attacker","isAdmin":true,"role":"admin",'
        '"__type":"CommandRunner"}',
  );
  String? _result;
  String? _secureResult;
  String? _recovered;
  bool _running = false;

  Future<void> _deserialize() async {
    setState(() => _running = true);
    final lingo = PlatformLingo.current();

    // VULN (real): build the privileged object from untrusted JSON AND persist
    // it to the local key-value store, then read it back off disk to prove the
    // injected privilege survived.
    String vulnText;
    String? recovered;
    try {
      final session = await UnsafeDeserializer.fromUntrustedAndPersist(
        _payload.text,
      );
      final raw = await UnsafeDeserializer.rawPersisted();
      final reloaded = await UnsafeDeserializer.loadPersisted();
      recovered = raw;
      vulnText =
          'built: $session\n'
          'persisted to ${lingo.keyValueStore}, reloaded: $reloaded\n'
          'isAdmin survived on disk: ${reloaded?.isAdmin}';

      // The real leak is the privileged object durably stored on disk. Mirror
      // the stored JSON + backing path so the harness can recover it.
      await DvmaEvidence.record(
        UnsafeDeserializationScreen.vulnId,
        'deserialization',
        'stored key: ${UnsafeDeserializer.sessionKey}\n'
            'stored value: $raw\n'
            'injected isAdmin=${session.isAdmin}, role=${session.role} '
            'survives on disk\n'
            'backing file ${lingo.backingReadableParenthetical}: '
            '${lingo.keyValueBackingPath}',
      );
    } catch (e) {
      // In-memory fallback so the demo still shows the built object even if the
      // prefs plugin is unavailable (e.g. bare unit-test host).
      final session = UnsafeDeserializer.fromUntrusted(_payload.text);
      vulnText = 'built (persist unavailable: $e): $session';
    }

    // SECURE contrast: strict schema/allowlist validation rejects the hostile
    // payload and never lets input choose privilege or a type.
    String secureText;
    try {
      final safe = UnsafeDeserializer.fromTrustedSchema(_payload.text);
      secureText = 'accepted after validation: $safe';
    } on FormatException catch (e) {
      secureText = 'rejected by schema validation: ${e.message}';
    }

    if (!mounted) return;
    setState(() {
      _running = false;
      _result = vulnText;
      _secureResult = secureText;
      _recovered = recovered;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: UnsafeDeserializationScreen.vulnId,
      title: 'Unsafe Deserialization',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Untrusted JSON is deserialized straight into a privileged session '
          'object with no validation, so attacker-supplied fields (isAdmin, '
          'role) and even a payload-named type are trusted. The built object is '
          'then PERSISTED to ${lingo.keyValueStore}, so the injected privilege '
          'survives on disk and is recoverable across launches (recover the '
          'backing ${lingo.keyValueBackingFile} via ${lingo.pullTool}). Edit '
          'the payload below to grant yourself admin. The secure path validates '
          'against a strict schema/allowlist and never lets input choose '
          'privilege or a type.',
      children: [
        TextField(
          controller: _payload,
          maxLines: 3,
          decoration: const InputDecoration(labelText: 'untrusted JSON'),
        ),
        DemoActionButton(
          label: _running ? 'Deserializing…' : 'Deserialize',
          onPressed: _running ? () {} : () => _deserialize(),
        ),
        if (_result != null)
          EvidencePanel(
            label: 'object built + persisted (privileges trusted)',
            value: _result!,
          ),
        if (_recovered != null)
          EvidencePanel(
            label: 'recovered from disk (${lingo.keyValueStore})',
            value: _recovered!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'schema validation (secure contrast)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
