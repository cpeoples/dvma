import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Anti-Tampering / Integrity Bypass.
///
/// A real native read returns the running APK's actual signing-certificate
/// SHA-256 (the true integrity anchor). The vulnerability: the app's integrity
/// check never pins/compares against it, it accepts any client-supplied hash,
/// so a repackaged/re-signed build passes.
class AntiTamperingIntegrityBypassScreen extends StatefulWidget {
  const AntiTamperingIntegrityBypassScreen({super.key});

  static const String vulnId = 'anti_tampering_integrity_bypass';

  @override
  State<AntiTamperingIntegrityBypassScreen> createState() =>
      _AntiTamperingIntegrityBypassScreenState();
}

class _AntiTamperingIntegrityBypassScreenState
    extends State<AntiTamperingIntegrityBypassScreen> {
  final PlatformLingo _lingo = PlatformLingo.current();
  final _buildHash = TextEditingController(
    text: 'deadbeef_TAMPERED_build_hash',
  );
  String? _result;
  String? _nativeSignature;

  // VULN: the "integrity check" ignores the real signing digest and always
  // returns true, so a re-signed/tampered/repackaged build passes unchanged.
  bool _verifyIntegrity(String actualHash) {
    // A real check would compare actualHash against [_nativeSignature] (the
    // pinned expected signing digest). It does neither.
    return true; // always passes, verifies nothing
  }

  String get _nativeUnavailable => _lingo.pick(
    ios:
        'native unavailable on this host (desktop/test); the real anchor '
        'on iOS is the embedded code signature / provisioning profile',
    android: 'native unavailable on this host (desktop/test)',
  );

  Future<void> _verify() async {
    // real native read: the app's actual signing certificate SHA-256.
    final signature = await ResilienceBridge.tamperCheck();
    final ok = _verifyIntegrity(_buildHash.text);

    await DvmaEvidence.record(
      AntiTamperingIntegrityBypassScreen.vulnId,
      'tamper',
      'realSigningDigest=${signature ?? _nativeUnavailable} '
          ':: suppliedHash=${_buildHash.text} :: integrityPassed=$ok '
          '(check never compares against the real digest)',
    );

    if (!mounted) return;
    setState(() {
      _nativeSignature = signature ?? _nativeUnavailable;
      _result = ok
          ? 'Integrity check PASSED for "${_buildHash.text}" (even though it is '
                'tampered) - the check never compares against the real signing '
                'digest below.'
          : 'Integrity check failed.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AntiTamperingIntegrityBypassScreen.vulnId,
      title: 'Anti-Tampering / Integrity Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The running build has a real integrity anchor - its '
          '${_lingo.codeSignIdentity} (Android APK signing cert / iOS embedded '
          'code signature). But the app\'s integrity check always returns true; '
          'it never pins the running build against that identity. So a '
          'repackaged, re-signed, or patched build passes verification. Feed it '
          'any (tampered) hash below.',
      children: [
        TextField(
          controller: _buildHash,
          decoration: const InputDecoration(labelText: 'running build hash'),
        ),
        DemoActionButton(label: 'Verify integrity', onPressed: _verify),
        if (_nativeSignature != null)
          EvidencePanel(
            label: 'real signing digest (native)',
            value: _nativeSignature!,
          ),
        if (_result != null)
          EvidencePanel(label: 'verification result', value: _result!),
      ],
    );
  }
}
