import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'platform_version_gate.dart';

/// Platform-Version Security Fallback.
///
/// A hardware-backed-key decision is gated on the OS version and silently falls
/// back to software/plaintext storage on older versions instead of failing
/// closed.
class PlatformVersionSecurityFallbackScreen extends StatefulWidget {
  const PlatformVersionSecurityFallbackScreen({super.key});

  static const String vulnId = 'platform_version_security_fallback';

  @override
  State<PlatformVersionSecurityFallbackScreen> createState() =>
      _PlatformVersionSecurityFallbackScreenState();
}

class _PlatformVersionSecurityFallbackScreenState
    extends State<PlatformVersionSecurityFallbackScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(KeyStorageResult r) {
    final b = StringBuffer();
    b.writeln(
      'threshold (API)     : '
      '${PlatformVersionGate.hardwareBackingThreshold}',
    );
    b.writeln('osVersion (API)     : ${r.osVersion}');
    b.writeln('stored              : ${r.stored}');
    b.writeln('hardwareBacked      : ${r.hardwareBacked}');
    b.writeln('proceededInsecurely : ${r.proceededInsecurely}');
    if (r.denyReason != null) {
      b.writeln('reason              : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const gate = PlatformVersionGate();
    const oldOs = PlatformVersionGate.oldOsVersion;

    // VULN: old OS -> silent downgrade to software/plaintext, proceeds.
    final vuln = gate.storeKey(oldOs);

    // SECURE: old OS -> fails closed, refuses the sensitive op.
    final secure = gate.storeKeySafe(oldOs);

    // real artifact: record the silent security downgrade, key stored in
    // software/plaintext on an unsupported OS while proceeding as protected.
    await DvmaEvidence.record(
      PlatformVersionSecurityFallbackScreen.vulnId,
      'version-fallback',
      'osVersion=${vuln.osVersion} threshold='
          '${PlatformVersionGate.hardwareBackingThreshold} '
          'stored=${vuln.stored} hardwareBacked=${vuln.hardwareBacked} '
          'proceededInsecurely=${vuln.proceededInsecurely}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, read the real Build.VERSION.SDK_INT and attempt a genuine
    // StrongBox-backed Keystore key, catching StrongBoxUnavailableException -
    // the device-observable hardware-backing posture.
    final native = await SystemProviderBridge.platformVersionKeystore();
    if (native != null) {
      await DvmaEvidence.record(
        PlatformVersionSecurityFallbackScreen.vulnId,
        'version-fallback-native',
        'real keystore/version posture: $native',
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PlatformVersionSecurityFallbackScreen.vulnId,
      title: 'Platform-Version Security Fallback',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A security decision is gated on the OS version (if (SDK_INT >= X) / '
          '@available) and silently falls back to an INSECURE path on older '
          'versions. Here, storing a key with hardware backing (StrongBox / '
          'Secure Enclave) requires API >= 28; on an older OS the code quietly '
          'stores the key in software/plaintext and proceeds as if it were '
          'protected, so devices below the threshold run without the '
          'guarantee (MASTG-TEST-0245 class). This is an offline, '
          'deterministic simulation. The secure path FAILS CLOSED - it refuses '
          'the sensitive op when the platform cannot provide the hardware '
          'guarantee, and stores hardware-backed only on a supported OS.',
      children: [
        DemoActionButton(
          label: 'Store key on old OS (API 25)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'version gate: silent software fallback, proceeded',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'fails closed: unsupported OS refused',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real SDK_INT + StrongBox Keystore attempt',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
