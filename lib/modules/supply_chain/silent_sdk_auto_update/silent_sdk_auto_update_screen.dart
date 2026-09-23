import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'updatable_sdk.dart';

/// Silent SDK Auto-Update (Post-Deploy Behavior Change).
///
/// A benign-looking SDK fetches a new behavior descriptor at runtime and swaps
/// it in with no signature check (SpinOK-style), turning malicious after
/// install with no app update or store review.
class SilentSdkAutoUpdateScreen extends StatefulWidget {
  const SilentSdkAutoUpdateScreen({super.key});

  static const String vulnId = 'silent_sdk_auto_update';

  @override
  State<SilentSdkAutoUpdateScreen> createState() =>
      _SilentSdkAutoUpdateScreenState();
}

class _SilentSdkAutoUpdateScreenState extends State<SilentSdkAutoUpdateScreen> {
  final UpdatableSdk _sdk = UpdatableSdk();

  String? _initial;
  String? _afterUpdate;
  String? _secureResult;

  /// The malicious "remote" behavior descriptor. It is unsigned - the
  /// vulnerable SDK does not care.
  static const RemotePayload _maliciousPayload = RemotePayload(
    behavior: 'exfiltrate',
    signature: null,
  );

  void _runInstalledBehavior() {
    setState(() {
      _initial = _sdk.run().toString();
    });
  }

  Future<void> _applyMaliciousUpdate() async {
    // VULN: no signature verification. The SDK really fetches its new behavior
    // descriptor from `$captureBase/sdk-update` over the wire (observable in
    // mitmproxy/tcpdump) and applies whatever comes back, unsigned. If the
    // listener returns nothing usable we fall back to the local unsigned
    // malicious descriptor so behavior still flips.
    final base = context.read<AppConfig>().captureBase;
    final applied = await _sdk.fetchAndApplyUpdate(
      base,
      fallback: _maliciousPayload,
    );

    DvmaEvidence.record(
      SilentSdkAutoUpdateScreen.vulnId,
      'sdk-update',
      'GET $base/sdk-update\napplied (no signature check): '
          '${applied.toMap()}',
    );

    if (!mounted) return;
    setState(() {
      _afterUpdate = _sdk.run().toString();
    });
  }

  void _applyViaSignedUpdater() {
    // SECURE contrast: a fresh SDK guarded by the signed updater rejects the
    // unsigned malicious payload, so behavior stays benign.
    final sdk = UpdatableSdk();
    final updater = SignedSdkUpdater(sdk);
    final applied = updater.applyIfVerified(_maliciousPayload);
    setState(() {
      _secureResult =
          'applyIfVerified(unsigned exfiltrate) -> $applied (rejected)\n'
          'behavior after: ${sdk.run()}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SilentSdkAutoUpdateScreen.vulnId,
      title: 'Silent SDK Auto-Update',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A benign-looking analytics/ads SDK ships inside the app and passes '
          'store review serving only ads. At runtime it silently fetches a new '
          '"behavior descriptor" from its server and applies it WITHOUT '
          'verifying any signature or checksum - the SpinOK-style pattern where '
          'a library turns malicious AFTER install, with no new app version and '
          'no store re-review. Once the malicious descriptor lands, the same '
          'unchanged binary begins exfiltrating device contacts and the auth '
          'token. This is an offline/deterministic simulation: the "remote" is '
          'a local Map. The secure contrast requires a valid signature before '
          'applying any update, so the unsigned payload is rejected and '
          'behavior stays benign.',
      children: [
        DemoActionButton(
          label: '1. Run installed SDK (benign)',
          onPressed: _runInstalledBehavior,
        ),
        if (_initial != null)
          EvidencePanel(label: 'installed behavior', value: _initial!),
        DemoActionButton(
          label: '2. Silent auto-update (unsigned) then run',
          onPressed: _applyMaliciousUpdate,
        ),
        if (_afterUpdate != null)
          EvidencePanel(
            label: 'behavior AFTER silent update (same binary!)',
            value: _afterUpdate!,
          ),
        DemoActionButton(
          label: '3. Same update via signed updater',
          onPressed: _applyViaSignedUpdater,
        ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure contrast: signature verified before apply',
            value: _secureResult!,
          ),
      ],
    );
  }
}
