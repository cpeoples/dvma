import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'model_updater.dart';

/// Unverified Model Supply Chain.
///
/// Model update fetched from an unauthenticated URL with no checksum.
class UnverifiedModelSupplyChainScreen extends StatefulWidget {
  const UnverifiedModelSupplyChainScreen({super.key});

  static const String vulnId = 'unverified_model_supply_chain';

  @override
  State<UnverifiedModelSupplyChainScreen> createState() =>
      _UnverifiedModelSupplyChainScreenState();
}

class _UnverifiedModelSupplyChainScreenState
    extends State<UnverifiedModelSupplyChainScreen> {
  final _updater = ModelUpdater();
  String? _result;
  bool _fetching = false;

  Future<void> _update() async {
    setState(() {
      _fetching = true;
      _result = null;
    });
    // The mirror (or an on-path attacker) serves a poisoned model; this is the
    // fallback body used only when no listener answers the real fetch.
    const poisonedFallback = 'POISONED_MODEL_backdoor_weights';
    final fetch = await _updater.fetchAndInstallOverHttp(poisonedFallback);
    if (!mounted) return;
    setState(() {
      _fetching = false;
      _result =
          'GET ${fetch.url}'
          '${fetch.overTheWire ? " (bytes arrived over the wire)" : " (no listener; poisoned fallback installed)"}\n'
          'installed bytes (unverified): ${fetch.bytes}\n'
          'sha256: ${fetch.sha256} (never checked)\n'
          'verifiesChecksum: ${ModelUpdater.verifiesChecksum}';
    });
    // Record the real, unverified bytes/URL that were installed, pullable.
    DvmaEvidence.record(
      UnverifiedModelSupplyChainScreen.vulnId,
      'model-bytes',
      'GET ${fetch.url} over cleartext http (no checksum/signature)\n'
          'installed bytes (unverified): ${fetch.bytes}\n'
          'sha256: ${fetch.sha256} (never checked)\n'
          'overTheWire: ${fetch.overTheWire}\n'
          'verifiesChecksum: ${ModelUpdater.verifiesChecksum}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnverifiedModelSupplyChainScreen.vulnId,
      title: 'Unverified Model Supply Chain',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Model updates are fetched over plain HTTP from '
          '${ModelUpdater.liveUpdateUrl} with no checksum or signature check, '
          'so a malicious mirror / on-path attacker (mitmproxy) serves a '
          'poisoned model and the app installs it. This performs a REAL '
          'cleartext http.get and installs whatever comes back, unverified. '
          'Trigger an update below.',
      children: [
        DemoActionButton(
          label: _fetching ? 'Fetching…' : 'Check for model update',
          onPressed: _fetching ? () {} : () => _update(),
        ),
        if (_result != null)
          EvidencePanel(label: 'update result', value: _result!),
      ],
    );
  }
}
