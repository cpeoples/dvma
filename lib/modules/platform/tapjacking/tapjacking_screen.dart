import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Tapjacking.
///
/// Sensitive action screen does not set filterTouchesWhenObscured.
class TapjackingScreen extends StatefulWidget {
  const TapjackingScreen({super.key});

  static const String vulnId = 'tapjacking';

  @override
  State<TapjackingScreen> createState() => _TapjackingScreenState();
}

class _TapjackingScreenState extends State<TapjackingScreen> {
  // VULN: the sensitive button does not set filterTouchesWhenObscured, so a
  // malicious overlay can sit on top and pass touches through to it.
  static const bool filterTouchesWhenObscured = false;
  bool _overlayVisible = false;
  String? _result;
  String? _nativeResult;

  Future<void> _confirm() async {
    setState(
      () => _result = _overlayVisible
          ? 'Tap PASSED THROUGH overlay -> "Confirm transfer" fired while the '
                'user believed they tapped a harmless "Claim reward" button.'
          : 'Confirmed transfer.',
    );

    // On Android, report the real overlay / obscured-touch config gap and read
    // back the native evidence.
    final native = await PlatformIpcBridge.overlayConfigGap();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      TapjackingScreen.vulnId,
      'overlay-config-gap',
      'real obscured-touch / overlay protection gap:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: TapjackingScreen.vulnId,
      title: 'Tapjacking',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The sensitive confirm button never sets filterTouchesWhenObscured, '
          'so a malicious full-screen overlay (SYSTEM_ALERT_WINDOW) can cover '
          'it and route the user\'s taps to the hidden button. Toggle a '
          'simulated overlay, then tap confirm.',
      children: [
        SwitchListTile(
          value: _overlayVisible,
          onChanged: (v) => setState(() => _overlayVisible = v),
          title: const Text('malicious overlay present'),
          activeColor: DvmaColors.accent,
        ),
        EvidencePanel(
          label: 'touch filtering',
          value: 'filterTouchesWhenObscured = $filterTouchesWhenObscured',
        ),
        DemoActionButton(
          label: _overlayVisible
              ? 'Claim reward (overlay)'
              : 'Confirm transfer',
          onPressed: _confirm,
        ),
        if (_result != null) EvidencePanel(label: 'outcome', value: _result!),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real obscured-touch / overlay-config gap',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
