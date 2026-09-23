import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'overlay_capture.dart';

/// Overlay Phishing.
///
/// A credential screen can be covered by a look-alike overlay to phish input
/// (no overlay/obscured-touch protection).
class OverlayPhishingScreen extends StatefulWidget {
  const OverlayPhishingScreen({super.key});

  static const String vulnId = 'overlay_phishing';

  @override
  State<OverlayPhishingScreen> createState() => _OverlayPhishingScreenState();
}

class _OverlayPhishingScreenState extends State<OverlayPhishingScreen> {
  final _username = TextEditingController(text: 'victim');
  final _password = TextEditingController(text: 'Sup3rSecret!');
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  Future<void> _run() async {
    // A malicious overlay is drawn on top of the (unprotected) credential
    // field. The user types their credentials, unaware of the overlay.
    final overlay = MaliciousOverlay();
    final field = CredentialField()..overlay = overlay;
    field.type('user:${_username.text}');
    field.type('pass:${_password.text}');

    // Secure field filters obscured touches, so the overlay captures nothing.
    final secureOverlay = MaliciousOverlay();
    final secureField = SecureCredentialField()..overlay = secureOverlay;
    secureField.type('user:${_username.text}', obscured: true);
    secureField.type('pass:${_password.text}', obscured: true);

    setState(() {
      _vulnResult = 'overlay captured:\n${overlay.captured.join('\n')}';
      _secureResult = secureOverlay.captured.isEmpty
          ? '(overlay captured nothing - obscured touches filtered)'
          : secureOverlay.captured.join('\n');
    });

    // On Android, report the real SYSTEM_ALERT_WINDOW / overlay-config gap the
    // app leaves open and read back the native evidence.
    final native = await PlatformIpcBridge.overlayConfigGap();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      OverlayPhishingScreen.vulnId,
      'overlay-config-gap',
      'real overlay / obscured-touch protection gap:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: OverlayPhishingScreen.vulnId,
      title: 'Overlay Phishing',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The credential field sets no obscured-touch / overlay protection, so '
          'a malicious look-alike overlay drawn on top of it captures every '
          'keystroke while the user believes they are typing into the real app. '
          'This is a Dart simulation; the real exploit is platform-level (a '
          'SYSTEM_ALERT_WINDOW overlay plus the app failing to set '
          'filterTouchesWhenObscured / FLAG_SECURE).',
      children: [
        TextField(
          controller: _username,
          decoration: const InputDecoration(labelText: 'Username'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _password,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        DemoActionButton(label: 'Type into overlaid field', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'credentials stolen by overlay',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'field with obscured-touch protection',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real SYSTEM_ALERT_WINDOW / overlay-config gap',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
