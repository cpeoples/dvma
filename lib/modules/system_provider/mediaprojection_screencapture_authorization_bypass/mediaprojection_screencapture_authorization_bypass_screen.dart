import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'media_projection_broker.dart';

/// MediaProjection / Screen-Capture Authorization Bypass.
///
/// A projection/consent token issued to one package is reused/forwarded by an
/// attacker and treated as authoritative without validation, starting
/// unauthorized screen recording (Android MediaProjection CVE-2025-32322
/// class).
class MediaprojectionScreencaptureAuthorizationBypassScreen
    extends StatefulWidget {
  const MediaprojectionScreencaptureAuthorizationBypassScreen({super.key});

  static const String vulnId =
      'mediaprojection_screencapture_authorization_bypass';

  @override
  State<MediaprojectionScreencaptureAuthorizationBypassScreen> createState() =>
      _MediaprojectionScreencaptureAuthorizationBypassScreenState();
}

class _MediaprojectionScreencaptureAuthorizationBypassScreenState
    extends State<MediaprojectionScreencaptureAuthorizationBypassScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(CaptureToken token, CaptureResult r) {
    final b = StringBuffer();
    b.writeln('token                : ${token.value}');
    b.writeln('consent bound to     : ${token.grantedToPackage}');
    b.writeln('presented by         : ${r.usingPackage}');
    b.writeln('recording started    : ${r.recording}');
    b.writeln('unauthorized capture : ${r.unauthorized}');
    if (r.denyReason != null) {
      b.writeln('deny reason          : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: confirm MediaProjectionManager + its consent-intent
    // API are present on this device and report the token-reuse gap.
    final native = await SystemProviderBridge.mediaProjectionState();

    // The user granted screen-capture consent to the meeting app.
    final broker = MediaProjectionBroker();
    final token = broker.issueToken(MediaProjectionBroker.consentingPackage);

    // VULN: the attacker recorder forwards that token and starts recording.
    final vuln = broker.startCapture(
      token,
      MediaProjectionBroker.attackerPackage,
    );

    // SECURE: the token is bound to the consenting package -> forwarded use
    // by the attacker is refused.
    final secureBroker = MediaProjectionBroker();
    final secureToken = secureBroker.issueToken(
      MediaProjectionBroker.consentingPackage,
    );
    final secure = secureBroker.startCaptureSafe(
      secureToken,
      MediaProjectionBroker.attackerPackage,
    );

    await DvmaEvidence.record(
      MediaprojectionScreencaptureAuthorizationBypassScreen.vulnId,
      'media-projection',
      'nativeState=${native ?? 'unavailable (off-Android fallback)'} :: '
          'forwardedToken=${token.value} :: '
          'unauthorizedRecording=${vuln.unauthorized}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? 'native unavailable (off-Android fallback)';
      _vulnResult = _render(token, vuln);
      _secureResult = _render(secureToken, secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: MediaprojectionScreencaptureAuthorizationBypassScreen.vulnId,
      title: 'MediaProjection Screen-Capture Authorization Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Screen capture is authorized by a MediaProjection consent token '
          'that the user granted to ONE package. Here the token is treated as '
          'authoritative wherever it turns up: a forwarded/reused/forged token '
          'starts recording for a different (attacker) package with no '
          'validation, granting unauthorized screen recording / token leakage '
          '(Android MediaProjection CVE-2025-32322 class). This is an offline, '
          'deterministic simulation. The secure path validates the token is '
          'single-use, unexpired, and bound to the same package that obtained '
          'consent. The "real state" panel confirms MediaProjectionManager and '
          'its createScreenCaptureIntent consent API are present on this '
          'device. To fully arm capture, request the token via '
          'createScreenCaptureIntent and approve the system consent dialog; the '
          'granted token can then be reused across captures.',
      children: [
        DemoActionButton(
          label: 'Forward consent token to attacker',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real MediaProjection availability (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'any token starts recording',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'token bound to consenting package',
            value: _secureResult!,
          ),
      ],
    );
  }
}
