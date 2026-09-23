import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'otp_broadcast_bridge.dart';
import 'otp_broadcaster.dart';

/// Cross-App OTP / Credential Leak.
///
/// A co-resident malicious app reads OTP codes / auth deep links from a
/// legitimate 2FA app via an unprotected exported/broadcast surface
/// (Authenticator CVE-2026-26123 class).
class CrossAppOtpCredentialLeakScreen extends StatefulWidget {
  const CrossAppOtpCredentialLeakScreen({super.key});

  static const String vulnId = 'cross_app_otp_credential_leak';

  @override
  State<CrossAppOtpCredentialLeakScreen> createState() =>
      _CrossAppOtpCredentialLeakScreenState();
}

class _CrossAppOtpCredentialLeakScreenState
    extends State<CrossAppOtpCredentialLeakScreen> {
  static const int _counter = 42;

  String? _issued;
  String? _vulnResult;
  String? _secureResult;

  Future<void> _runUnprotected() async {
    final auth = OtpBroadcaster();
    final otp = auth.currentOtp(_counter);
    final link = auth.authDeepLink(_counter);
    final action = '${context.read<AppConfig>().appId}.action.OTP_ISSUED';

    // In-app simulation still runs (so the demo works on iOS / in tests).
    auth.broadcastOtp(_counter);
    final simCaptured = auth.readAsMaliciousApp();

    // On Android, also fire an unprotected broadcast that the separate
    // com.dvma.attacker app can receive. This is the cross-process leak.
    final native = await OtpBroadcastBridge.broadcastUnprotected(otp, link);

    await DvmaEvidence.record(
      CrossAppOtpCredentialLeakScreen.vulnId,
      'otp-broadcast',
      'issued otp=$otp link=$link; '
          '${native ?? "in-app sim only (non-Android)"}; '
          'unprotected action $action - any '
          'co-resident app can receive it.',
    );

    if (!mounted) return;
    setState(() {
      _issued = 'otp:  $otp\nlink: $link';
      _vulnResult = native == null
          ? 'in-app malicious reader captured: ${auth.capturedOtp()}\n'
                'full deep link: $simCaptured'
          : '$native\n'
                'A real co-resident app (com.dvma.attacker) receiving the '
                'unprotected broadcast harvests: otp=$otp';
    });
  }

  Future<void> _runSecure() async {
    final auth = OtpBroadcaster();
    final otp = auth.currentOtp(_counter);
    final link = auth.authDeepLink(_counter);

    auth.broadcastOtpSecure(_counter, 'com.evil.reader');
    final simCaptured = auth.readAsMaliciousApp();
    final native = await OtpBroadcastBridge.broadcastSecure(otp, link);

    if (!mounted) return;
    setState(() {
      _secureResult = native == null
          ? 'malicious app captured: '
                '${simCaptured ?? '(nothing - permission/allowlist enforced)'}'
          : '$native\n'
                'Delivery is gated by a signature-level permission, so the '
                'unsigned com.dvma.attacker app receives nothing.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CrossAppOtpCredentialLeakScreen.vulnId,
      difficulty: DvmaDifficulty.medium,
      title: 'Cross-App OTP / Credential Leak',
      explanation:
          'A 2FA authenticator publishes the current OTP and an auth deep link '
          '(myauth://login?otp=...&token=...) to an UNPROTECTED cross-app '
          'surface. Because that surface has no access control, any co-resident '
          'app can harvest the second factor - the Authenticator '
          'CVE-2026-26123 class. On Android this is an unprotected broadcast '
          'the companion com.dvma.attacker app receives; the iOS peer is a '
          'shared pasteboard / custom URL scheme / App Group. A secure design '
          'gates delivery behind a signature-level permission (or a private, '
          'per-recipient channel) so an arbitrary app gets nothing.',
      children: [
        DemoActionButton(
          label: 'Broadcast OTP (unprotected)',
          onPressed: () => _runUnprotected(),
        ),
        if (_issued != null)
          EvidencePanel(label: 'authenticator issued', value: _issued!),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'what the malicious co-resident app reads',
            value: _vulnResult!,
          ),
        DemoActionButton(
          label: 'Broadcast OTP (permission-scoped)',
          onPressed: () => _runSecure(),
        ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what the attacker gets on the secure channel',
            value: _secureResult!,
          ),
      ],
    );
  }
}
