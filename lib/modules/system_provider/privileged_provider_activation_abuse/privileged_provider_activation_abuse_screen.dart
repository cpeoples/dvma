import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'provider_activation_manager.dart';

/// Privileged Provider Activation Abuse.
///
/// An app becomes an enabled system provider through an enablement flow that
/// can be tapjacked/overlaid into the toggle and is never re-confirmed, then
/// exposes a confused-deputy path so the granted capability is driven for an
/// untrusted caller (Android tapjack-to-enable phone-account CVE-2023-20913
/// class).
class PrivilegedProviderActivationAbuseScreen extends StatefulWidget {
  const PrivilegedProviderActivationAbuseScreen({super.key});

  static const String vulnId = 'privileged_provider_activation_abuse';

  @override
  State<PrivilegedProviderActivationAbuseScreen> createState() =>
      _PrivilegedProviderActivationAbuseScreenState();
}

class _PrivilegedProviderActivationAbuseScreenState
    extends State<PrivilegedProviderActivationAbuseScreen> {
  static const ProviderType _target = ProviderType.phoneAccount;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _renderVuln(EnablementResult enable, InvocationResult invoke) {
    final b = StringBuffer();
    b.writeln('provider           : ${_target.label}');
    b.writeln('capability         : ${_target.capability}');
    b.writeln('enable() enabled   : ${enable.enabled}');
    b.writeln('tap obscured/coerced: ${enable.coerced}');
    b.writeln('invoke() caller    : ${invoke.caller}');
    b.writeln('capability driven  : ${invoke.performed}');
    b.writeln('confused deputy    : ${invoke.confusedDeputy}');
    return b.toString().trimRight();
  }

  String _renderSecure(EnablementResult enable, InvocationResult invoke) {
    final b = StringBuffer();
    b.writeln('provider           : ${_target.label}');
    b.writeln('enableSafe enabled : ${enable.enabled}');
    if (enable.denyReason != null) {
      b.writeln('enable deny reason : ${enable.denyReason}');
    }
    b.writeln('invokeSafe driven  : ${invoke.performed}');
    if (invoke.denyReason != null) {
      b.writeln('invoke deny reason : ${invoke.denyReason}');
    }
    b.writeln('confused deputy    : ${invoke.confusedDeputy}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: enumerate the actually-enabled privileged providers
    // via Settings.Secure (enabled IMEs / accessibility services / notification
    // listeners), the OS record of which apps hold system-provider status.
    final native = await SystemProviderBridge.enabledProviders();

    // VULN: enablement toggle tapped THROUGH an attacker overlay (obscured),
    // then the granted phone-account capability driven for the attacker.
    final vulnMgr = ProviderActivationManager();
    final vulnEnable = vulnMgr.enable(_target, obscuredByOverlay: true);
    final vulnInvoke = vulnMgr.invoke(
      _target,
      ProviderActivationManager.attackerPackage,
    );

    // SECURE: the obscured tap is refused, so the capability never activates.
    final secureMgr = ProviderActivationManager();
    final secureEnable = secureMgr.enableSafe(_target, obscuredByOverlay: true);
    final secureInvoke = secureMgr.invokeSafe(
      _target,
      ProviderActivationManager.attackerPackage,
    );

    await DvmaEvidence.record(
      PrivilegedProviderActivationAbuseScreen.vulnId,
      'provider-activation',
      'enabledProviders=${native ?? 'unavailable (off-Android fallback)'} :: '
          'coercedEnable=${vulnEnable.coerced} :: '
          'confusedDeputy=${vulnInvoke.confusedDeputy}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? 'native unavailable (off-Android fallback)';
      _vulnResult = _renderVuln(vulnEnable, vulnInvoke);
      _secureResult = _renderSecure(secureEnable, secureInvoke);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PrivilegedProviderActivationAbuseScreen.vulnId,
      title: 'Privileged Provider Activation Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Becoming an enabled system provider (accessibility, notification '
          'listener, VPN, IME, device-admin, call-screening, phone-account, '
          'media-projection, credential-provider) is the real security '
          'boundary. Here the enablement toggle is TAPJACKED: the confirming '
          'tap is delivered through an attacker overlay and the flow never '
          'checks FLAG_WINDOW_IS_OBSCURED nor re-confirms, so the app is '
          'silently enabled as a phone-account provider. It then acts as a '
          'confused deputy, driving the granted capability for an untrusted '
          'caller (Android tapjack-to-enable phone-account CVE-2023-20913 '
          'class). The secure path refuses an obscured confirmation and '
          're-checks the caller on invoke. The "real state" panel lists the '
          'providers actually enabled on this device via Settings.Secure; to '
          'fully arm one, enable it in Settings (e.g. the DVMA custom keyboard, '
          'or an accessibility service).',
      children: [
        DemoActionButton(
          label: 'Tapjack the enablement toggle',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real enabled providers (native, Settings.Secure)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'coerced enablement -> confused deputy',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'obscured tap refused, caller re-checked',
            value: _secureResult!,
          ),
      ],
    );
  }
}
