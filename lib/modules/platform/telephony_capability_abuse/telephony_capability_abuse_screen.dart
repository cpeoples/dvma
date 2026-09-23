import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'telephony_gateway.dart';

/// Telephony Capability Abuse.
///
/// A loosely-guarded exported Telecom-like component lets an untrusted caller
/// drive a telephony capability with no per-invocation permission check
/// (Android Telecom permission-bypass CVE-2026-28615 class).
class TelephonyCapabilityAbuseScreen extends StatefulWidget {
  const TelephonyCapabilityAbuseScreen({super.key});

  static const String vulnId = 'telephony_capability_abuse';

  @override
  State<TelephonyCapabilityAbuseScreen> createState() =>
      _TelephonyCapabilityAbuseScreenState();
}

class _TelephonyCapabilityAbuseScreenState
    extends State<TelephonyCapabilityAbuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(TelephonyResult r) {
    final b = StringBuffer();
    b.writeln('capability         : ${r.capability.label}');
    b.writeln('required permission: ${r.capability.requiredPermission}');
    b.writeln('caller             : ${r.caller}');
    b.writeln('argument           : ${r.arg}');
    b.writeln('performed          : ${r.performed}');
    b.writeln('abused (no perm)   : ${r.abused}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const gateway = TelephonyGateway();
    const caller = TelephonyGateway.untrustedCaller;

    // VULN: untrusted caller with no CALL_PHONE permission dials a premium
    // number and it goes through.
    final vuln = gateway.invoke(
      caller,
      TelephonyCapability.placeCall,
      TelephonyGateway.premiumNumber,
    );

    // SECURE: the caller lacks the permission -> refused before dialing.
    final secure = gateway.invokeSafe(
      caller,
      TelephonyCapability.placeCall,
      TelephonyGateway.premiumNumber,
    );

    // real artifact: record the telephony capability abused with no permission.
    await DvmaEvidence.record(
      TelephonyCapabilityAbuseScreen.vulnId,
      'telephony-abuse',
      'caller=${vuln.caller} invoked capability=${vuln.capability.label} '
          '(requires ${vuln.capability.requiredPermission}) arg=${vuln.arg} '
          'performed=${vuln.performed} abused=${vuln.abused}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, build the real ACTION_CALL intent and read the CALL_PHONE
    // runtime permission state, the device-observable missing per-invocation
    // check (placing the call needs the grant + a real SIM).
    final native = await SystemProviderBridge.telephonyCapability(
      number: TelephonyGateway.premiumNumber,
    );
    if (native != null) {
      await DvmaEvidence.record(
        TelephonyCapabilityAbuseScreen.vulnId,
        'telephony-abuse-native',
        'real telephony capability posture: $native',
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: TelephonyCapabilityAbuseScreen.vulnId,
      title: 'Telephony Capability Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported Telecom-like component drives telephony capabilities '
          '(place a call, send an SMS, register a phone account) but performs '
          'NO per-invocation permission check. An untrusted local app that '
          'holds none of the required permissions therefore dials a '
          'premium-rate number on the user\'s behalf (Android Telecom '
          'permission-bypass CVE-2026-28615 class). This is an offline, '
          'deterministic simulation - no call is placed. The secure path '
          'requires the caller to hold the matching permission plus a '
          'per-invocation user confirmation for sensitive actions.',
      children: [
        DemoActionButton(
          label: 'Dial premium number as untrusted app',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'no per-invocation permission check',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'permission + confirmation enforced',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real ACTION_CALL + CALL_PHONE state (device-observable)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
