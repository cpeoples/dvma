import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'device_policy_controller.dart';

/// Device Policy / MDM Capability Abuse.
///
/// A Device Admin / DevicePolicyManager receiver is a device-wide policy
/// authority but validates the caller / parameters insufficiently, so an
/// untrusted caller can trigger a device wipe or weaken the password policy
/// (Android DevicePolicyManagerService logic-flaw CVE-2025-48553 class).
class DevicePolicyMdmCapabilityAbuseScreen extends StatefulWidget {
  const DevicePolicyMdmCapabilityAbuseScreen({super.key});

  static const String vulnId = 'device_policy_mdm_capability_abuse';

  @override
  State<DevicePolicyMdmCapabilityAbuseScreen> createState() =>
      _DevicePolicyMdmCapabilityAbuseScreenState();
}

class _DevicePolicyMdmCapabilityAbuseScreenState
    extends State<DevicePolicyMdmCapabilityAbuseScreen> {
  static const DevicePolicy _policy = DevicePolicy.wipeData;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(PolicyResult r) {
    final b = StringBuffer();
    b.writeln('caller package     : ${r.callerPackage}');
    b.writeln(
      'active admin        : ${DevicePolicyController.registeredAdmin}',
    );
    b.writeln('caller is admin    : ${r.callerIsActiveAdmin}');
    b.writeln('policy             : ${r.policy.label}');
    b.writeln('value              : ${r.value}');
    b.writeln('applied            : ${r.applied}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: query DevicePolicyManager for this app's actual
    // device-admin / device-owner posture (isAdminActive / activeAdmins /
    // isDeviceOwner). Off-Android the bridge returns null -> in-memory model.
    final native = await SystemProviderBridge.devicePolicyState();

    // VULN: an untrusted caller triggers a device wipe; the caller is never
    // checked against the registered active admin.
    final vulnCtl = DevicePolicyController();
    final vuln = vulnCtl.applyPolicy(
      DevicePolicyController.attackerPackage,
      _policy,
      true,
    );

    // SECURE: the same untrusted caller is refused for not being the active
    // admin, so the wipe never applies.
    final secureCtl = DevicePolicyController();
    final secure = secureCtl.applyPolicySafe(
      DevicePolicyController.attackerPackage,
      _policy,
      true,
    );

    // Record the real device-policy state as a pullable/logcat artifact.
    await DvmaEvidence.record(
      DevicePolicyMdmCapabilityAbuseScreen.vulnId,
      'device-policy',
      'nativeState=${native ?? 'unavailable (off-Android fallback)'} :: '
          'vulnUntrustedWipeApplied=${vuln.applied} :: '
          'secureDenyReason=${secure.denyReason}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? 'native unavailable (off-Android fallback)';
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DevicePolicyMdmCapabilityAbuseScreen.vulnId,
      title: 'Device Policy / MDM Capability Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A Device Admin / DevicePolicyManager receiver is a device-wide '
          'policy authority: it can wipe data, disable the camera, or weaken '
          'the password policy. Here policy changes are applied WITHOUT '
          'verifying the caller is the currently-registered active admin and '
          'WITHOUT validating parameters, so an untrusted caller triggers a '
          'full device wipe (and could push a weak password-quality value) - '
          'a privilege escalation across the work-profile / policy boundary '
          '(Android DevicePolicyManagerService logic-flaw CVE-2025-48553 '
          'class). The secure path verifies the caller is the active admin AND '
          'validates the parameter before applying, denying untrusted or '
          'invalid requests. On device the "real state" panel shows this '
          "app's actual DevicePolicyManager posture. To fully arm the "
          'capability, register a DeviceAdminReceiver and activate it via '
          'ACTION_ADD_DEVICE_ADMIN (or provision DVMA as device owner via '
          '`adb dpm set-device-owner`).',
      children: [
        DemoActionButton(
          label: 'Untrusted caller requests wipe-data',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real DevicePolicyManager state (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'no caller/param check -> untrusted wipe applied',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'active-admin + parameter check denies wipe',
            value: _secureResult!,
          ),
      ],
    );
  }
}
