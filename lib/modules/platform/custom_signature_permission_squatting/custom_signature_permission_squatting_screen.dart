import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'custom_permission_guard.dart';

/// Custom Signature-Permission Squatting.
///
/// An IPC component is guarded by a custom permission declared at `normal`
/// level (auto-granted to any requester) or squatted by a malicious app, so the
/// guard the developer trusts is trivially obtained and the interface is
/// externally reachable.
class CustomSignaturePermissionSquattingScreen extends StatefulWidget {
  const CustomSignaturePermissionSquattingScreen({super.key});

  static const String vulnId = 'custom_signature_permission_squatting';

  @override
  State<CustomSignaturePermissionSquattingScreen> createState() =>
      _CustomSignaturePermissionSquattingScreenState();
}

class _CustomSignaturePermissionSquattingScreenState
    extends State<CustomSignaturePermissionSquattingScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(GuardedCallResult r) {
    final b = StringBuffer();
    b.writeln('permission         : ${CustomPermissionGuard.permissionName}');
    b.writeln(
      'operation          : ${CustomPermissionGuard.protectedOperation}',
    );
    b.writeln('app signature      : ${CustomPermissionGuard.appSignature}');
    b.writeln('caller package     : ${r.callerPackage}');
    b.writeln(
      'attacker signature : ${CustomPermissionGuard.attackerSignature}',
    );
    b.writeln('call allowed       : ${r.callAllowed}');
    b.writeln('guard effective    : ${r.guardEffective}');
    b.writeln('attacker held perm : ${r.attackerHeldPermission}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final attacker = CustomPermissionGuard.attackerApp();

    // VULN: normal-level permission auto-granted to the attacker -> guard is
    // ineffective and the protected operation runs.
    final vuln = CustomPermissionGuard().call(attacker);

    // SECURE: signature-level permission + caller signature verification ->
    // the squatter is refused.
    final secure = CustomPermissionGuard().callSafe(attacker);

    // real artifact: record the squatter's successful privileged call through
    // the ineffective normal-level custom permission.
    await DvmaEvidence.record(
      CustomSignaturePermissionSquattingScreen.vulnId,
      'permission-squat',
      'caller=${vuln.callerPackage} obtained normal-level permission='
          '${CustomPermissionGuard.permissionName} and ran protected op='
          '${CustomPermissionGuard.protectedOperation} '
          '(callAllowed=${vuln.callAllowed} guardEffective=${vuln.guardEffective})',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, read the real protectionLevel of DVMA's custom ADMIN_OP
    // permission and runtime checkPermission via PackageManager.
    final native = await SystemProviderBridge.checkCustomPermission();
    if (native != null) {
      await DvmaEvidence.record(
        CustomSignaturePermissionSquattingScreen.vulnId,
        'permission-squat-native',
        'real permission posture: $native',
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CustomSignaturePermissionSquattingScreen.vulnId,
      title: 'Custom Signature-Permission Squatting',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An IPC component is "protected" by a custom permission whose '
          'protectionLevel is normal/dangerous (not signature), or by a '
          'permission NAME a malicious app can define first (install-order '
          'squatting). A normal permission is auto-granted to any app that '
          'requests it, and a squatted permission is attacker-owned - so the '
          'guard is trivially obtained or attacker-controlled and the interface '
          'the developer believes is protected is externally reachable. The '
          'secure path requires protectionLevel: signature AND verifies the '
          'caller\'s signing identity matches the app\'s, refusing the '
          'squatter.',
      children: [
        DemoActionButton(
          label: 'Call guarded IPC as attacker app',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'normal-level permission: attacker auto-granted',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'signature-level + identity check: refused',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real PackageManager protectionLevel + checkPermission',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
