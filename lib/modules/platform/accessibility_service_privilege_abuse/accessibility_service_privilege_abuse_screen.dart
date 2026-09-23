import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'a11y_service.dart';

/// AccessibilityService Privilege Abuse.
///
/// An AccessibilityService performs a privileged action (background activity
/// launch, hiding UI, injecting a gesture) with insufficient caller /
/// service-state validation (Android AccessibilityServiceConnection
/// CVE-2025-26462 / CVE-2023-21109 class).
class AccessibilityServicePrivilegeAbuseScreen extends StatefulWidget {
  const AccessibilityServicePrivilegeAbuseScreen({super.key});

  static const String vulnId = 'accessibility_service_privilege_abuse';

  @override
  State<AccessibilityServicePrivilegeAbuseScreen> createState() =>
      _AccessibilityServicePrivilegeAbuseScreenState();
}

class _AccessibilityServicePrivilegeAbuseScreenState
    extends State<AccessibilityServicePrivilegeAbuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(A11yResult r) {
    final b = StringBuffer();
    b.writeln('action requested   : ${r.kind.name}');
    b.writeln('performed          : ${r.performed}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('effect             : ${r.effect}');
    b.writeln('privilege abused   : ${r.privilegeAbused}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    const action = A11yService.maliciousLaunch;
    // VULN: the service launches a background phishing/consent activity with no
    // foreground a11y event or state check.
    final vuln = A11yService(userEnabled: true).perform(action);
    // SECURE: the same action is refused, a background launch is not on the
    // self-initiable allowlist and has no genuine foreground event.
    final secure = A11yService(userEnabled: true).performSafe(action);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, report the real declared-but-unguarded AccessibilityService
    // state and read back the native evidence.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await PlatformIpcBridge.accessibilityServiceState();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      AccessibilityServicePrivilegeAbuseScreen.vulnId,
      'accessibility-service-state',
      'real declared AccessibilityService state:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AccessibilityServicePrivilegeAbuseScreen.vulnId,
      title: 'AccessibilityService Privilege Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An AccessibilityService performs a PRIVILEGED action - launching an '
          'activity from the background, hiding/suppressing UI, injecting a '
          'gesture - with INSUFFICIENT caller / service-state validation, so '
          'the a11y capability is abused for privilege escalation or UI '
          'manipulation (Android AccessibilityServiceConnection CVE-2025-26462 '
          '/ CVE-2023-21109 class). Here the vulnerable service launches a fake '
          'consent activity from the background with no genuine foreground a11y '
          'event behind it. This is an offline, deterministic simulation. The '
          'secure path requires the service to be user-enabled AND the action '
          'to be tied to a real foreground a11y event AND on an allowlist of '
          'permitted actions, refusing background launches / UI hiding.',
      children: [
        DemoActionButton(
          label: 'Trigger background activity launch',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'a11y action runs with no state/event check',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'enabled + foreground-event + allowlist enforced (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real declared AccessibilityService state',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
