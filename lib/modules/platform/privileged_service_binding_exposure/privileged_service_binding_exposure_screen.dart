import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'service_binder_host.dart';

/// Privileged Service Binding Exposure.
///
/// An exported bindable Service hands any caller a privileged Binder with no
/// caller-identity check, so an untrusted client reads the secret and elevates
/// its role, and state set by one client leaks to another.
class PrivilegedServiceBindingExposureScreen extends StatefulWidget {
  const PrivilegedServiceBindingExposureScreen({super.key});

  static const String vulnId = 'privileged_service_binding_exposure';

  @override
  State<PrivilegedServiceBindingExposureScreen> createState() =>
      _PrivilegedServiceBindingExposureScreenState();
}

class _PrivilegedServiceBindingExposureScreenState
    extends State<PrivilegedServiceBindingExposureScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _renderVuln(
    ServiceBindResult bind,
    ServiceCallResult read,
    ServiceCallResult elevate,
    String crossClientRole,
  ) {
    final b = StringBuffer();
    b.writeln('caller package     : ${bind.callerPackage}');
    b.writeln('bound              : ${bind.bound}');
    b.writeln('caller checked     : ${bind.callerChecked}');
    b.writeln('readSecret ran     : ${read.privilegedCallSucceeded}');
    b.writeln('secret leaked      : ${read.value}');
    b.writeln('elevateRole ran    : ${elevate.privilegedCallSucceeded}');
    b.writeln('attacker role now  : ${elevate.value}');
    b.writeln(
      'trusted-client view: role of ${ServiceBinderHost.trustedPackage}'
      ' = $crossClientRole',
    );
    b.writeln(
      'privileged hit     : '
      '${bind.bound && !bind.callerChecked && read.privilegedCallSucceeded}',
    );
    return b.toString().trimRight();
  }

  String _renderSecure(ServiceBindResult bind) {
    final b = StringBuffer();
    b.writeln('caller package     : ${bind.callerPackage}');
    b.writeln('bound              : ${bind.bound}');
    b.writeln('caller checked     : ${bind.callerChecked}');
    if (bind.denyReason != null) {
      b.writeln('deny reason        : ${bind.denyReason}');
    }
    b.writeln('privileged hit     : ${bind.bound}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: the attacker binds the exported service, reads the secret and
    // elevates its own role - shared state that the trusted client would see.
    final vulnHost = ServiceBinderHost();
    final vulnBind = vulnHost.bind(ServiceBinderHost.attackerPackage);
    final read = vulnBind.binder!.readSecret();
    final elevate = vulnBind.binder!.elevateRole();
    final crossClientRole = vulnHost.roleOf(
      ServiceBinderHost.attackerPackage,
    ); // set by attacker

    // SECURE: the service verifies the caller's signature before binding, so
    // the untrusted client never receives a usable binder.
    final secureHost = ServiceBinderHost();
    final secureBind = secureHost.bindSafe(ServiceBinderHost.attackerPackage);

    // On Android, actively bind DVMA's real exported PrivilegedService
    // in-process and invoke its Binder method, capturing the served secret.
    final applied = await ComponentIpcBridge.bindPrivilegedService();
    if (applied != null) {
      await DvmaEvidence.record(
        PrivilegedServiceBindingExposureScreen.vulnId,
        'service-served-bound-client',
        'exported service served a privileged call to a bound external client: $applied',
      );
    }

    setState(() {
      _vulnResult = _renderVuln(vulnBind, read, elevate, crossClientRole);
      _secureResult = _renderSecure(secureBind);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PrivilegedServiceBindingExposureScreen.vulnId,
      title: 'Privileged Service Binding Exposure',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported, bindable Service exposes a privileged Binder interface '
          '(AIDL / Messenger) that any app can bindService() to and invoke '
          'with NO caller-identity or permission check. An untrusted client '
          'reads a protected secret, elevates its role, and can observe state '
          'another client established - the BINDING model is the boundary '
          '(Android service IPC MASTG-KNOW-0133). This is an offline, '
          'deterministic simulation. The secure path verifies the caller '
          'against a signature-level allowlist before returning a usable '
          'binder, refusing the untrusted client.',
      children: [
        DemoActionButton(
          label: 'Bind service from untrusted app',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unchecked bind: privileged calls succeed',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'signature-checked bind: untrusted caller refused',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported PrivilegedService bound in-process',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
