import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'ime_event_injector.dart';

/// Privileged Input-Provider (IME) Event Injection.
///
/// The default input-method (IME) service accepts injected key/motion events
/// from an untrusted caller because a permission/caller check is missing, so a
/// co-resident app injects synthetic input into other apps (typing, taps,
/// confirmations) for local privilege escalation (Android IME event-injection
/// CVE-2025-26450 class).
class PrivilegedInputProviderInjectionScreen extends StatefulWidget {
  const PrivilegedInputProviderInjectionScreen({super.key});

  static const String vulnId = 'privileged_input_provider_injection';

  @override
  State<PrivilegedInputProviderInjectionScreen> createState() =>
      _PrivilegedInputProviderInjectionScreenState();
}

class _PrivilegedInputProviderInjectionScreenState
    extends State<PrivilegedInputProviderInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(InjectionResult r) {
    final b = StringBuffer();
    b.writeln('caller package     : ${r.callerPackage}');
    b.writeln('caller authorized  : ${r.callerAuthorized}');
    b.writeln('events performed   : ${r.performed}');
    b.writeln(
      'dispatched events  : ${r.performedEvents.isEmpty ? '(none)' : r.performedEvents.join(', ')}',
    );
    b.writeln('victim action      : ${ImeEventInjector.victimAction}');
    b.writeln('sensitive confirmed: ${r.sensitiveActionConfirmed}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: enumerate enabled IMEs / accessibility services /
    // notification listeners via Settings.Secure, the privileged input
    // providers that CAN synthesize/observe events across apps on this device.
    final native = await SystemProviderBridge.enabledProviders();

    // VULN: the IME dispatches injected events for an untrusted caller with no
    // permission check, auto-confirming the sensitive "approve payment" tap.
    final vulnIme = ImeEventInjector();
    final vuln = vulnIme.inject(
      ImeEventInjector.attackerPackage,
      ImeEventInjector.attackerBatch,
    );

    // SECURE: the same untrusted caller is refused for lacking INJECT_EVENTS.
    final secureIme = ImeEventInjector();
    final secure = secureIme.injectSafe(
      ImeEventInjector.attackerPackage,
      ImeEventInjector.attackerBatch,
    );

    await DvmaEvidence.record(
      PrivilegedInputProviderInjectionScreen.vulnId,
      'input-provider-injection',
      'enabledInputProviders=${native ?? 'unavailable (off-Android fallback)'} :: '
          'injectedEvents=${vuln.performedEvents.join(",")} :: '
          'sensitiveActionConfirmed=${vuln.sensitiveActionConfirmed}',
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
      vulnId: PrivilegedInputProviderInjectionScreen.vulnId,
      title: 'Privileged Input-Provider (IME) Event Injection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The default input-method (IME) service is a privileged surface that '
          'can synthesize key and motion events into whatever app has focus. '
          'Here it accepts a batch of injected events from an untrusted '
          'co-resident caller WITHOUT checking that the caller is the system '
          'or holds INJECT_EVENTS, so the attacker drives synthetic taps and '
          'keystrokes into other apps and auto-confirms a sensitive action '
          '(tapping "approve payment"). This is the INJECT direction of the '
          'keyboard boundary (Android IME event-injection CVE-2025-26450 '
          'class), the opposite of read/exfil interception. The secure path '
          'requires the caller to be the system / hold the injection '
          'permission and refuses untrusted callers. The "real state" panel '
          'lists the input providers actually enabled on this device '
          '(Settings.Secure enabled IMEs / accessibility services); enabling '
          'one and granting INJECT_EVENTS / an accessibility service fully arms '
          'the injection path.',
      children: [
        DemoActionButton(
          label: 'Inject events from untrusted app',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real enabled input providers (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'events injected -> sensitive action auto-confirmed',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'untrusted caller refused (no injection permission)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
