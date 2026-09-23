import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'privileged_action_handler.dart';

/// Clipboard -> Privileged Action Injection.
///
/// Clipboard content sourced from an untrusted origin flows straight into a
/// privileged payment/command action with no validation or confirmation.
class ClipboardToPrivilegedActionInjectionScreen extends StatefulWidget {
  const ClipboardToPrivilegedActionInjectionScreen({super.key});

  static const String vulnId = 'clipboard_to_privileged_action_injection';

  @override
  State<ClipboardToPrivilegedActionInjectionScreen> createState() =>
      _ClipboardToPrivilegedActionInjectionScreenState();
}

class _ClipboardToPrivilegedActionInjectionScreenState
    extends State<ClipboardToPrivilegedActionInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(ActionResult r) {
    final b = StringBuffer();
    b.writeln('action kind          : ${r.kind.name}');
    b.writeln('executed             : ${r.executed}');
    b.writeln('payload              : ${r.payload}');
    b.writeln('injected (untrusted) : ${r.injectedFromUntrusted}');
    if (r.denyReason != null) {
      b.writeln('reason               : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // A hostile page wrote a "pay to attacker" instruction to the clipboard.
    // real side effect: actually place the attacker payee on the system
    // clipboard, then read it back (the untrusted origin -> clipboard hop).
    var clipboardValue = PrivilegedActionHandler.injectedPayee;
    try {
      await Clipboard.setData(
        const ClipboardData(text: PrivilegedActionHandler.injectedPayee),
      );
      final read = await Clipboard.getData(Clipboard.kTextPlain);
      clipboardValue = read?.text ?? PrivilegedActionHandler.injectedPayee;
    } on MissingPluginException {
      // No platform clipboard in the test harness; use the seeded value.
    } catch (_) {}

    final tainted = ClipboardEntry(
      value: clipboardValue,
      origin: PrivilegedActionHandler.untrustedOrigin,
    );
    // VULN: the automation auto-pastes it into the payment field and pays.
    final vuln = const PrivilegedActionHandler().runFromClipboard(tainted);
    // SECURE: untrusted origin -> refused before any payment.
    final secure = const PrivilegedActionHandler().runFromClipboardSafe(
      tainted,
    );
    // real artifact: record the tainted clipboard value that drove the
    // privileged payment.
    await DvmaEvidence.record(
      ClipboardToPrivilegedActionInjectionScreen.vulnId,
      'clipboard-injection',
      'untrusted clipboard value=$clipboardValue drove privileged '
          'action=${vuln.kind.name} executed=${vuln.executed} '
          'payload=${vuln.payload}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ClipboardToPrivilegedActionInjectionScreen.vulnId,
      title: 'Clipboard → Privileged Action Injection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Clipboard content sourced from an untrusted origin flows into a '
          'privileged action - an auto-paste into a payment field or an '
          'assistant/automation step - with no validation and no '
          'confirmation. The taint chain is: untrusted origin → clipboard → '
          'automation → privileged capability. Here a hostile page seeds a '
          '"pay to attacker" instruction and the automation executes the '
          'payment. The tainted value is placed on and read back from the REAL '
          'system clipboard (Clipboard.setData/getData); the payment-decision '
          'logic is the offline contrast. The secure '
          'path refuses clipboard values that did not originate from a trusted '
          'source, validates the payee against an allowlist, and requires '
          'explicit user confirmation.',
      children: [
        DemoActionButton(
          label: 'Auto-run payment from tainted clipboard',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'untrusted clipboard drove privileged payment (injected)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'trusted origin + allowlist + confirmation (refused)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
