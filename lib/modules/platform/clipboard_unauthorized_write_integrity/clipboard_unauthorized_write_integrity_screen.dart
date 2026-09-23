import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'clipboard_writer.dart';

/// Clipboard Unauthorized Write / Integrity Tampering.
///
/// Untrusted content overwrites the system clipboard with no user gesture or
/// origin check, so the user copies address A but pastes attacker address B.
class ClipboardUnauthorizedWriteIntegrityScreen extends StatefulWidget {
  const ClipboardUnauthorizedWriteIntegrityScreen({super.key});

  static const String vulnId = 'clipboard_unauthorized_write_integrity';

  @override
  State<ClipboardUnauthorizedWriteIntegrityScreen> createState() =>
      _ClipboardUnauthorizedWriteIntegrityScreenState();
}

class _ClipboardUnauthorizedWriteIntegrityScreenState
    extends State<ClipboardUnauthorizedWriteIntegrityScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(ClipboardWriteResult r) {
    final b = StringBuffer();
    b.writeln('write origin    : ${r.origin}');
    b.writeln('attempted value : ${r.attemptedValue}');
    b.writeln('wrote           : ${r.wrote}');
    b.writeln('clipboard now   : ${r.clipboardAfter}');
    b.writeln('tampered        : ${r.tampered}');
    if (r.denyReason != null) {
      b.writeln('reason          : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // The user copied THEIR address into the clipboard.
    final vulnClipboard = SystemClipboard(ClipboardWriter.userAddress);
    // VULN: a hostile WebView page overwrites the clipboard with no gesture.
    final vuln = ClipboardWriter(vulnClipboard).writeFromContent(
      ClipboardWriter.untrustedOrigin,
      ClipboardWriter.attackerAddress,
    );

    final secureClipboard = SystemClipboard(ClipboardWriter.userAddress);
    // SECURE: same untrusted origin, no valid gesture -> refused.
    final secure = ClipboardWriter(secureClipboard).writeFromContentSafe(
      ClipboardWriter.untrustedOrigin,
      ClipboardWriter.attackerAddress,
    );

    // real artifact: perform the genuine integrity tampering by overwriting the
    // system clipboard with the attacker's address (no gesture / origin check).
    if (vuln.tampered) {
      try {
        await Clipboard.setData(
          const ClipboardData(text: ClipboardWriter.attackerAddress),
        );
      } on MissingPluginException {
        // No platform clipboard in the test harness.
      } catch (_) {}
    }
    await DvmaEvidence.record(
      ClipboardUnauthorizedWriteIntegrityScreen.vulnId,
      'clipboard',
      'untrusted origin=${vuln.origin} silently overwrote clipboard with '
          'attacker address=${ClipboardWriter.attackerAddress} '
          '(user had copied=${ClipboardWriter.userAddress})',
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
      vulnId: ClipboardUnauthorizedWriteIntegrityScreen.vulnId,
      title: 'Clipboard Unauthorized Write / Integrity Tampering',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Untrusted content - a page loaded in the app WebView or another '
          'app - overwrites the system clipboard with NO user gesture and NO '
          'origin check. The user copies their own wallet address, but before '
          'they paste, attacker-controlled content silently swaps the '
          'clipboard for the attacker\'s address, so the user pastes the wrong '
          'value (a clipboard-hijack / address-swap). The attacker address is '
          'written to the REAL system clipboard (Clipboard.setData); the '
          'origin/gesture decision is the offline contrast. The secure path '
          'requires a trusted origin '
          'plus a genuine user-gesture token and refuses untrusted writes, '
          'preserving what the user copied.',
      children: [
        DemoActionButton(
          label: 'Let untrusted page overwrite clipboard',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'untrusted origin swapped clipboard (paste is attacker\'s)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'trusted origin + gesture required (user value preserved)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
