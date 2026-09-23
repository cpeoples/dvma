import 'dart:async';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/widgets/qr_scan_button.dart';
import 'scan_action_dispatcher.dart';

/// QR / NFC Scan -> Privileged Action Without Confirmation.
///
/// A scanned QR/NFC tag from an untrusted caller is forwarded straight to a
/// privileged action / automation trigger with no user confirmation, so a
/// co-resident app or a planted tag executes it silently (Home Assistant
/// Companion GHSA NFC/QR class).
class QrNfcToPrivilegedActionScreen extends StatefulWidget {
  const QrNfcToPrivilegedActionScreen({super.key});

  static const String vulnId = 'qr_nfc_to_privileged_action';

  @override
  State<QrNfcToPrivilegedActionScreen> createState() =>
      _QrNfcToPrivilegedActionScreenState();
}

class _QrNfcToPrivilegedActionScreenState
    extends State<QrNfcToPrivilegedActionScreen> {
  // A planted NFC tag fed by a co-resident, untrusted app.
  static const ScanEvent _maliciousScan = ScanEvent(
    source: ScanSource.nfc,
    callerPackage: 'com.evil.tagwriter',
    callerTrusted: false,
    action: ScanActionDispatcher.privilegedAction,
  );

  String? _vulnResult;
  String? _secureResult;

  String _render(ScanActionResult r, ScanEvent event) {
    final b = StringBuffer();
    b.writeln('scan source   : ${event.source.name}');
    b.writeln(
      'caller        : ${event.callerPackage} '
      '(trusted=${event.callerTrusted})',
    );
    b.writeln('user confirmed: ${event.userConfirmed}');
    b.writeln('action        : ${event.action}');
    b.writeln('executed      : ${r.executed}');
    b.writeln('blocked       : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason  : ${r.blockReason}');
    }
    if (r.executedAction != null) {
      b.writeln('fired action  : ${r.executedAction}');
    }
    b.writeln('silently triggered : ${r.silentlyTriggered(event)}');
    return b.toString().trimRight();
  }

  Future<void> _run([ScanEvent event = _maliciousScan]) async {
    const dispatcher = ScanActionDispatcher();

    // VULN: the untrusted scan fires the automation immediately.
    final vuln = dispatcher.dispatch(event);

    // SECURE: untrusted source + no confirmation -> refused.
    final secure = dispatcher.dispatchSafe(event);

    // real artifact: record the untrusted scan that silently fired the
    // privileged automation with no source auth / no confirmation.
    await DvmaEvidence.record(
      QrNfcToPrivilegedActionScreen.vulnId,
      'scan-action',
      'source=${event.source.name} caller=${event.callerPackage} '
          'trusted=${event.callerTrusted} action=${event.action} '
          'executed=${vuln.executed} firedAction=${vuln.executedAction} '
          'silentlyTriggered=${vuln.silentlyTriggered(event)}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln, event);
      _secureResult = _render(secure, event);
    });
  }

  // Optional live scan: a scanned QR is an untrusted source carrying the
  // decoded string as its action, exercising the same dispatch path.
  void _onScanned(String decoded) => unawaited(
    _run(
      ScanEvent(
        source: ScanSource.qr,
        callerPackage: 'camera-scan',
        callerTrusted: false,
        action: decoded,
      ),
    ),
  );

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: QrNfcToPrivilegedActionScreen.vulnId,
      title: 'QR / NFC Scan -> Privileged Action',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A scanned QR code or tapped NFC tag carries a payload naming a '
          'privileged automation (${ScanActionDispatcher.privilegedAction}). '
          'The app forwards that payload straight to the action dispatcher with '
          'NO authentication of the scan SOURCE and NO explicit user '
          'confirmation, so a planted/overwritten NFC tag fed by a co-resident '
          'app (com.evil.tagwriter) silently triggers the automation (Home '
          'Assistant Companion GHSA NFC/QR class). This is an offline, '
          'deterministic simulation: a scan event carries its source, caller '
          'trust, and payload. The secure path requires BOTH a trusted scan '
          'source AND an explicit user confirmation before firing.',
      children: [
        DemoActionButton(
          label: 'Tap planted NFC tag (untrusted caller)',
          onPressed: () => _run(),
        ),
        QrScanButton(onScanned: _onScanned),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'dispatcher.dispatch (no source auth / no confirm)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'gated: trusted source + explicit user confirmation',
            value: _secureResult!,
          ),
      ],
    );
  }
}
