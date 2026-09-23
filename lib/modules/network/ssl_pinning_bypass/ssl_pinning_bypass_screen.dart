import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// SSL Pinning (Trivially Bypassable).
///
/// Pinning is implemented but disabled by a client-side flag / easy hook.
class SslPinningBypassScreen extends StatefulWidget {
  const SslPinningBypassScreen({super.key});

  static const String vulnId = 'ssl_pinning_bypass';

  @override
  State<SslPinningBypassScreen> createState() => _SslPinningBypassScreenState();
}

class _SslPinningBypassScreenState extends State<SslPinningBypassScreen> {
  // VULN: pinning is real, but gated behind a mutable client-side flag and a
  // single _checkPin() function an attacker hooks to always-true. When the flag
  // is off (or the function is hooked), a TLS connection is made and the
  // presented (mitmproxy) certificate is accepted regardless of the pin.
  bool _pinningEnabled = true;
  String? _result;
  bool _connecting = false;

  // A pin that will not match the mitmproxy cert, so pinning (when enabled)
  // genuinely rejects, and bypass genuinely accepts.
  static const String _pinnedSha =
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAA=';

  bool _checkPin(String presentedSha) {
    // Attacker hooks this to `return true;`, or just flips _pinningEnabled.
    if (!_pinningEnabled) return true; // bypass path
    return presentedSha == _pinnedSha;
  }

  static String _spkiSha256(X509Certificate cert) {
    // Pin over the whole DER here for demo purposes (real pins use the SPKI).
    final digest = sha256.convert(cert.der);
    return 'sha256/${base64.encode(digest.bytes)}';
  }

  Future<void> _connectViaMitm() async {
    setState(() {
      _connecting = true;
      _result = null;
    });

    final base = context.read<AppConfig>().captureBase;
    final uri = Uri.parse(base.replaceFirst(RegExp('^http:'), 'https:'));
    final host = uri.host;
    final port = uri.hasPort ? uri.port : 443;

    var summary = '';
    try {
      String? presentedSha;
      final socket = await SecureSocket.connect(
        host,
        port,
        timeout: const Duration(seconds: 6),
        onBadCertificate: (cert) {
          presentedSha = _spkiSha256(cert);
          // The pin decision drives whether the (untrusted) cert is accepted.
          return _checkPin(presentedSha!);
        },
      );
      summary =
          'pinningEnabled=$_pinningEnabled -> MITM cert ACCEPTED '
          '(pinning bypassed); presented=${presentedSha ?? "(trusted chain)"}; '
          'traffic intercepted.';
      await socket.close();
      socket.destroy();
    } on HandshakeException catch (_) {
      summary =
          'pinningEnabled=$_pinningEnabled -> MITM cert REJECTED '
          '(pinning held); handshake aborted.';
    } catch (e) {
      final s = e.toString();
      summary =
          'connect $host:$port -> '
          '${s.length <= 120 ? s : '${s.substring(0, 117)}...'}';
    }

    await DvmaEvidence.record(
      SslPinningBypassScreen.vulnId,
      'pinning',
      summary,
    );

    if (!mounted) return;
    setState(() {
      _connecting = false;
      _result = summary;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SslPinningBypassScreen.vulnId,
      title: 'SSL Pinning (Trivially Bypassable)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Certificate pinning is implemented but gated behind a mutable '
          'client-side flag and a single checkPin() function. An attacker '
          'flips the flag or hooks the function to return true (frida/'
          'objection), and a Burp/mitmproxy cert sails through. This makes a '
          'TLS connection: toggle pinning off (the hook) and the mitm '
          'cert is accepted; leave it on and the handshake is rejected.',
      children: [
        SwitchListTile(
          value: _pinningEnabled,
          onChanged: (v) => setState(() => _pinningEnabled = v),
          title: const Text('pinningEnabled (attacker sets false)'),
          activeColor: DvmaColors.accent,
        ),
        EvidencePanel(label: 'pinned cert', value: _pinnedSha),
        DemoActionButton(
          label: _connecting ? 'Connecting…' : 'Connect through mitmproxy',
          onPressed: _connecting ? () {} : () => _connectViaMitm(),
        ),
        if (_result != null)
          EvidencePanel(label: 'connection result', value: _result!),
      ],
    );
  }
}
