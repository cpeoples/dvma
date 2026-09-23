import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Weak / Outdated TLS Config.
///
/// Negotiates deprecated TLS versions / weak cipher suites.
class WeakTlsConfigScreen extends StatefulWidget {
  const WeakTlsConfigScreen({super.key});

  static const String vulnId = 'weak_tls_config';

  @override
  State<WeakTlsConfigScreen> createState() => _WeakTlsConfigScreenState();
}

class _WeakTlsConfigScreenState extends State<WeakTlsConfigScreen> {
  // VULN: the client's intended policy permits deprecated protocol versions
  // and known-weak cipher suites (RC4, 3DES, export-grade, no forward secrecy).
  // Modern OpenSSL removes SSLv3/RC4 outright, so we cannot literally negotiate
  // them here, instead we make a TLS connection (accepting any cert, as a
  // weakly-configured client would) and report the actual negotiated protocol
  // and certificate. testssl.sh / mitmproxy against the same endpoint confirm
  // whether the *server* still offers the weak options this client would take.
  static const List<String> allowedProtocols = ['SSLv3', 'TLS 1.0', 'TLS 1.2'];
  static const List<String> allowedCiphers = [
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
  ];

  String? _handshake;
  bool _connecting = false;

  Future<void> _connect() async {
    setState(() {
      _connecting = true;
      _handshake = null;
    });

    final base = context.read<AppConfig>().captureBase;
    final uri = Uri.parse(base.replaceFirst(RegExp('^http:'), 'https:'));
    final host = uri.host;
    final port = uri.hasPort ? uri.port : 443;

    var result = '';
    try {
      // A weakly-configured client that also skips cert validation, the real
      // negotiated protocol is read off the live socket.
      final socket = await SecureSocket.connect(
        host,
        port,
        onBadCertificate: (_) => true,
        timeout: const Duration(seconds: 6),
      );
      final proto = socket.selectedProtocol ?? 'unknown';
      final cert = socket.peerCertificate;
      result =
          'connected $host:$port; negotiated=$proto; '
          'peer=${cert?.subject ?? "(none)"}; '
          'client would also accept: ${allowedProtocols.join(", ")}';
      await socket.close();
      socket.destroy();
    } catch (e) {
      final s = e.toString();
      result =
          'connect $host:$port failed: '
          '${s.length <= 120 ? s : '${s.substring(0, 117)}...'}';
    }

    await DvmaEvidence.record(
      WeakTlsConfigScreen.vulnId,
      'tls-negotiation',
      '$result\npermitted ciphers: ${allowedCiphers.join(", ")}',
    );

    if (!mounted) return;
    setState(() {
      _connecting = false;
      _handshake = result;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WeakTlsConfigScreen.vulnId,
      title: 'Weak / Outdated TLS Config',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The TLS client permits deprecated protocol versions (SSLv3/TLS 1.0) '
          'and weak cipher suites (RC4/3DES/export), with no forward secrecy or '
          'downgrade protection, and skips certificate validation. This makes a '
          'TLS connection to your capture host and reports the actual '
          'negotiated protocol/cert; run testssl.sh against the endpoint to '
          'confirm the weak options a downgrade attacker would force.',
      children: [
        EvidencePanel(
          label: 'permitted protocols',
          value: allowedProtocols.join(', '),
        ),
        EvidencePanel(
          label: 'permitted ciphers',
          value: allowedCiphers.join('\n'),
        ),
        DemoActionButton(
          label: _connecting ? 'Negotiating…' : 'Negotiate TLS',
          onPressed: _connecting ? () {} : () => _connect(),
        ),
        if (_handshake != null)
          EvidencePanel(label: 'negotiated (real socket)', value: _handshake!),
      ],
    );
  }
}
