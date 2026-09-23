import 'dart:io';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'local_service.dart';

/// Unauthenticated Local / Loopback Service.
///
/// The app opens a privileged service on 127.0.0.1. The vulnerable path serves
/// any local caller (co-resident app or DNS-rebinding web page); the secure
/// path requires an unpredictable per-session token and validates Origin/Host.
class UnauthenticatedLocalLoopbackServiceScreen extends StatefulWidget {
  const UnauthenticatedLocalLoopbackServiceScreen({super.key});

  static const String vulnId = 'unauthenticated_local_loopback_service';

  @override
  State<UnauthenticatedLocalLoopbackServiceScreen> createState() =>
      _UnauthenticatedLocalLoopbackServiceScreenState();
}

class _UnauthenticatedLocalLoopbackServiceScreenState
    extends State<UnauthenticatedLocalLoopbackServiceScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _liveResult;

  String _render(LocalServiceResult r) {
    final b = StringBuffer();
    b.writeln('loopback port      : 127.0.0.1:${LocalService.loopbackPort}');
    b.writeln('caller origin      : ${r.callerOrigin}');
    b.writeln('auth checked       : ${r.authChecked}');
    b.writeln('served             : ${r.served}');
    b.writeln(
      'response data      : ${r.responseData.isEmpty ? '(none)' : r.responseData}',
    );
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('data exposed       : ${r.dataExposed}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: the unauthenticated service serves the rebinding attacker.
    final vuln = LocalService().handle(LocalService.attackerRequest);

    // SECURE: token + origin/host validation rejects the same attacker.
    final secure = LocalService().handleSafe(LocalService.attackerRequest);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real side effect: actually bind a dart:io HttpServer on 127.0.0.1 with
    // no authentication that serves the privileged data to any local caller,
    // then hit it over the wire with http.get and record the exposed response.
    await _runLiveLoopback();
  }

  Future<void> _runLiveLoopback() async {
    HttpServer? server;
    try {
      // Ephemeral port (0) so we never collide with a real service.
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      // No token check, no Origin/Host validation: serve everyone.
      server.listen((HttpRequest req) {
        req.response
          ..statusCode = 200
          ..write(LocalService.privilegedData);
        req.response.close();
      });
      final port = server.port;
      final resp = await http
          .get(Uri.parse('http://127.0.0.1:$port/getSecrets'))
          .timeout(const Duration(seconds: 5));
      final live =
          'bound real loopback service 127.0.0.1:$port (no auth)\n'
          'unauthenticated GET /getSecrets -> ${resp.statusCode}\n'
          'exposed response: ${resp.body}';
      // real artifact: the unauthenticated response read off the live socket.
      await DvmaEvidence.record(
        UnauthenticatedLocalLoopbackServiceScreen.vulnId,
        'loopback-service',
        'real HttpServer on 127.0.0.1:$port served unauthenticated '
            'GET /getSecrets status=${resp.statusCode} body=${resp.body}',
      );
      if (!mounted) return;
      setState(() => _liveResult = live);
    } catch (e) {
      // Hosts without socket access (e.g. some CI sandboxes) still have the
      // in-memory simulation + evidence line above.
      await DvmaEvidence.record(
        UnauthenticatedLocalLoopbackServiceScreen.vulnId,
        'loopback-service',
        'live loopback bind/get attempted, error=$e',
      );
    } finally {
      await server?.close(force: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnauthenticatedLocalLoopbackServiceScreen.vulnId,
      title: 'Unauthenticated Local / Loopback Service',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app opens a privileged service (an IPC / debug / WebView bridge) '
          'on the loopback interface and trusts every caller simply because the '
          'socket is "only local". With no token and no Origin/Host check, a '
          'co-resident app can invoke privileged operations, and a remote web '
          'page can reach 127.0.0.1 via DNS rebinding and read the app\'s '
          'secrets. This demo binds a REAL loopback HttpServer on 127.0.0.1 '
          'with no token/Origin check and issues an unauthenticated '
          'GET /getSecrets over the socket, recording the exposed response as '
          'a pullable artifact (the in-memory panels show the same attacker '
          'request against a tokened, Origin/Host-validating handler for '
          'contrast). The secure path requires an '
          'unpredictable per-session token and validates the Origin/Host, '
          'rejecting untokened and rebinding callers.',
      children: [
        DemoActionButton(
          label: 'Send rebinding request to loopback',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unauthenticated caller served (privileged data exposed)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'token + origin check rejects rebinding caller',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL loopback service: unauthenticated response over 127.0.0.1',
            value: _liveResult!,
          ),
      ],
    );
  }
}
