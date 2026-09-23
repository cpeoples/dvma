import 'dart:io';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'media_request_broker.dart';

/// Authorization Based on Mutable Resource State.
///
/// A security decision is made on mutable resource existence, so a caller wins
/// read/write access to a not-yet-existing file it should not own (Android
/// MediaProvider TOCTOU/logic CVE-2026-0035 class).
class AuthorizationByMutableResourceStateScreen extends StatefulWidget {
  const AuthorizationByMutableResourceStateScreen({super.key});

  static const String vulnId = 'authorization_by_mutable_resource_state';

  @override
  State<AuthorizationByMutableResourceStateScreen> createState() =>
      _AuthorizationByMutableResourceStateScreenState();
}

class _AuthorizationByMutableResourceStateScreenState
    extends State<AuthorizationByMutableResourceStateScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _realToctou;

  String _render(RequestResult r) {
    final b = StringBuffer();
    b.writeln('caller           : ${r.caller}');
    b.writeln('path             : ${r.path}');
    b.writeln('granted          : ${r.granted}');
    b.writeln('effective owner  : ${r.effectiveOwner}');
    b.writeln('stolen from owner: ${r.stolenFromOwner}');
    if (r.denyReason != null) {
      b.writeln('reason           : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // The attacker requests a path the victim has reserved but not yet written.
    final vuln = MediaRequestBroker.seeded().createRequest(
      MediaRequestBroker.attacker,
      MediaRequestBroker.contestedPath,
    );
    final secure = MediaRequestBroker.seeded().createRequestSafe(
      MediaRequestBroker.attacker,
      MediaRequestBroker.contestedPath,
    );
    // real artifact: record the mutable-state authorization win, the attacker
    // seized ownership of a path the victim had reserved.
    await DvmaEvidence.record(
      AuthorizationByMutableResourceStateScreen.vulnId,
      'mutable-authz',
      'caller=${vuln.caller} path=${vuln.path} granted=${vuln.granted} '
          'effectiveOwner=${vuln.effectiveOwner} '
          'stolenFromOwner=${vuln.stolenFromOwner}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real on-disk TOCTOU: the attacker's grant is decided by File.exists()
    // (time-of-check) and then bound by writing an owner tag (time-of-use). The
    // victim has a stable reservation, but existence, not identity, drives
    // the grant, so the attacker seizes the reserved path on the real disk.
    final real = await _realDiskToctou();
    if (real != null) {
      await DvmaEvidence.record(
        AuthorizationByMutableResourceStateScreen.vulnId,
        'mutable-authz-real',
        real,
      );
      if (!mounted) return;
      setState(() => _realToctou = real);
    }
  }

  /// Performs a genuine check-then-act on the real filesystem: if the reserved
  /// path does not yet exist, grant the attacker and write their owner tag.
  Future<String?> _realDiskToctou() async {
    try {
      final base = await DvmaEvidence.artifactDirPath();
      final dir = Directory(base ?? '${Directory.systemTemp.path}/dvma_authz');
      await dir.create(recursive: true);
      final reserved = File('${dir.path}/private_scan.jpg.owner');
      // Start clean so the demo is deterministic across runs.
      if (await reserved.exists()) await reserved.delete();

      const victim = MediaRequestBroker.victim;
      const attacker = MediaRequestBroker.attacker;

      // TIME-OF-CHECK: authorize purely on mutable existence.
      final grantedToAttacker = !await reserved.exists();
      // TIME-OF-USE: bind the (attacker) owner tag onto the reserved path.
      if (grantedToAttacker) {
        await reserved.writeAsString(attacker, flush: true);
      }
      final effectiveOwner = (await reserved.readAsString()).trim();
      return 'real File.exists() check granted=$grantedToAttacker; wrote owner '
          'tag -> ${reserved.path}; effectiveOwner=$effectiveOwner; '
          'reservedFor=$victim; stolen=${effectiveOwner == attacker}';
    } catch (e) {
      return 'real TOCTOU attempted, error=$e';
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AuthorizationByMutableResourceStateScreen.vulnId,
      title: 'Authorization Based on Mutable Resource State',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A security decision is made on the MUTABLE existence of a resource '
          '- "if the file does not exist yet, grant the caller ownership and '
          'create it" - decoupling the authorization check from the resource '
          'binding. An attacker wins read/write access to a path a victim has '
          'legitimately reserved but not yet written (a TOCTOU / logic flaw, '
          'the Android MediaProvider CVE-2026-0035 class). This is an offline, '
          'deterministic simulation with an in-memory filesystem. The secure '
          'path binds authorization to a stable owner identity captured '
          'atomically, never to mutable existence.',
      children: [
        DemoActionButton(
          label: 'Claim victim\'s reserved path via existence check',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'granted on mutable existence (stole reserved path)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'bound to stable owner identity (refused)',
            value: _secureResult!,
          ),
        if (_realToctou != null)
          EvidencePanel(
            label: 'real on-disk TOCTOU (File.exists then claim)',
            value: _realToctou!,
          ),
      ],
    );
  }
}
