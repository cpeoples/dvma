import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'persistable_uri_vault.dart';

/// Persistent URI-Grant Capability Abuse.
///
/// An exported component takes a persistable URI permission on an
/// attacker-backed `content://` URI, turning a one-shot read into a durable,
/// revocation-resistant capability whose bytes the attacker provider can later
/// swap. The secure path refuses to persist grants for untrusted authorities.
class PersistableUriGrantAbuseScreen extends StatefulWidget {
  const PersistableUriGrantAbuseScreen({super.key});

  static const String vulnId = 'persistable_uri_grant_abuse';

  @override
  State<PersistableUriGrantAbuseScreen> createState() =>
      _PersistableUriGrantAbuseScreenState();
}

class _PersistableUriGrantAbuseScreenState
    extends State<PersistableUriGrantAbuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _renderVuln(PersistGrantResult onReceive, PersistGrantResult later) {
    final b = StringBuffer();
    b.writeln('granted uri        : ${onReceive.uri}');
    b.writeln('provider authority : ${PersistableUriVault.attackerAuthority}');
    b.writeln('persisted          : ${onReceive.persisted}');
    b.writeln('first read         : ${onReceive.dataRead}');
    b.writeln('--- intent ended + transient grant revoked ---');
    b.writeln('later read ok      : ${later.readSucceeded}');
    b.writeln('survives revocation: ${later.survivesRevocation}');
    b.writeln('data swapped       : ${later.dataSwapped}');
    b.writeln('later read         : ${later.dataRead}');
    b.writeln(
      'persistent-grant hit: '
      '${later.survivesRevocation && later.dataSwapped}',
    );
    return b.toString().trimRight();
  }

  String _renderSecure(PersistGrantResult r) {
    final b = StringBuffer();
    b.writeln('granted uri        : ${r.uri}');
    b.writeln('provider authority : ${PersistableUriVault.attackerAuthority}');
    b.writeln('persisted          : ${r.persisted}');
    b.writeln('survives revocation: ${r.survivesRevocation}');
    b.writeln('read succeeded     : ${r.readSucceeded}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('persistent-grant hit: ${r.survivesRevocation}');
    return b.toString().trimRight();
  }

  void _run() {
    const grant = UriGrant(
      uri: PersistableUriVault.attackerUri,
      providerAuthority: PersistableUriVault.attackerAuthority,
      persistable: true,
    );

    // VULN: take the persistable permission, end the intent + revoke the
    // transient grant, then read again - the durable grant still works and the
    // attacker provider now serves swapped, sensitive data.
    final vulnVault = PersistableUriVault();
    final onReceive = vulnVault.receiveGrant(grant);
    vulnVault.endIntentAndRevokeTransient();
    final later = vulnVault.readLater(grant);

    // SECURE: refuse to persist a grant for an untrusted authority; only a
    // transient read is ever allowed.
    final secureVault = PersistableUriVault();
    final secure = secureVault.receiveGrantSafe(grant);

    setState(() {
      _vulnResult = _renderVuln(onReceive, later);
      _secureResult = _renderSecure(secure);
    });
    // On Android, call the real takePersistableUriPermission() on a granted
    // content:// URI, converting a one-shot grant into a durable capability.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await ProviderIpcBridge.grantUri();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      PersistableUriGrantAbuseScreen.vulnId,
      'persistable-uri-grant',
      'attempted durable persistable grant on content:// URI:\n$native',
    );
    if (!mounted) return;
    setState(() {
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PersistableUriGrantAbuseScreen.vulnId,
      title: 'Persistent URI-Grant Capability Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported component receives an attacker-controlled content:// URI '
          'carrying FLAG_GRANT_PERSISTABLE_URI_PERMISSION and calls '
          'takePersistableUriPermission(), converting a one-shot, intent-scoped '
          'grant into a LONG-LIVED capability that survives revocation '
          '(CWE-284 / CWE-266 / CWE-668). Because the URI is backed by the '
          "attacker's own provider, the attacker can later swap the bytes it "
          'serves for the same URI - a transient read becomes durable, mutable '
          'access. The distinguishing bug is the PERSISTENCE. This is an '
          'offline, deterministic simulation. The secure path never persists '
          'grants for untrusted authorities and re-validates the provider on '
          'each use.',
      children: [
        DemoActionButton(
          label: 'Receive persistable grant, then read after revoke',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'persisted grant: durable, swappable capability',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'untrusted authority: persistence refused',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real takePersistableUriPermission (durable capability)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
