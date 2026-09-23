import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'grant_uri_broker.dart';

/// URI Permission / GRANT_URI_PERMISSIONS Abuse.
///
/// A forwarded/redirected Intent carries FLAG_GRANT_READ/WRITE_URI_PERMISSION
/// to a private content:// URI, so a malicious app is transitively granted
/// access to files it should not reach (Pixel CVE-2024-27222 Intent-redirect +
/// grant-URI class).
class GrantUriPermissionAbuseScreen extends StatefulWidget {
  const GrantUriPermissionAbuseScreen({super.key});

  static const String vulnId = 'grant_uri_permission_abuse';

  @override
  State<GrantUriPermissionAbuseScreen> createState() =>
      _GrantUriPermissionAbuseScreenState();
}

class _GrantUriPermissionAbuseScreenState
    extends State<GrantUriPermissionAbuseScreen> {
  static const String _attacker = 'com.evil.exfil';

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  ForwardedIntent get _malicious => const ForwardedIntent(
    callerPackage: _attacker,
    // Attacker redirects the Intent back at their own component.
    targetPackage: _attacker,
    dataUri: GrantUriBroker.privateUri,
    flags: UriGrantFlags(read: true, write: true),
  );

  String _render(GrantOutcome o) {
    final b = StringBuffer();
    b.writeln('private uri     : ${o.uri}');
    b.writeln('granted to      : ${o.grantedTo ?? '(nobody)'}');
    b.writeln('forwarded flags : ${o.effectiveFlags}');
    b.writeln('blocked         : ${o.blocked}');
    if (o.blockReason != null) {
      b.writeln('block reason    : ${o.blockReason}');
    }
    b.writeln('leaked to attacker : ${o.leakedToAttacker}');
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: forward the untrusted Intent verbatim (flags + target intact).
    final vuln = GrantUriBroker.forward(_malicious);
    // SECURE: strip grant flags on redirect + enforce a target allowlist.
    final secure = GrantUriBroker.forwardSafe(_malicious);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
    // On Android, perform the real grantor-side URI-grant op against the
    // exported provider (Intent grant flags + grantUriPermission), recording
    // the leaked grant.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await ProviderIpcBridge.grantUri();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      GrantUriPermissionAbuseScreen.vulnId,
      'uri-grant',
      'real URI grant handed to an external target:\n$native',
    );
    if (!mounted) return;
    setState(() {
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: GrantUriPermissionAbuseScreen.vulnId,
      title: 'URI Permission / GRANT_URI_PERMISSIONS Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app receives an Intent from an untrusted caller and forwards it '
          'onward WITHOUT stripping the grant flags. The forwarded Intent still '
          'carries FLAG_GRANT_READ/WRITE_URI_PERMISSION pointing at a PRIVATE '
          'content:// provider URI the app can read, so the transitive grant '
          'reaches the attacker-chosen target - handing a malicious app '
          'read/write access to files it should never reach (Pixel '
          'CVE-2024-27222 Intent-redirect + grant-URI class). This is an '
          'offline, deterministic simulation: the broker returns which package '
          'ended up holding the grant. The secure path strips inbound grant '
          'flags on redirect and only forwards to a trusted target allowlist.',
      children: [
        DemoActionButton(label: 'Forward redirected Intent', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'forwarded verbatim (grant flags intact)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'flags stripped + target allowlist',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real URI grant to external target (grantUriPermission)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
