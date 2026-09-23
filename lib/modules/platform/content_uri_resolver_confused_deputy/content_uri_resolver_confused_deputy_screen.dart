import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'content_resolver_proxy.dart';

/// content:// URI -> ContentResolver Confused Deputy.
///
/// The app reads an attacker-supplied `content://` URI through its own
/// ContentResolver, becoming a proxy for a privileged provider the caller could
/// never reach directly (Android DownloadProvider CVE-2025-26417 class).
class ContentUriResolverConfusedDeputyScreen extends StatefulWidget {
  const ContentUriResolverConfusedDeputyScreen({super.key});

  static const String vulnId = 'content_uri_resolver_confused_deputy';

  @override
  State<ContentUriResolverConfusedDeputyScreen> createState() =>
      _ContentUriResolverConfusedDeputyScreenState();
}

class _ContentUriResolverConfusedDeputyScreenState
    extends State<ContentUriResolverConfusedDeputyScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(ResolveResult r) {
    final b = StringBuffer();
    b.writeln('caller uid         : ${r.caller}');
    b.writeln('supplied uri       : ${r.uri}');
    b.writeln('authority          : ${r.authority ?? '(unparsed)'}');
    b.writeln('privileged provider: ${r.privileged}');
    b.writeln('opened             : ${r.opened}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('data returned      : ${r.data ?? '(none)'}');
    b.writeln('confused deputy    : ${r.confusedDeputy}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    const uri = ContentResolverProxy.privilegedUri;
    // VULN: the app proxies the attacker's crafted URI with its own privileges.
    final vuln = ContentResolverProxy.seeded().openUri(
      ContentResolverProxy.attackerUid,
      uri,
    );
    // SECURE: the untrusted caller lacks the permission for the private
    // authority, so the proxy refuses to lend its privileges.
    final secure = ContentResolverProxy.seeded().openUriSafe(
      ContentResolverProxy.attackerUid,
      uri,
    );
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
    // On Android, the app reads a caller-supplied content:// URI through its
    // own ContentResolver, the confused-deputy op, against the real exported
    // provider, returning app-private bytes the caller could not reach directly.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await ProviderIpcBridge.openTraversal('../session.token');
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      ContentUriResolverConfusedDeputyScreen.vulnId,
      'confused-deputy-read',
      'app proxied a content:// read through its own ContentResolver, '
          'returning app-private bytes:\n$native',
    );
    if (!mounted) return;
    setState(() {
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ContentUriResolverConfusedDeputyScreen.vulnId,
      title: 'content:// URI -> ContentResolver Confused Deputy',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app takes an ATTACKER-SUPPLIED content:// URI (e.g. from an '
          'intent extra) and reads it through its OWN ContentResolver. Because '
          'the resolver runs with the app\'s identity, the app becomes a '
          'confused-deputy proxy for a privileged, app-private provider '
          '(content://com.dvma.private/tokens) the untrusted caller could never '
          'reach directly - with NO owner/permission validation on the URI '
          '(the Android DownloadProvider CVE-2025-26417 class). This is an '
          'offline, deterministic simulation over in-memory providers. The '
          'secure path validates that the caller is actually permitted to reach '
          'that authority (allowlisted authority + a granted read permission), '
          'refusing to proxy the privileged read for an untrusted caller.',
      children: [
        DemoActionButton(
          label: 'Proxy attacker-supplied content:// URI',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'resolver proxies any authority (confused deputy)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'caller authorization on authority verified (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'app proxied real content:// read (confused deputy)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
