import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'clipdata_forwarder.dart';

/// ClipData URI-Grant Leakage.
///
/// The app attaches a private content:// URI to an implicit intent's ClipData
/// with FLAG_GRANT_READ_URI_PERMISSION, silently forwarding a read capability
/// for its own provider to whichever app catches the intent. The secure path
/// sends an explicit, pinned intent with no grant on private URIs.
class ClipdataUriGrantLeakageScreen extends StatefulWidget {
  const ClipdataUriGrantLeakageScreen({super.key});

  static const String vulnId = 'clipdata_uri_grant_leakage';

  @override
  State<ClipdataUriGrantLeakageScreen> createState() =>
      _ClipdataUriGrantLeakageScreenState();
}

class _ClipdataUriGrantLeakageScreenState
    extends State<ClipdataUriGrantLeakageScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _renderVuln(ClipForwardResult r) {
    final b = StringBuffer();
    b.writeln('recipient package  : ${r.recipientPackage}');
    b.writeln('data uri (visible) : ${ClipDataForwarder.publicShareUri}');
    b.writeln('clip uri (hidden)  : ${ClipDataForwarder.privateContentUri}');
    b.writeln('capability forwarded: ${r.capabilityForwarded}');
    b.writeln('recipient can read : ${r.recipientCanRead}');
    b.writeln('leaked uris        : ${r.leakedUris.join(', ')}');
    b.writeln('leaked provider data: ${r.leakedData ?? '(none)'}');
    b.writeln(
      'clip-grant leak hit: '
      '${r.capabilityForwarded && r.recipientPackage == ClipDataForwarder.attackerResolverPackage}',
    );
    return b.toString().trimRight();
  }

  String _renderSecure(ClipForwardResult r) {
    final b = StringBuffer();
    b.writeln('recipient package  : ${r.recipientPackage}');
    b.writeln('capability forwarded: ${r.capabilityForwarded}');
    b.writeln('recipient can read : ${r.recipientCanRead}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('clip-grant leak hit: ${r.capabilityForwarded}');
    return b.toString().trimRight();
  }

  void _run() {
    // The visible data URI is a benign public thumbnail, but the ClipData also
    // carries the app's PRIVATE provider URI - and the read grant rides on it.
    const intent = ForwardedIntent(
      action: 'android.intent.action.SEND',
      explicitPackage: null, // implicit: any app can catch it
      dataUri: ClipDataForwarder.publicShareUri,
      clipUris: [ClipDataForwarder.privateContentUri],
      grantRead: true,
    );

    // VULN: implicit send forwards the read capability to the attacker resolver.
    final vulnForwarder = ClipDataForwarder();
    final vuln = vulnForwarder.send(intent);

    // SECURE: refuse to forward a grant for a private URI to an implicit
    // resolver; send explicit + ungranted instead.
    final secureForwarder = ClipDataForwarder();
    final secure = secureForwarder.sendSafe(intent);

    setState(() {
      _vulnResult = _renderVuln(vuln);
      _secureResult = _renderSecure(secure);
    });
    // On Android, build a real Intent with FLAG_GRANT_READ_URI_PERMISSION whose
    // ClipData also carries the private provider URI, so the read grant rides
    // on the ClipData, the real clip-grant leakage op.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await ProviderIpcBridge.grantUri();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      ClipdataUriGrantLeakageScreen.vulnId,
      'clipdata-uri-grant',
      'read capability forwarded on Intent ClipData:\n$native',
    );
    if (!mounted) return;
    setState(() {
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ClipdataUriGrantLeakageScreen.vulnId,
      title: 'ClipData URI-Grant Leakage',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app attaches a PRIVATE content:// URI (backed by its own '
          "provider) to an Intent's ClipData together with "
          'FLAG_GRANT_READ_URI_PERMISSION and fires it to an implicit / '
          'untrusted target. Android propagates the read grant to every URI in '
          'the ClipData - not just the visible data URI - so whichever app '
          'catches the intent silently inherits read access to the private '
          'provider (CWE-200 / CWE-668 / CWE-927). The grant rides on the '
          'ClipData, which makes it easy to miss, and it leaks a CAPABILITY, '
          'not just a copied value. This is an offline, deterministic '
          'simulation. The secure path sends an explicit intent to a pinned '
          'package and never grants on ClipData bound for an untrusted '
          'resolver.',
      children: [
        DemoActionButton(
          label: 'Share via implicit intent with ClipData grant',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'implicit send: private read capability forwarded',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'explicit + no grant: capability withheld',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real Intent ClipData grant (read rides on clip URI)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
