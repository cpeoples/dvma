import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_intent_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'capability_composition_chain.dart';

/// iOS Capability-Composition Chain.
///
/// The vulnerability is the chain: Universal Link -> App Intent perform() ->
/// security-scoped bookmark -> Contacts export, each hop inheriting trust from
/// the last rather than re-authorizing the untrusted link.
class IosCapabilityCompositionChainScreen extends StatefulWidget {
  const IosCapabilityCompositionChainScreen({super.key});

  static const String vulnId = 'ios_capability_composition_chain';

  @override
  State<IosCapabilityCompositionChainScreen> createState() =>
      _IosCapabilityCompositionChainScreenState();
}

class _IosCapabilityCompositionChainScreenState
    extends State<IosCapabilityCompositionChainScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(IosChainResult r) {
    final b = StringBuffer();
    for (var i = 0; i < r.hops.length; i++) {
      final h = r.hops[i];
      b.writeln(
        'hop ${i + 1}: ${h.name}'
        '${h.reauthorized ? '  ->  requires fresh authorization' : ''}',
      );
    }
    b.writeln('contacts exported : ${r.contactsExported}');
    b.writeln('user authorized   : ${r.userAuthorized}');
    b.writeln('records exported  : ${r.exportedCount}');
    if (r.denyReason != null) {
      b.writeln('deny reason       : ${r.denyReason}');
    }
    b.writeln('chain exploited   : ${r.chainExploited}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final chain = IosCapabilityCompositionChain();
    final vuln = chain.run(IosCapabilityCompositionChain.craftedLink);
    final secure = chain.runSafe(IosCapabilityCompositionChain.craftedLink);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real artifact: persist the composed-chain exfiltration result to real
    // SharedPreferences (NSUserDefaults on iOS) and mirror to the evidence sink.
    const prefsKey = 'dvma_ios_capability_chain';
    final payload =
        'craftedLink=${IosCapabilityCompositionChain.craftedLink} '
        'hops=${vuln.hops.map((h) => h.name).join(">")} '
        'contactsExported=${vuln.contactsExported} '
        'records=${vuln.exportedCount} chainExploited=${vuln.chainExploited}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, payload);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    await DvmaEvidence.record(
      IosCapabilityCompositionChainScreen.vulnId,
      'capability-chain',
      'shared_prefs key=$prefsKey :: $payload',
    );

    // On iOS, drive the real App-Intent hop of the chain: the crafted link's
    // parameter reaches the real ExportAccountIntent.perform() with no
    // re-authorization, producing a real container-file artifact at the sink.
    final native = await AppIntentBridge.invokeExportIntent('contacts:all');
    if (native != null && native.isNotEmpty && mounted) {
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: IosCapabilityCompositionChainScreen.vulnId,
      title: 'iOS Capability-Composition Chain',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The vulnerability is the CHAIN, not any one API. A Universal Link '
          'resolves to an App Intent whose perform() reads its parameter as a '
          'security-scoped file reference, resolves a persisted bookmark, and '
          'reads + exports Contacts - each hop inheriting trust from the last '
          'rather than re-authorizing the untrusted link (CWE-441 confused '
          'deputy). A crafted link therefore drives a full contacts export '
          'with no user authorization, even though matching a link, running an '
          'App Intent, resolving a bookmark, and reading Contacts are each '
          'individually legitimate. This is an offline, deterministic '
          'simulation. The secure path treats the link as untrusted, requires '
          'fresh user authorization at the App Intent for the protected-data '
          'action, and re-validates the bookmark scope before the sink.',
      children: [
        DemoActionButton(label: 'Open crafted Universal Link', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'composed chain: crafted link exfiltrates contacts',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'authorization at the sink: chain refused',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real iOS App-Intent hop: crafted param reached export',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
