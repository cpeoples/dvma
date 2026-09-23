import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'universal_link_router.dart';

/// Universal Link / AASA Associated-Domain Confusion.
///
/// The app trusts an incoming Universal Link because it matched an associated
/// domain, but weak AASA deployment (broad wildcards + an open redirect) lets a
/// crafted URL reach a sensitive in-app handler with attacker parameters.
class UniversalLinkAasaConfusionScreen extends StatefulWidget {
  const UniversalLinkAasaConfusionScreen({super.key});

  static const String vulnId = 'universal_link_aasa_confusion';

  @override
  State<UniversalLinkAasaConfusionScreen> createState() =>
      _UniversalLinkAasaConfusionScreenState();
}

class _UniversalLinkAasaConfusionScreenState
    extends State<UniversalLinkAasaConfusionScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(String inputUrl, UniversalLinkRoute r) {
    final b = StringBuffer();
    b.writeln('associated domain  : ${UniversalLinkRouter.associatedDomain}');
    b.writeln('input url          : $inputUrl');
    b.writeln('effective url      : ${r.url}');
    b.writeln('--- outcome ---');
    b.writeln('routed             : ${r.routed}');
    b.writeln('handler            : ${r.handler}');
    b.writeln('params             : ${r.params}');
    b.writeln('matched AASA comp  : ${r.matchedPattern ?? '(none)'}');
    if (r.matchComment != null && r.matchComment!.isNotEmpty) {
      b.writeln('component comment  : ${r.matchComment}');
    }
    b.writeln('sensitive reached  : ${r.reachedSensitiveHandler}');
    b.writeln('path match broad   : ${r.pathMatchTooBroad}');
    b.writeln(
      'hit                : '
      '${r.routed && r.reachedSensitiveHandler}',
    );
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // Route against the real bundled apple-app-site-association.json.
    final router = await UniversalLinkRouter.real();

    // VULN: crafted wildcard link reaches resetPassword because the real AASA
    // component /account/* matches it.
    final crafted = UniversalLinkRouter.craftedWildcardLink;
    final vuln = router.openUniversalLink(crafted);

    // SECURE: same crafted link is refused; the genuine link still routes.
    final secureCrafted = router.openUniversalLinkSafe(crafted);
    final secureGenuine = router.openUniversalLinkSafe(
      UniversalLinkRouter.genuineLink,
    );

    setState(() {
      _vulnResult = _render(crafted, vuln);
      _secureResult =
          '${_render(crafted, secureCrafted)}\n'
          '--- genuine link ---\n'
          '${_render(UniversalLinkRouter.genuineLink, secureGenuine)}';
    });

    // real artifact: persist the crafted Universal Link, the real AASA component
    // it matched, and the routed handler to real SharedPreferences.
    const prefsKey = 'dvma_universal_link_aasa';
    final payload =
        'craftedLink=$crafted effectiveUrl=${vuln.url} '
        'routed=${vuln.routed} matchedPattern=${vuln.matchedPattern} '
        'handler=${vuln.handler} params=${vuln.params} '
        'reachedSensitiveHandler=${vuln.reachedSensitiveHandler}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, payload);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    await DvmaEvidence.record(
      UniversalLinkAasaConfusionScreen.vulnId,
      'universal-link',
      'shared_prefs key=$prefsKey :: $payload',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UniversalLinkAasaConfusionScreen.vulnId,
      title: 'Universal Link / AASA Associated-Domain Confusion',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app trusts an incoming Universal Link because it matched an '
          'associated domain, but the AASA deployment is weak: an over-broad '
          '/account/* and /* wildcard. The incoming URL is parsed with '
          'Uri.parse and matched against the real bundled '
          'apple-app-site-association.json components, so a crafted URL routes '
          'to a sensitive in-app handler (resetPassword) with '
          'attacker-controlled parameters. The whole app -> associated-domain '
          '-> AASA -> web-server chain is the boundary, not just link parsing. '
          'The secure path uses tight exact-path matching, refuses redirects, '
          're-validates parameters, and never treats a matched link as an '
          'authorization decision - while the genuine link still works.',
      children: [
        DemoActionButton(label: 'Open crafted Universal Link', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'broad AASA + redirect: sensitive handler reached',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'exact-path AASA, no redirect: crafted refused',
            value: _secureResult!,
          ),
      ],
    );
  }
}
