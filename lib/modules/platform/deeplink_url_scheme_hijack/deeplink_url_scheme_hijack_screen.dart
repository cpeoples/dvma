import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'deep_link_handler.dart';

/// Deep Link / URL Scheme Hijack.
///
/// Custom scheme is unvalidated and can be claimed/abused by another app.
class DeeplinkUrlSchemeHijackScreen extends StatefulWidget {
  const DeeplinkUrlSchemeHijackScreen({super.key});

  static const String vulnId = 'deeplink_url_scheme_hijack';

  @override
  State<DeeplinkUrlSchemeHijackScreen> createState() =>
      _DeeplinkUrlSchemeHijackScreenState();
}

class _DeeplinkUrlSchemeHijackScreenState
    extends State<DeeplinkUrlSchemeHijackScreen> {
  final _link = TextEditingController(text: DeepLinkHandler.hostileSample);
  String? _routed;
  String? _followed;

  Future<void> _open() async {
    final link = _link.text;
    final result = DeepLinkHandler.handle(link);
    final routed = result.entries
        .map((e) => '${e.key} = ${e.value}')
        .join('\n');
    // real artifact: record the unverified deep link and the trusted-as-is
    // params it routed into (e.g. the password-reset / open-redirect action).
    await DvmaEvidence.record(
      DeeplinkUrlSchemeHijackScreen.vulnId,
      'deeplink',
      'hijackable scheme link=$link routed params: '
          '${result.entries.map((e) => '${e.key}=${e.value}').join(' ')}',
    );
    if (!mounted) return;
    setState(() => _routed = routed);

    // Wire the parsed `next` param into a real action: a genuine open-redirect
    // follow. The unverified deep link controls where the app navigates, so an
    // http(s) `next` is fetched with no allowlist (the real redirect sink).
    final next = Uri.tryParse(link)?.queryParameters['next'];
    final nextUri = next == null ? null : Uri.tryParse(next);
    if (nextUri != null &&
        (nextUri.scheme == 'http' || nextUri.scheme == 'https')) {
      var follow = 'open-redirect: followed next=$next via real http.get';
      try {
        final resp = await http
            .get(nextUri)
            .timeout(const Duration(seconds: 5));
        follow +=
            ' -> status=${resp.statusCode} bytes=${resp.bodyBytes.length}';
      } catch (e) {
        follow += ' -> error=$e';
      }
      await DvmaEvidence.record(
        DeeplinkUrlSchemeHijackScreen.vulnId,
        'open-redirect-follow',
        follow,
      );
      if (!mounted) return;
      setState(() => _followed = follow);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeeplinkUrlSchemeHijackScreen.vulnId,
      title: 'Deep Link / URL Scheme Hijack',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The custom "${DeepLinkHandler.scheme}://" scheme is unverified (any '
          'installed app can also register it) and its parameters are trusted '
          'as-is, so a crafted link drives a password reset or open redirect. '
          'Use verified App Links / Universal Links instead. Enter a link '
          'below to route it.',
      children: [
        TextField(
          controller: _link,
          decoration: const InputDecoration(labelText: 'incoming deep link'),
        ),
        DemoActionButton(label: 'Open link', onPressed: _open),
        if (_routed != null)
          EvidencePanel(label: 'routed (params trusted)', value: _routed!),
        if (_followed != null)
          EvidencePanel(
            label: 'real open-redirect follow (http.get of next)',
            value: _followed!,
          ),
      ],
    );
  }
}
