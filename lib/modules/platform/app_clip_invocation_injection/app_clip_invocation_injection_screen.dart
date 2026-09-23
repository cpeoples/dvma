import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'app_clip_invoker.dart';

/// App Clip Invocation Injection.
///
/// An App Clip acts on its invocation parameters while trusting the physical
/// trigger and inheriting full-app authentication, so a crafted invocation URL
/// drives a privileged payment without the re-auth the full app would require.
class AppClipInvocationInjectionScreen extends StatefulWidget {
  const AppClipInvocationInjectionScreen({super.key});

  static const String vulnId = 'app_clip_invocation_injection';

  @override
  State<AppClipInvocationInjectionScreen> createState() =>
      _AppClipInvocationInjectionScreenState();
}

class _AppClipInvocationInjectionScreenState
    extends State<AppClipInvocationInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(AppClipInvocation inv, AppClipInvocationOutcome r) {
    final b = StringBuffer();
    b.writeln('associated domain  : ${AppClipInvoker.associatedDomain}');
    b.writeln('invocation url     : ${inv.url}');
    b.writeln('invocation source  : ${inv.source.name}');
    b.writeln('parsed host        : ${r.host ?? '(none)'}');
    b.writeln('matched AASA comp  : ${r.matchedPattern ?? '(none)'}');
    b.writeln('invocation params  : ${inv.params}');
    b.writeln('--- outcome ---');
    b.writeln('action             : ${r.action}');
    b.writeln('action params      : ${r.params}');
    b.writeln('action performed   : ${r.actionPerformed}');
    b.writeln('invocation valid   : ${r.invocationValidated}');
    b.writeln('reauthenticated    : ${r.reauthenticated}');
    b.writeln(
      'privileged hit     : '
      '${r.actionPerformed && !r.reauthenticated}',
    );
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // Validate against the real bundled apple-app-site-association.json.
    final invoker = await AppClipInvoker.real();
    const crafted = AppClipInvoker.craftedInvocation;

    // VULN: crafted invocation performs pay(999, evil) with inherited trust.
    final vuln = invoker.invoke(crafted);

    // SECURE: crafted invocation blocked (host is not the associated domain).
    final secure = invoker.invokeSafe(crafted);

    setState(() {
      _vulnResult = _render(crafted, vuln);
      _secureResult = _render(crafted, secure);
    });

    // real artifact: persist the injected invocation URL + params (the payload
    // that drove the privileged, un-reauthenticated payment) to real
    // SharedPreferences (NSUserDefaults on iOS) and mirror to the evidence sink.
    const prefsKey = 'dvma_app_clip_invocation';
    final payload =
        'url=${crafted.url} source=${crafted.source.name} '
        'parsedHost=${vuln.host} params=${crafted.params} action=${vuln.action} '
        'actionParams=${vuln.params} reauthenticated=${vuln.reauthenticated}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, payload);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    await DvmaEvidence.record(
      AppClipInvocationInjectionScreen.vulnId,
      'app-clip-invocation',
      'shared_prefs key=$prefsKey :: $payload',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AppClipInvocationInjectionScreen.vulnId,
      title: 'App Clip Invocation Injection',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An App Clip acts on its invocation parameters (invocation URL / NFC '
          '/ QR / banner) and performs a purchase while TRUSTING that the '
          'invocation came from a legitimate physical trigger and INHERITING '
          'authentication state as if it were the full app. A crafted '
          'invocation URL from a look-alike domain drives a high-value payment '
          'with no re-auth. The invocation URL is parsed with Uri.parse and '
          'validated against the same real bundled '
          'apple-app-site-association.json as the Universal Link module. The '
          'secure path requires the invocation host to equal the associated '
          'domain and the path to match a real AASA component, '
          're-authenticates sensitive actions, and never inherits '
          'full-app trust.',
      children: [
        DemoActionButton(
          label: 'Handle crafted App Clip invocation',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trusted invocation: privileged payment performed',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'domain-validated + reauth required: blocked',
            value: _secureResult!,
          ),
      ],
    );
  }
}
