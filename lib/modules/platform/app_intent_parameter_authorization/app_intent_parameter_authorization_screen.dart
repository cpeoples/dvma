import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_intent_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'app_intent_router.dart';

/// App Intent / Siri Parameter -> Privileged Action (No Authz).
///
/// An App Intent entry point maps an untrusted, system-supplied parameter
/// straight to a privileged action with no per-invocation authorization or
/// ownership check (Apple App Intents capability-confusion class).
class AppIntentParameterAuthorizationScreen extends StatefulWidget {
  const AppIntentParameterAuthorizationScreen({super.key});

  static const String vulnId = 'app_intent_parameter_authorization';

  @override
  State<AppIntentParameterAuthorizationScreen> createState() =>
      _AppIntentParameterAuthorizationScreenState();
}

class _AppIntentParameterAuthorizationScreenState
    extends State<AppIntentParameterAuthorizationScreen> {
  /// A crafted shortcut invocation: export BOB's account, with no auth token.
  AppIntentInvocation get _malicious => const AppIntentInvocation(
    intentName: AppIntentRouter.exportIntent,
    params: {'accountId': AppIntentRouter.victimAccount},
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(InvocationResult r) {
    final b = StringBuffer();
    b.writeln('action requested   : ${r.action}');
    b.writeln('executed           : ${r.executed}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('effect             : ${r.effect ?? '(none)'}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: the shortcut param drives the privileged export with no authz.
    final vuln = AppIntentRouter.seeded().invoke(_malicious);
    // SECURE: same invocation refused, no auth token and not the caller's
    // account.
    final secure = AppIntentRouter.seeded().invokeSafe(_malicious);
    // real artifact: record the unauthenticated App Intent param that drove a
    // privileged export of another user's account.
    await DvmaEvidence.record(
      AppIntentParameterAuthorizationScreen.vulnId,
      'app-intent',
      'intent=${_malicious.intentName} params=${_malicious.params} -> '
          'action=${vuln.action} executed=${vuln.executed} '
          'effect=${vuln.effect}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On iOS, drive the real parameterized ExportAccountIntent: the untrusted
    // accountId parameter drives a privileged export with no authorization.
    final native = await AppIntentBridge.invokeExportIntent(
      AppIntentRouter.victimAccount,
    );
    if (native != null && native.isNotEmpty && mounted) {
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AppIntentParameterAuthorizationScreen.vulnId,
      title: 'App Intent / Siri Parameter -> Privileged Action (No Authz)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An App Intent / Siri / Shortcuts / Spotlight entry point maps an '
          'UNTRUSTED, system-supplied parameter straight to a privileged app '
          'action (transfer / delete / export) with NO per-invocation '
          'authorization and NO ownership check. A crafted shortcut here names '
          'another user\'s account id and the app EXPORTS it directly from the '
          'parameter - capability confusion where the intent\'s privilege is '
          'applied to an entity the invoker does not own (the Apple App Intents '
          'class). This is an offline, deterministic simulation over a tiny '
          'in-memory bank. The secure path requires the invocation to carry a '
          'verified user-authorization token AND checks the current user owns '
          'the target entity, refusing the unauthorized / other-user param.',
      children: [
        DemoActionButton(label: 'Run crafted shortcut', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'param -> privileged action (no authz)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'authz token + ownership verified (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real iOS ExportAccountIntent ran from untrusted parameter',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
