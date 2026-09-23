import 'dart:io' show File;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'handoff_activity_receiver.dart';

/// Handoff / NSUserActivity Injection.
///
/// The receiving app restores state from a Handoff `NSUserActivity` and trusts
/// it merely because it arrived over Continuity, so a crafted continuation
/// payload targeting ANOTHER account's resource is applied without validating
/// the source device, activityType, or account binding.
class HandoffUseractivityInjectionScreen extends StatefulWidget {
  const HandoffUseractivityInjectionScreen({super.key});

  static const String vulnId = 'handoff_useractivity_injection';

  @override
  State<HandoffUseractivityInjectionScreen> createState() =>
      _HandoffUseractivityInjectionScreenState();
}

class _HandoffUseractivityInjectionScreenState
    extends State<HandoffUseractivityInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;

  // A crafted continuation payload from an untrusted device whose
  // attacker-controlled webpageURL (parsed for real) targets another account's
  // resource on a look-alike host that is not an associated domain.
  static const HandoffUserActivity _craftedActivity = HandoffUserActivity(
    activityType: 'com.dvma.app.viewAccountResource',
    userInfo: {
      'accountId': HandoffActivityReceiver.attackerTargetAccount,
      'action': 'transfer_funds',
    },
    webpageURL: 'https://dvma.example.attacker.test/resource?acct=acct_2002&action=transfer_funds',
    sourceDeviceTrusted: false,
    boundAccountId: HandoffActivityReceiver.attackerTargetAccount,
  );

  String _render(HandoffContinuationResult r) {
    final b = StringBuffer();
    b.writeln(
      'current account    : ${HandoffActivityReceiver.loggedInAccount}',
    );
    b.writeln('activity type      : ${_craftedActivity.activityType}');
    b.writeln('activity userInfo  : ${_craftedActivity.userInfo}');
    b.writeln('webpageURL         : ${_craftedActivity.webpageURL}');
    b.writeln('parsed web host    : ${r.webHost ?? '(none)'}');
    b.writeln('domain allowed     : ${r.domainAllowed}');
    b.writeln('source trusted     : ${_craftedActivity.sourceDeviceTrusted}');
    b.writeln('bound account      : ${_craftedActivity.boundAccountId}');
    b.writeln('--- outcome ---');
    b.writeln('action applied     : ${r.action}');
    b.writeln('target account     : ${r.targetAccount}');
    b.writeln('state applied      : ${r.stateApplied}');
    b.writeln('source validated   : ${r.sourceValidated}');
    b.writeln('account bound       : ${r.accountBound}');
    b.writeln(
      'cross-account hit  : '
      '${r.stateApplied && !r.accountBound}',
    );
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final receiver = HandoffActivityReceiver();

    // VULN: crafted continuation applied blindly -> operates on attacker's
    // target account.
    final vuln = receiver.continueActivity(_craftedActivity);

    // SECURE: source/activityType/account-binding checks refuse the payload.
    final secure = receiver.continueActivitySafe(_craftedActivity);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real artifact: persist the applied cross-account continuation to real
    // SharedPreferences (NSUserDefaults on iOS) AND a real on-disk file, then
    // mirror to the evidence sink.
    const prefsKey = 'dvma_handoff_useractivity';
    final payload =
        'activityType=${_craftedActivity.activityType} '
        'webpageURL=${_craftedActivity.webpageURL} '
        'parsedHost=${vuln.webHost} domainAllowed=${vuln.domainAllowed} '
        'userInfo=${_craftedActivity.userInfo} '
        'sourceTrusted=${_craftedActivity.sourceDeviceTrusted} '
        'appliedAction=${vuln.action} targetAccount=${vuln.targetAccount} '
        'stateApplied=${vuln.stateApplied} accountBound=${vuln.accountBound}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, payload);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    try {
      final base = await DvmaEvidence.writableBaseDir();
      if (base != null) {
        final f = File('${base.path}/handoff_continuation_state.txt');
        await f.writeAsString(
          '${DateTime.now().toIso8601String()}\n$payload\n',
          flush: true,
        );
      }
    } catch (_) {}
    await DvmaEvidence.record(
      HandoffUseractivityInjectionScreen.vulnId,
      'handoff-activity',
      'shared_prefs key=$prefsKey :: $payload',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: HandoffUseractivityInjectionScreen.vulnId,
      title: 'Handoff / NSUserActivity Injection',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The receiving app restores state from a Handoff NSUserActivity '
          '(userInfo / webpageURL) and TRUSTS it merely because it arrived '
          'over Continuity. Without validating the source device, the '
          'activityType, or the account binding, a crafted continuation '
          'payload drives the app to operate on ANOTHER account\'s resource. '
          'The attacker-controlled webpageURL is parsed with real Uri.parse and '
          'its query merged over userInfo. The secure path '
          'validates the parsed host against an associated-domain allowlist and '
          'the activityType against a known set, requires the activity '
          'to be bound to the current authenticated account, and treats '
          'userInfo/webpageURL as untrusted input.',
      children: [
        DemoActionButton(
          label: 'Continue crafted Handoff activity',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trusted continuation: cross-account state applied',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated activity + account binding: refused',
            value: _secureResult!,
          ),
      ],
    );
  }
}
