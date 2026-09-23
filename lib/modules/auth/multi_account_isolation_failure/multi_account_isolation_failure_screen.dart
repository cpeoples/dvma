import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'account_vault.dart';

/// Multi-Account Isolation Failure.
///
/// Account A logs in, then the app switches to account B. The vulnerable path
/// leaves A's cached token/note (and live session) readable to B; the secure
/// path wipes and rotates all per-account state on switch/logout.
class MultiAccountIsolationFailureScreen extends StatefulWidget {
  const MultiAccountIsolationFailureScreen({super.key});

  static const String vulnId = 'multi_account_isolation_failure';

  @override
  State<MultiAccountIsolationFailureScreen> createState() =>
      _MultiAccountIsolationFailureScreenState();
}

class _MultiAccountIsolationFailureScreenState
    extends State<MultiAccountIsolationFailureScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(AccountAccessResult r) {
    final b = StringBuffer();
    b.writeln('active account     : ${r.activeAccount}');
    b.writeln('readable token     : ${r.readableToken ?? '(none)'}');
    b.writeln('readable note      : ${r.readableNote ?? '(none)'}');
    b.writeln('data owner         : ${r.ownerOfReadableData ?? '(none)'}');
    b.writeln(
      'live sessions      : ${r.liveSessions.isEmpty ? '(none)' : r.liveSessions.join(', ')}',
    );
    b.writeln('prev-acct visible  : ${r.previousAccountDataVisible}');
    b.writeln('leaked cross-acct  : ${r.leakedAcrossAccounts}');
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: A logs in, app switches to B without wiping A's cached state.
    final vulnVault = AccountVault()..login(AccountVault.accountA);
    final vuln = vulnVault.switchTo(AccountVault.accountB);

    // SECURE: switching to B wipes/rotates all of A's per-account state.
    final secureVault = AccountVault()..login(AccountVault.accountA);
    final secure = secureVault.switchToSafe(AccountVault.accountB);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real ARTIFACT: after the vulnerable switch, account A's token still sits
    // on disk in the shared_prefs XML. Dump the persisted tokens and mirror
    // them (plus the backing file) to the evidence sink.
    _recordPersistedLeak(vulnVault);
  }

  Future<void> _recordPersistedLeak(AccountVault vulnVault) async {
    final appId = context.read<AppConfig>().appId;
    final persisted = await vulnVault.dumpPersistedTokens();
    final prefsXmlPath = PlatformLingo.current().keyValueBackingPath
        .replaceAll('<pkg>', appId)
        .replaceAll('<bundle-id>', appId);
    final dump = persisted.entries
        .map((e) => '${AccountVault.prefsTokenKey(e.key)}=${e.value}')
        .join('\n');
    final artifact =
        '$dump'
        '\n\nactive account after switch : ${AccountVault.accountB}'
        '\nnote: account A\'s token was NOT purged on switch, so it lingers on '
        'disk and is readable by whoever pulls the shared_prefs XML.'
        '\n\nbacking file (adb/root-readable): $prefsXmlPath';
    DvmaEvidence.record(
      MultiAccountIsolationFailureScreen.vulnId,
      'account-token',
      artifact,
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: MultiAccountIsolationFailureScreen.vulnId,
      title: 'Multi-Account Isolation Failure',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Account A signs in on the device, then the user switches to account '
          'B. Because the app caches credentials in process-wide slots and '
          'never tears them down, switching (or logging out and back in) does '
          'not clear account A\'s token, private note, or live session - so '
          'account B reads and acts with account A\'s data, and A\'s old '
          'session survives. Each account\'s token is also persisted to the '
          'SharedPreferences XML and NOT purged on switch, so account A\'s '
          'token lingers on disk (adb-pullable). The secure path scopes all '
          'per-account state to the active principal and wipes/rotates it '
          '(including the on-disk token) on every switch and logout.',
      children: [
        DemoActionButton(label: 'Login A, then switch to B', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'account B reads account A data (isolation failed)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'per-account state wiped on switch (isolated)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
