import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'toctou_bank.dart';

/// TOCTOU Race Condition in Auth Check.
///
/// Auth is checked then used with a mutable gap an attacker can win. The raced
/// (double-spent) balance is a real side effect: it is persisted to
/// SharedPreferences and recorded to the evidence sink so the corrupted state
/// survives the demo.
class ToctouRaceConditionScreen extends StatefulWidget {
  const ToctouRaceConditionScreen({super.key});

  static const String vulnId = 'toctou_race_condition';

  /// SharedPreferences key holding the raced balance (persisted side effect).
  static const String balanceKey = 'toctou_raced_balance';

  @override
  State<ToctouRaceConditionScreen> createState() =>
      _ToctouRaceConditionScreenState();
}

class _ToctouRaceConditionScreenState extends State<ToctouRaceConditionScreen> {
  String? _result;
  int? _persistedBalance;

  Future<void> _exploit() async {
    final bank = ToctouBank(100);
    // Two concurrent \$100 withdrawals. The first checks (ok), then in the gap
    // the second withdrawal fires, also seeing balance>=100, so both debit.
    var second = false;
    final firstOk = bank.withdraw(
      100,
      duringGap: () {
        second = bank.withdraw(100); // races in during the check->use window
      },
    );

    // real side effect: persist the corrupted (negative) balance so the
    // double-spend outlives the in-memory demo, then record it as evidence.
    int? stored;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(ToctouRaceConditionScreen.balanceKey, bank.balance);
      stored = prefs.getInt(ToctouRaceConditionScreen.balanceKey);
    } on MissingPluginException {
      // Best effort: on hosts without a prefs plugin the record below still
      // captures the raced balance.
    }

    await DvmaEvidence.record(
      ToctouRaceConditionScreen.vulnId,
      'toctou',
      'startBalance=100 :: withdraw1=$firstOk :: withdraw2(raced)=$second :: '
          'finalBalance=${bank.balance} (double-spend went negative) :: '
          'persistedBalance=${stored ?? "unavailable"}',
    );

    if (!mounted) return;
    setState(() {
      _persistedBalance = stored;
      _result =
          'start balance = 100\n'
          'withdraw #1 (in gap) succeeded = $firstOk\n'
          'withdraw #2 (racing) succeeded = $second\n'
          'final balance = ${bank.balance}  (double-spend: went negative)';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ToctouRaceConditionScreen.vulnId,
      title: 'TOCTOU Race Condition',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The withdrawal checks the balance, then debits it in a separate '
          'step. Between check and use, a second concurrent withdrawal sees the '
          'same stale balance and also succeeds - a double-spend. The exploit '
          'below wins the race deterministically and persists the corrupted '
          'balance to on-disk storage.',
      children: [
        DemoActionButton(
          label: 'Run concurrent withdrawals',
          onPressed: _exploit,
        ),
        if (_result != null)
          EvidencePanel(label: 'race outcome', value: _result!),
        if (_persistedBalance != null)
          EvidencePanel(
            label: 'persisted balance (on disk)',
            value:
                '${ToctouRaceConditionScreen.balanceKey} = '
                '$_persistedBalance',
          ),
      ],
    );
  }
}
