import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'insecure_reset_token.dart';

/// Insecure Password Reset Token / Magic Link.
///
/// Password-reset tokens / magic-login links are short, predictable, and never
/// expire.
class InsecurePasswordResetTokenScreen extends StatefulWidget {
  const InsecurePasswordResetTokenScreen({super.key});

  static const String vulnId = 'insecure_password_reset_token';

  @override
  State<InsecurePasswordResetTokenScreen> createState() =>
      _InsecurePasswordResetTokenScreenState();
}

class _InsecurePasswordResetTokenScreenState
    extends State<InsecurePasswordResetTokenScreen> {
  String? _vulnResult;
  String? _secureResult;

  Future<void> _run() async {
    InsecureResetToken.resetCounter();
    final t1 = InsecureResetToken.issue();
    final t2 = InsecureResetToken.issue();

    final secure = InsecureResetToken.secureToken();
    // A far-future check: the vulnerable token is still valid; secure expired.
    final future = DateTime.now().add(const Duration(days: 365));

    // real side effect: persist the guessable, non-expiring reset token to real
    // SharedPreferences (the token an attacker can predict / reuse forever).
    const prefsKey = 'dvma_password_reset_token';
    final stored =
        'token=${t1.value} '
        'link=https://dvma.training/reset?t=${t1.value} '
        'expires=${t1.expiresAt ?? "NEVER"} '
        'validAYearLater=${t1.isValidAt(future)}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, stored);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    await DvmaEvidence.record(
      InsecurePasswordResetTokenScreen.vulnId,
      'reset-token',
      'shared_prefs key=$prefsKey :: $stored',
    );

    if (!mounted) return;
    setState(() {
      _vulnResult =
          'link1: https://dvma.training/reset?t=${t1.value}\n'
          'link2: https://dvma.training/reset?t=${t2.value}\n'
          'expires: ${t1.expiresAt ?? "NEVER"}\n'
          'valid a year later: ${t1.isValidAt(future)}\n'
          '=> short, sequential-seed, guessable, non-expiring';
      _secureResult =
          'token: ${secure.value}\n'
          'expires: ${secure.expiresAt}\n'
          'valid a year later: ${secure.isValidAt(future)}\n'
          '=> long Random.secure() token with a TTL';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecurePasswordResetTokenScreen.vulnId,
      title: 'Insecure Reset Token',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Reset tokens are short 6-digit values from a seeded, non-secure '
          'Random() and never expire. Two tokens issued in sequence are related '
          'and guessable, and an old link works forever - so an attacker can '
          'brute-force or predict a valid reset link and take over accounts. A '
          'secure token is long, from Random.secure(), and has a short TTL.',
      children: [
        DemoActionButton(label: 'Issue two reset links', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(label: 'vulnerable reset tokens', value: _vulnResult!),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what a secure token looks like',
            value: _secureResult!,
          ),
      ],
    );
  }
}
