import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'session_rollback_validator.dart';

/// Authentication-State Rollback / Restore.
///
/// The app treats a locally-persisted session as authoritative and never checks
/// freshness/revocation server-side, so restoring an old session blob revives
/// an already-ended or revoked session.
class AuthStateRollbackRestoreScreen extends StatefulWidget {
  const AuthStateRollbackRestoreScreen({super.key});

  static const String vulnId = 'auth_state_rollback_restore';

  @override
  State<AuthStateRollbackRestoreScreen> createState() =>
      _AuthStateRollbackRestoreScreenState();
}

class _AuthStateRollbackRestoreScreenState
    extends State<AuthStateRollbackRestoreScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(SessionResumeResult r) {
    final b = StringBuffer();
    b.writeln('token              : ${r.token}');
    b.writeln('blob epoch         : ${r.epoch}');
    b.writeln('server epoch       : ${SessionRollbackValidator.serverEpoch}');
    b.writeln('authenticated      : ${r.authenticated}');
    b.writeln('rolled back accepted : ${r.rolledBack}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    const validator = SessionRollbackValidator();
    // Attacker restores a stale/revoked session blob from an old backup.
    const stale = SessionRollbackValidator.staleSession;
    const current = SessionRollbackValidator.currentSession;

    // VULN: resume trusts the locally-present blob with no server check.
    final vuln = validator.resume(stale);

    // SECURE: resumeSafe validates epoch + revocation against the server,
    // rejecting the rolled-back blob but accepting the current session.
    final secureStale = validator.resumeSafe(stale);
    final secureCurrent = validator.resumeSafe(current);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult =
          'ROLLED-BACK SESSION (restored from old backup):\n'
          '${_render(secureStale)}\n\n'
          'CURRENT SESSION:\n'
          '${_render(secureCurrent)}';
    });

    // real ARTIFACT: write the stale/rolled-back blob to the shared_prefs XML
    // (the on-disk rollback surface an attacker restores), resume FROM it, and
    // mirror the persisted state + backing file to the evidence sink.
    _persistRestoreAndRecord();
  }

  Future<void> _persistRestoreAndRecord() async {
    const validator = SessionRollbackValidator();
    final appId = context.read<AppConfig>().appId;

    // The attacker has restored an OLD on-disk blob: persist the stale session
    // to prefs so it is the real state resume reads back from disk.
    final storedLines = await validator.persistSession(
      SessionRollbackValidator.staleSession,
    );
    // Resume FROM the persisted on-disk blob (falls back to the const stale
    // blob under `flutter test`).
    final restored = await validator.loadPersistedBlob(
      fallback: SessionRollbackValidator.staleSession,
    );
    validator.resume(restored); // vulnerable path acts on the on-disk state

    final prefsXmlPath = PlatformLingo.current().keyValueBackingPath
        .replaceAll('<pkg>', appId)
        .replaceAll('<bundle-id>', appId);
    final artifact =
        '$storedLines'
        '\n\nserver epoch (current) : ${SessionRollbackValidator.serverEpoch}'
        '\nrestored token         : ${restored.token}'
        '\nrestored epoch         : ${restored.epoch}'
        '\nnote: resume trusts this on-disk blob with no server freshness/'
        'revocation check, so an old restored XML revives a revoked session.'
        '\n\nbacking file (adb pull/restore rollback surface): $prefsXmlPath';
    DvmaEvidence.record(
      AuthStateRollbackRestoreScreen.vulnId,
      'session',
      artifact,
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AuthStateRollbackRestoreScreen.vulnId,
      title: 'Authentication-State Rollback / Restore',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app treats a locally-persisted session/token as authoritative '
          'and never checks freshness or revocation server-side. Restoring an '
          'OLD local state (from a backup, snapshot, or copied container) '
          'revives an already-ended or revoked session, and the app believes '
          'the user is still authenticated. On device the session blob is '
          'persisted to the SharedPreferences XML and resume reads it back from '
          'disk, so restoring an old adb-pulled/edited XML (or rolling back '
          'session_epoch) revives a revoked session. The secure path validates '
          'the session against the current server epoch and a revocation list, '
          'rejecting rolled-back state while accepting the current session.',
      children: [
        DemoActionButton(
          label: 'Resume from restored session',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'no server check revives stale session',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'server-validated resume rejects rollback',
            value: _secureResult!,
          ),
      ],
    );
  }
}
