import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/storage/backup_archive_integrity_tampering/backup_archive.dart';
import 'package:dvma/modules/storage/local_security_state_integrity_tampering/security_state_store.dart';
import 'package:dvma/modules/storage/auth_state_rollback_restore/session_rollback_validator.dart';
import 'package:dvma/modules/storage/sensitive_data_in_crash_reports/crash_reporter.dart';
import 'package:dvma/modules/auth/multi_account_isolation_failure/account_vault.dart';
import 'package:dvma/modules/platform/unauthenticated_local_loopback_service/local_service.dart';

/// Regression suite for the local-state & backup INTEGRITY / isolation family.
/// A mobile attacker doesn't always need to READ a secret - if they can alter
/// backup archives, local security state, or an old session, the app can be
/// made to TRUST attacker-controlled state. Each test asserts the INSECURE path
/// trusts the tampered/rolled-back/leaked state AND that the secure contrast
/// rejects it, so an accidental "fix" of the lab fails CI.
void main() {
  group('backup_archive_integrity_tampering', () {
    test('tampered archive trusted; safe path verifies integrity', () {
      final vuln = BackupRestorer().restore(BackupRestorer.tamperedArchive());
      expect(vuln.restored, isTrue);
      expect(vuln.integrityVerified, isFalse);
      expect(vuln.tamperedValueTrusted, isTrue);

      final blocked = BackupRestorer().restoreSafe(
        BackupRestorer.tamperedArchive(),
      );
      expect(blocked.restored, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = BackupRestorer().restoreSafe(BackupRestorer.genuineArchive());
      expect(ok.restored, isTrue);
      expect(ok.integrityVerified, isTrue);
    });
  });

  group('local_security_state_integrity_tampering', () {
    test('tampered role flag trusted; safe path verifies a keyed MAC', () {
      final vuln = SecurityStateStore.tamperedStore().readDecision(
        SecurityStateStore.keyRole,
      );
      expect(vuln.granted, isTrue);
      expect(vuln.integrityVerified, isFalse);
      expect(vuln.tamperedValueTrusted, isTrue);

      final blocked = SecurityStateStore.tamperedStore().readDecisionSafe(
        SecurityStateStore.keyRole,
      );
      expect(blocked.granted, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = SecurityStateStore.legitimateStore().readDecisionSafe(
        SecurityStateStore.keyRole,
      );
      expect(ok.integrityVerified, isTrue);
    });
  });

  group('auth_state_rollback_restore', () {
    test('rolled-back session revived; safe path validates freshness', () {
      final vuln = SessionRollbackValidator().resume(
        SessionRollbackValidator.staleSession,
      );
      expect(vuln.authenticated, isTrue);
      expect(vuln.rolledBack, isTrue);

      final blocked = SessionRollbackValidator().resumeSafe(
        SessionRollbackValidator.staleSession,
      );
      expect(blocked.authenticated, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = SessionRollbackValidator().resumeSafe(
        SessionRollbackValidator.currentSession,
      );
      expect(ok.authenticated, isTrue);
    });
  });

  group('sensitive_data_in_crash_reports', () {
    test('crash payload leaks secrets; safe path scrubs before send', () {
      final vuln = CrashReporter().report(CrashReporter.sampleState());
      expect(vuln.sent, isTrue);
      expect(vuln.scrubbed, isFalse);
      expect(vuln.leaked, isTrue);
      expect(vuln.leakedFields, isNotEmpty);

      final safe = CrashReporter().reportSafe(CrashReporter.sampleState());
      expect(safe.sent, isTrue);
      expect(safe.scrubbed, isTrue);
      expect(safe.leaked, isFalse);
      expect(safe.leakedFields, isEmpty);
    });
  });

  group('multi_account_isolation_failure', () {
    test(
      "account A's data survives switch to B; safe path wipes on switch",
      () {
        final vault = AccountVault()..login(AccountVault.accountA);
        final vuln = vault.switchTo(AccountVault.accountB);
        expect(vuln.leakedAcrossAccounts, isTrue);
        expect(vuln.previousAccountDataVisible, isTrue);
        expect(vault.readToken(), AccountVault.secretTokenA);

        final safeVault = AccountVault()..login(AccountVault.accountA);
        final safe = safeVault.switchToSafe(AccountVault.accountB);
        expect(safe.leakedAcrossAccounts, isFalse);
        expect(safeVault.readToken(), isNot(AccountVault.secretTokenA));
      },
    );
  });

  group('unauthenticated_local_loopback_service', () {
    test('untokened local caller served; safe path checks token + origin', () {
      final vuln = LocalService().handle(LocalService.attackerRequest);
      expect(vuln.served, isTrue);
      expect(vuln.authChecked, isFalse);
      expect(vuln.dataExposed, isTrue);

      final blocked = LocalService().handleSafe(LocalService.attackerRequest);
      expect(blocked.served, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = LocalService().handleSafe(LocalService.legitimateRequest);
      expect(ok.served, isTrue);
    });
  });
}
