import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/storage/sensitive_data_in_memory/memory_secret_store.dart';
import 'package:dvma/modules/storage/insecure_sdcard_external_storage/external_storage_leak.dart';

import 'package:dvma/modules/auth/username_enumeration/enumerable_auth.dart';
import 'package:dvma/modules/auth/insecure_password_reset_token/insecure_reset_token.dart';
import 'package:dvma/modules/auth/developer_backdoor/backdoor_auth.dart';

import 'package:dvma/modules/platform/fileprovider_path_traversal/file_provider_model.dart';
import 'package:dvma/modules/platform/dynamic_code_loading_rce/untrusted_module_loader.dart';
import 'package:dvma/modules/platform/overlay_phishing/overlay_capture.dart';

import 'package:dvma/modules/supply_chain/insecure_firebase_cloud_config/firebase_cloud_config.dart';

/// Regression suite for the "classic" storage/auth/platform/supply-chain
/// training modules. Every test asserts the *insecure* behavior is still
/// present, so an accidental "fix" fails CI.
void main() {
  group('sensitive_data_in_memory', () {
    test('memory dump recovers the retained secret', () {
      final store = InMemorySecretStore.instance..reset();
      store.useSecret('password', 'hunter2-Sup3rSecret!');
      store.useSecret('symmetric_key', 'AES-KEY:0f1e2d3c4b5a6978');

      final dump = store.dumpMemory();
      expect(dump['password'], 'hunter2-Sup3rSecret!');
      expect(dump['symmetric_key'], 'AES-KEY:0f1e2d3c4b5a6978');

      // The secure scope wipes its buffer, so a later dump finds nothing.
      final scope = SecureSecretScope('hunter2-Sup3rSecret!');
      scope.useThenWipe((s) => s.length);
      expect(scope.dumpAfterUse(), isEmpty);

      store.reset();
    });
  });

  group('insecure_sdcard_external_storage', () {
    test(
      'sensitive file is written to shared storage and readable back',
      () async {
        ExternalStorageLeak.resetMemoryFs();
        const secret = 'auth_token=eyJhbGciOiJIUzI1NiJ9.session';
        final path = await ExternalStorageLeak.writeSensitiveFile(secret);
        expect(path, contains(ExternalStorageLeak.fileName));

        final readBack = await ExternalStorageLeak.readAsOtherApp(path);
        // World-readable: another app / adb recovers the cleartext contents.
        expect(readBack, secret);
      },
    );
  });

  group('username_enumeration', () {
    test('responses distinguish a real account from an unknown one', () {
      final knownWrong = EnumerableAuth.authenticate('alice', 'wrong-password');
      final unknown = EnumerableAuth.authenticate('mallory', 'wrong-password');

      expect(knownWrong.success, isFalse);
      expect(unknown.success, isFalse);
      // VULN: the two failures are distinguishable -> enumerable.
      expect(knownWrong.message, isNot(equals(unknown.message)));

      // A secure login returns one identical generic error.
      final secureKnown = EnumerableAuth.secureAuthenticate(
        'alice',
        'wrong-password',
      );
      final secureUnknown = EnumerableAuth.secureAuthenticate(
        'mallory',
        'wrong-password',
      );
      expect(secureKnown.message, equals(secureUnknown.message));
    });
  });

  group('insecure_password_reset_token', () {
    test('tokens are predictable/related and never expire', () {
      InsecureResetToken.resetCounter();
      final t1 = InsecureResetToken.issue();
      final t2 = InsecureResetToken.issue();

      // Short, non-expiring.
      expect(t1.value.length, 6);
      expect(t1.expiresAt, isNull);
      final farFuture = t1.issuedAt.add(const Duration(days: 365));
      expect(t1.isValidAt(farFuture), isTrue, reason: 'never expires');

      // Predictable: re-seeding the counter reproduces the exact sequence.
      InsecureResetToken.resetCounter();
      final r1 = InsecureResetToken.issue();
      final r2 = InsecureResetToken.issue();
      expect(r1.value, t1.value);
      expect(r2.value, t2.value);

      // A secure token is long and DOES expire.
      final secure = InsecureResetToken.secureToken();
      expect(secure.value.length, greaterThan(32));
      expect(
        secure.isValidAt(secure.issuedAt.add(const Duration(days: 365))),
        isFalse,
      );
    });
  });

  group('developer_backdoor', () {
    test('hardcoded backdoor credential is accepted as admin', () {
      final outcome = BackdoorAuth.authenticate(
        BackdoorAuth.backdoorUser,
        BackdoorAuth.backdoorPassword,
      );
      expect(outcome.success, isTrue);
      expect(outcome.isAdmin, isTrue);
      expect(outcome.via, 'backdoor');

      // Without a backdoor, the same credential is denied.
      final secure = BackdoorAuth.secureAuthenticate(
        BackdoorAuth.backdoorUser,
        BackdoorAuth.backdoorPassword,
      );
      expect(secure.success, isFalse);
    });
  });

  group('fileprovider_path_traversal', () {
    test(
      'traversal path escapes the export dir and reads a private file',
      () async {
        final leaked = await FileProviderModel.resolve('../session.token');
        expect(leaked, isNotNull);
        expect(leaked, contains('SECRET-SESSION'));

        // A confining resolver rejects the traversal.
        final secure = await FileProviderModel.secureResolve(
          '../session.token',
        );
        expect(secure, isNull);

        // Both still serve a legitimate in-dir file.
        expect(await FileProviderModel.secureResolve('report.pdf'), isNotNull);
      },
    );
  });

  group('dynamic_code_loading_rce', () {
    test('untrusted module executes with no verification', () {
      final result = UntrustedModuleLoader.loadAndRun('wipe_data');
      expect(result.executed, isTrue);
      expect(result.output, contains('EXECUTED'));

      // The secure loader blocks the unsigned, non-allowlisted module.
      final secure = UntrustedModuleLoader.secureLoadAndRun('wipe_data');
      expect(secure.executed, isFalse);
    });
  });

  group('overlay_phishing', () {
    test('malicious overlay captures typed credentials', () {
      final overlay = MaliciousOverlay();
      final field = CredentialField()..overlay = overlay;
      field.type('user:victim');
      field.type('pass:Sup3rSecret!');

      expect(overlay.captured, contains('user:victim'));
      expect(overlay.captured, contains('pass:Sup3rSecret!'));

      // With obscured-touch protection the overlay captures nothing.
      final secureOverlay = MaliciousOverlay();
      final secureField = SecureCredentialField()..overlay = secureOverlay;
      secureField.type('pass:Sup3rSecret!', obscured: true);
      expect(secureOverlay.captured, isEmpty);
    });
  });

  group('insecure_firebase_cloud_config', () {
    test('unauthenticated read returns other users\' data', () {
      final all = FirebaseCloudConfig.fetchAllRecords();
      // No auth required, yet we get everyone's records.
      expect(all.keys, containsAll(<String>['alice', 'bob', 'carol']));
      expect(all['bob']!['ssn'], '555-11-0000');

      // Config is hardcoded in the app.
      expect(FirebaseCloudConfig.apiKey, isNotEmpty);
      expect(FirebaseCloudConfig.databaseUrl, contains('firebaseio.com'));

      // A secure backend requires a token and scopes to the owner.
      expect(
        FirebaseCloudConfig.secureFetchOwnRecords(userId: 'alice', token: null),
        isNull,
      );
      final own = FirebaseCloudConfig.secureFetchOwnRecords(
        userId: 'alice',
        token: 'valid',
      );
      expect(own, isNotNull);
      expect(own!.containsKey('ssn'), isFalse);
    });
  });
}
