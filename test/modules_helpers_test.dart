import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/crypto/hardcoded_keys_ivs/hardcoded_crypto.dart';
import 'package:dvma/modules/crypto/weak_key_derivation/weak_kdf.dart';
import 'package:dvma/modules/crypto/custom_crypto_implementation/homegrown_cipher.dart';
import 'package:dvma/modules/auth/jwt_vulnerabilities/insecure_jwt.dart';
import 'package:dvma/modules/auth/weak_session_management/weak_session_manager.dart';
import 'package:dvma/modules/auth/weak_password_policy/password_policy.dart';
import 'package:dvma/modules/platform/content_provider_sql_injection/vulnerable_content_provider.dart';
import 'package:dvma/modules/platform/zip_path_traversal/zip_slip_unpacker.dart';
import 'package:dvma/modules/platform/qr_code_injection/qr_action_handler.dart';
import 'package:dvma/modules/platform/deeplink_url_scheme_hijack/deep_link_handler.dart';
import 'package:dvma/modules/code_quality/verbose_error_handling/verbose_error_formatter.dart';
import 'package:dvma/modules/code_quality/native_code_memory_bugs/native_buffer_sim.dart';
import 'package:dvma/modules/resilience/root_jailbreak_detection_bypass/root_detector.dart';
import 'package:dvma/modules/resilience/toctou_race_condition/toctou_bank.dart';
import 'package:dvma/modules/input_validation/unsafe_deserialization/unsafe_deserializer.dart';
import 'package:dvma/modules/storage/third_party_sdk_data_leakage/analytics_sdk.dart';
import 'package:dvma/modules/storage/sensitive_data_in_logs/sensitive_logger.dart';
import 'package:dvma/modules/supply_chain/malicious_third_party_sdk/malicious_sdk.dart';
import 'package:dvma/modules/privacy/pii_in_analytics_events/analytics_events.dart';
import 'package:dvma/modules/ai_ml/insecure_output_handling/insecure_output_handler.dart';
import 'package:dvma/modules/ai_ml/hardcoded_llm_api_keys/llm_api_config.dart';

/// REGRESSION SUITE (part 2): asserts the *insecure* behavior of the module
/// helpers is still present. An accidental "fix" that hardened any of these
/// would fail CI and flag that a training lab has been broken.
void main() {
  group('crypto', () {
    test(
      'hardcoded key + static IV -> deterministic ciphertext (IV reuse)',
      () {
        final a = HardcodedCrypto.encryptHex('same message');
        final b = HardcodedCrypto.encryptHex('same message');
        expect(a, b); // reused IV leaks equality, still vulnerable
        expect(HardcodedCrypto.decryptHex(a), 'same message');
      },
    );

    test('weak KDF still uses a trivially-low iteration count', () {
      expect(WeakKdf.iterations, lessThan(1000));
      expect(
        WeakKdf.deriveKeyHex('password123'),
        WeakKdf.deriveKeyHex('password123'),
      );
    });

    test('homegrown XOR cipher is trivially reversible', () {
      final ct = HomegrownCipher.encrypt('attack at dawn');
      expect(HomegrownCipher.decrypt(ct), 'attack at dawn');
    });
  });

  group('auth', () {
    test('JWT verifier accepts a forged alg:none admin token', () {
      final token = InsecureJwt.forgeNoneToken({
        'sub': 'attacker',
        'role': 'admin',
      });
      final claims = InsecureJwt.verify(token);
      expect(claims, isNotNull);
      expect(claims!['role'], 'admin');
    });

    test('JWT verifier accepts a weak-secret token', () {
      final token = InsecureJwt.signWeak({'role': 'admin'});
      expect(InsecureJwt.verify(token), isNotNull);
    });

    test('session tokens are predictable and never expire', () {
      final mgr = WeakSessionManager();
      final t1 = mgr.issueToken();
      final t2 = mgr.issueToken();
      expect(WeakSessionManager.predictNext(t1), t2);
      expect(mgr.isValid(t1), isTrue);
    });

    test('password policy accepts a single character', () {
      expect(PasswordPolicy.isAcceptable('a'), isTrue);
    });
  });

  group('platform', () {
    test('content provider is injectable (UNION exfiltrates secret)', () {
      final rows = VulnerableContentProvider().query(
        "x' UNION SELECT secret --",
      );
      expect(rows.map((r) => r['name']).join(), contains('DVMA{'));
    });

    test('tautology injection dumps all rows', () {
      final rows = VulnerableContentProvider().query("x' OR '1'='1");
      expect(rows.length, greaterThan(1));
    });

    test('zip-slip entry escapes the target dir', () {
      const base = '/data/app/files';
      final resolved = ZipSlipUnpacker.resolveTargetPath(
        base,
        ZipSlipUnpacker.maliciousEntry,
      );
      expect(ZipSlipUnpacker.escapesBase(base, resolved), isTrue);
    });

    test('zip unpacker resolves a real crafted archive outside base', () {
      final zip = ZipSlipUnpacker.craftMaliciousZip();
      final targets = ZipSlipUnpacker.unpackTargets(zip, '/data/app/files');
      expect(targets.any((t) => !t.startsWith('/data/app/files/')), isTrue);
    });

    test('QR handler auto-executes an app-command payload', () {
      expect(
        QrActionHandler.handle(QrActionHandler.hostileSample),
        contains('AUTO-EXECUTED'),
      );
    });

    test('deep link honors an unvalidated password reset', () {
      final r = DeepLinkHandler.handle(DeepLinkHandler.hostileSample);
      expect(r['action'], contains('PASSWORD RESET'));
    });
  });

  group('code_quality', () {
    test('verbose error surfaces internal context to the user', () {
      final text = VerboseErrorFormatter.triggerAndFormat();
      expect(text, contains('db_dsn'));
      expect(text, contains('STACK TRACE'));
    });

    test('native strcpy overflows a fixed buffer', () {
      final r = NativeBufferSim.unsafeStrcpy('A' * 24);
      expect(r['overflowed'], isTrue);
    });
  });

  group('resilience', () {
    test('root detection is bypassed by flipping the flag', () {
      final d = RootDetector()..bypassed = true;
      expect(d.isCompromised(), isFalse);
    });

    test('TOCTOU race allows a double-spend', () {
      final bank = ToctouBank(100);
      var second = false;
      bank.withdraw(100, duringGap: () => second = bank.withdraw(100));
      expect(second, isTrue);
      expect(bank.balance, lessThan(0));
    });
  });

  group('input_validation', () {
    test('unsafe deserialization trusts attacker-supplied isAdmin', () {
      final s = UnsafeDeserializer.fromUntrusted('{"isAdmin":true}');
      expect(s.isAdmin, isTrue);
    });
  });

  group('storage / privacy / supply chain leakage', () {
    test('analytics SDK over-collects PII beyond its purpose', () {
      final p = AnalyticsSdk().track('Home');
      expect(p.containsKey('email'), isTrue);
      expect(p.containsKey('android_id'), isTrue);
    });

    test('sensitive logger emits the password unredacted', () {
      final line = SensitiveLogger.formatLogin(
        username: 'u',
        password: 'p@ss',
        token: 't',
      );
      expect(line, contains('p@ss'));
    });

    test('malicious SDK exfiltrates the auth token on init', () {
      final b = MaliciousSdk().onInit(
        authToken: 'tok',
        clipboard: 'c',
        keystrokes: ['a'],
      );
      expect(b['auth_token'], 'tok');
      expect(b['exfil_to'], MaliciousSdk.exfilEndpoint);
    });

    test('analytics event carries raw PII', () {
      final e = AnalyticsEvents.buildPurchaseEvent();
      expect(e['email'], isNotNull);
      expect(e['lat'], isNotNull);
    });
  });

  group('ai_ml', () {
    test('insecure output handler injects unescaped script into HTML', () {
      final html = InsecureOutputHandler.renderToHtml('<script>x</script>');
      expect(html, contains('<script>x</script>'));
    });

    test('LLM API key is hardcoded and extractable', () {
      expect(LlmApiConfig.apiKey, startsWith('sk-'));
      expect(LlmApiConfig.extractableString(), contains(LlmApiConfig.apiKey));
    });
  });
}
