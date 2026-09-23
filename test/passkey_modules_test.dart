import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:dvma/modules/auth/passkey_ceremony.dart';
import 'package:dvma/modules/auth/passkey_weak_attestation/weak_attestation_verifier.dart';
import 'package:dvma/modules/auth/passkey_origin_binding_bypass/origin_binding_verifier.dart';
import 'package:dvma/modules/auth/passkey_credential_exfiltration/passkey_credential_store.dart';
import 'package:dvma/modules/auth/passkey_fallback_downgrade/passkey_fallback_flow.dart';

/// Regression suite for the passkey/WebAuthn training scenarios: each test
/// asserts the *insecure* behavior is still present.
void main() {
  group('passkey_weak_attestation', () {
    test(
      'accepts none-attestation registration (secure verifier would not)',
      () {
        final att = PasskeyCeremony.register(
          rpId: 'dvma.training',
          userName: 'victim',
          attestationFormat: 'none',
        );
        expect(WeakAttestationVerifier.acceptRegistration(att), isTrue);
        expect(WeakAttestationVerifier.secureWouldAccept(att), isFalse);
      },
    );
  });

  group('passkey_origin_binding_bypass', () {
    test('accepts an attacker origin that merely contains the rpId', () {
      final assertion = PasskeyCeremony.assertion(
        credentialId: 'c1',
        rpId: OriginBindingVerifier.expectedRpId,
        origin: 'https://dvma.training.attacker.com',
      );
      expect(OriginBindingVerifier.verify(assertion), isTrue);
      expect(OriginBindingVerifier.secureVerify(assertion), isFalse);
    });
  });

  group('passkey_credential_exfiltration', () {
    test('caches private-key material in cleartext prefs', () async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();
      final store = PasskeyCredentialStore(prefs);
      await store.cacheCredential(
        credentialId: 'cred-abc',
        rpId: 'dvma.training',
        privateKeyBytes: const [1, 2, 3, 4],
      );
      final blob = store.exfiltrate();
      expect(blob, isNotNull);
      expect(blob, contains('privateKey'));
    });
  });

  group('passkey_fallback_downgrade', () {
    test(
      'forcing passkey-unavailable downgrades to the weak password path',
      () {
        final r = PasskeyFallbackFlow.login(
          passkeyAvailable: false,
          passkeyAssertionValid: true,
          fallbackAttempt: PasskeyFallbackFlow.fallbackPassword,
        );
        expect(r.success, isTrue);
        expect(r.downgraded, isTrue);
        expect(r.method, 'password-fallback');
      },
    );
  });
}
