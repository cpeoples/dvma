import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/auth/passkey_ceremony.dart';
import 'package:dvma/modules/auth/passkey_assertion_replay_signcount/signcount_verifier.dart';
import 'package:dvma/modules/auth/passkey_challenge_reuse/challenge_server.dart';
import 'package:dvma/modules/auth/passkey_user_verification_bypass/uv_verifier.dart';
import 'package:dvma/modules/auth/passkey_stepup_auth_bypass/stepup_flow.dart';
import 'package:dvma/modules/auth/passkey_credential_management_authz/credential_management_service.dart';
import 'package:dvma/modules/auth/passkey_session_fixation/session_fixation_flow.dart';
import 'package:dvma/modules/auth/passkey_thirdparty_pairing_authz/pairing_broker.dart';

/// Regression suite for the WebAuthn/passkey scenarios added under `auth`.
/// Each group asserts the INSECURE path still misbehaves AND the secure
/// contrast blocks the attack, so CI catches an accidental fix or an
/// accidental removal of the contrast.
void main() {
  PasskeyAssertion assertion({String credentialId = 'cred-victim'}) =>
      PasskeyCeremony.assertion(
        credentialId: credentialId,
        rpId: 'dvma.training',
        origin: 'https://dvma.training',
      );

  group('passkey_assertion_replay_signcount', () {
    test(
      'vulnerable verifier replays the same sign-count into new sessions',
      () {
        final vuln = SignCountVerifier();
        final a = assertion();
        expect(vuln.verify(a, reportedSignCount: 5), isTrue);
        // Replay: identical sign-count is still accepted -> another session.
        expect(vuln.verify(a, reportedSignCount: 5), isTrue);
        expect(vuln.issuedSessions.length, 2);
      },
    );

    test('secure verifier rejects a non-increasing sign-count', () {
      final secure = SecureSignCountVerifier();
      final a = assertion();
      expect(secure.verify(a, reportedSignCount: 5), isTrue);
      expect(secure.verify(a, reportedSignCount: 5), isFalse); // replay blocked
      expect(
        secure.verify(a, reportedSignCount: 4),
        isFalse,
      ); // rollback blocked
      expect(secure.verify(a, reportedSignCount: 6), isTrue); // advance ok
      expect(secure.issuedSessions.length, 2);
    });
  });

  group('passkey_challenge_reuse', () {
    test(
      'vulnerable server accepts a replayed assertion (static challenge)',
      () {
        final vuln = ReusedChallengeServer();
        final c = vuln.issueChallenge();
        final a = assertion();
        expect(vuln.verifyAssertion(a, challenge: c), isTrue);
        expect(
          vuln.verifyAssertion(a, challenge: c),
          isTrue,
        ); // replay accepted
      },
    );

    test('secure server consumes the challenge, blocking replay', () {
      final secure = SecureChallengeServer();
      final c = secure.issueChallenge();
      final a = assertion();
      expect(secure.verifyAssertion(a, challenge: c), isTrue);
      expect(secure.verifyAssertion(a, challenge: c), isFalse); // consumed
    });
  });

  group('passkey_user_verification_bypass', () {
    test('vulnerable verifier accepts presence-only despite UV=required', () {
      expect(
        UvVerifier.verify(
          signatureValid: true,
          userPresent: true,
          userVerified: false,
        ),
        isTrue,
      );
    });

    test('secure verifier rejects presence-only when UV=required', () {
      expect(
        UvVerifier.secureVerify(
          signatureValid: true,
          userPresent: true,
          userVerified: false,
        ),
        isFalse,
      );
      expect(
        UvVerifier.secureVerify(
          signatureValid: true,
          userPresent: true,
          userVerified: true,
        ),
        isTrue,
      );
    });
  });

  group('passkey_stepup_auth_bypass', () {
    test('vulnerable flow verifies step-up from mere passkey existence', () {
      final r = StepUpFlow.attemptSensitiveAction(
        hasRegisteredPasskey: true,
        freshAssertionCompleted: false,
      );
      expect(r.verified, isTrue);
      expect(r.actionAllowed, isTrue);
    });

    test('secure flow requires a fresh assertion bound to the challenge', () {
      final blocked = StepUpFlow.secureAttemptSensitiveAction(
        hasRegisteredPasskey: true,
        freshAssertionCompleted: false,
        issuedChallenge: 'stepup-chal-42',
        assertedChallenge: '',
      );
      expect(blocked.actionAllowed, isFalse);

      final allowed = StepUpFlow.secureAttemptSensitiveAction(
        hasRegisteredPasskey: true,
        freshAssertionCompleted: true,
        issuedChallenge: 'stepup-chal-42',
        assertedChallenge: 'stepup-chal-42',
      );
      expect(allowed.actionAllowed, isTrue);
    });
  });

  group('passkey_credential_management_authz', () {
    test('vulnerable endpoints let attacker implant + delete on victim', () {
      final svc = CredentialManagementService();
      expect(
        svc.registerCredential(
          callerAccount: 'attacker',
          targetAccount: 'victim',
          credentialId: 'attacker-implanted',
        ),
        isTrue,
      );
      expect(svc.credentialsOf('victim'), contains('attacker-implanted'));
      expect(
        svc.deleteCredential(
          callerAccount: 'attacker',
          targetAccount: 'victim',
          credentialId: 'victim-passkey-1',
        ),
        isTrue,
      );
      expect(svc.credentialsOf('victim'), isNot(contains('victim-passkey-1')));
    });

    test('secure endpoints deny cross-account register/delete', () {
      final svc = CredentialManagementService();
      expect(
        svc.secureRegisterCredential(
          callerAccount: 'attacker',
          targetAccount: 'victim',
          credentialId: 'attacker-implanted',
        ),
        isFalse,
      );
      expect(
        svc.secureDeleteCredential(
          callerAccount: 'attacker',
          targetAccount: 'victim',
          credentialId: 'victim-passkey-1',
        ),
        isFalse,
      );
      expect(svc.credentialsOf('victim'), contains('victim-passkey-1'));
      expect(
        svc.credentialsOf('victim'),
        isNot(contains('attacker-implanted')),
      );
    });
  });

  group('passkey_session_fixation', () {
    const fixedId = 'ATTACKER-FIXED-SESSION-1234';

    test('vulnerable login keeps the pre-auth (attacker-known) session id', () {
      final r = SessionFixationFlow.login(
        preAuthSessionId: fixedId,
        assertionValid: true,
      );
      expect(r.authenticated, isTrue);
      expect(r.rotated, isFalse);
      expect(r.sessionId, fixedId); // attacker's id is now authenticated
    });

    test('secure login rotates the session id', () {
      final r = SessionFixationFlow.secureLogin(
        preAuthSessionId: fixedId,
        assertionValid: true,
      );
      expect(r.authenticated, isTrue);
      expect(r.rotated, isTrue);
      expect(r.sessionId, isNot(fixedId));
    });
  });

  group('passkey_thirdparty_pairing_authz', () {
    test('vulnerable broker pairs a rogue requester with no checks', () {
      final r = PairingBroker.approve(
        requesterId: 'com.evil.rogue.authenticator',
        userConsented: false,
        hasPairingPermission: false,
      );
      expect(r.paired, isTrue);
    });

    test('secure broker requires allow-list, permission, and consent', () {
      final rogue = PairingBroker.secureApprove(
        requesterId: 'com.evil.rogue.authenticator',
        userConsented: false,
        hasPairingPermission: false,
      );
      expect(rogue.paired, isFalse);

      final trusted = PairingBroker.secureApprove(
        requesterId: 'com.dvma.trusted.authenticator',
        userConsented: true,
        hasPairingPermission: true,
      );
      expect(trusted.paired, isTrue);
    });
  });
}
