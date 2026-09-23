import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/auth/cross_app_otp_credential_leak/otp_broadcaster.dart';
import 'package:dvma/modules/platform/intent_arg_injection_rce/arg_injection_launcher.dart';
import 'package:dvma/modules/input_validation/unsafe_media_decoding/media_decoder.dart';

/// Regression suite for the recent CVE-class training modules. Each test
/// asserts the *insecure* behavior is still present (so an accidental "fix"
/// fails CI) AND that the secure contrast rejects the attack.
void main() {
  group('cross_app_otp_credential_leak', () {
    test('malicious app recovers the OTP only on the unprotected channel', () {
      final auth = OtpBroadcaster();
      const counter = 42;

      // VULN: unprotected broadcast -> a co-resident app with no permission
      // reads the OTP + auth deep link.
      auth.broadcastOtp(counter);
      final captured = auth.readAsMaliciousApp();
      expect(captured, isNotNull);
      expect(captured, contains('myauth://login'));
      expect(auth.capturedOtp(), auth.currentOtp(counter));

      // Deterministic OTP: same seed + counter reproduces the same code.
      expect(OtpBroadcaster().currentOtp(counter), auth.currentOtp(counter));

      // SECURE: delivering only to an allowlisted package leaves the shared
      // surface empty, so the (non-allowlisted) malicious app gets nothing.
      final secure = OtpBroadcaster();
      secure.broadcastOtpSecure(counter, 'com.evil.reader');
      expect(secure.readAsMaliciousApp(), isNull);
      expect(secure.capturedOtp(), isNull);
    });
  });

  group('intent_arg_injection_rce', () {
    test('injected cmd executes on exported handler, rejected on secure', () {
      // VULN: attacker-supplied cmd=dump_secrets runs with app privileges.
      final dump = ArgInjectionLauncher.handleIntent({'cmd': 'dump_secrets'});
      expect(dump.executed, isTrue);
      expect(dump.output, contains('app privileges'));
      expect(dump.output, contains('session_token'));

      // VULN: attacker-supplied library path is "loaded" in-process.
      final load = ArgInjectionLauncher.handleIntent({
        '-xrun': '/data/local/tmp/evil.so',
      });
      expect(load.executed, isTrue);
      expect(load.output, contains('/data/local/tmp/evil.so'));

      // SECURE: the same injected execution args are rejected.
      final secureDump = ArgInjectionLauncher.handleIntentSecure({
        'cmd': 'dump_secrets',
      });
      expect(secureDump.executed, isFalse);
      final secureLoad = ArgInjectionLauncher.handleIntentSecure({
        '-xrun': '/data/local/tmp/evil.so',
      });
      expect(secureLoad.executed, isFalse);

      // SECURE still allows a legitimate allowlisted navigation action.
      final ok = ArgInjectionLauncher.handleIntentSecure({
        'action': 'open_home',
      });
      expect(ok.executed, isTrue);
    });
  });

  group('unsafe_media_decoding', () {
    test(
      'decompression bomb over-allocates on decode, rejected by decodeSafe',
      () {
        const bomb = MediaHeader(
          width: 100000,
          height: 100000,
          format: 'x-evil-bomb',
          byteLength: 512,
        );

        // VULN: unchecked decode trusts the header and would allocate ~40 GB.
        final vuln = MediaDecoder.decode(bomb);
        expect(vuln.accepted, isTrue);
        expect(vuln.wouldOom, isTrue);
        expect(vuln.allocationBytes, 100000 * 100000 * 4);
        expect(vuln.allocationBytes, greaterThan(MediaDecoder.maxByteLength));

        // SECURE: the validating decoder rejects the bomb.
        final secure = MediaDecoder.decodeSafe(bomb);
        expect(secure.accepted, isFalse);

        // SECURE still accepts a legitimate, in-bounds image.
        final ok = MediaDecoder.decodeSafe(
          const MediaHeader(
            width: 1024,
            height: 768,
            format: 'png',
            byteLength: 200000,
          ),
        );
        expect(ok.accepted, isTrue);
      },
    );
  });
}
