import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/evidence_sink.dart';

/// Shared, real on-disk persistence for the passkey modules.
///
/// The passkey ceremony LOGIC that makes each scenario vulnerable stays in the
/// individual screens/helpers; this class exists only so that the
/// security-relevant *result* of a vulnerable action (the reused challenge, the
/// non-rotated session id, the accepted cross-origin assertion, ...) is written
/// to real SharedPreferences. That XML file is then device-extractable via
/// `adb`/objection, and the same artifact is mirrored to the DVMA evidence sink
/// so the dynamic-analysis harness can find it.
///
/// Writes go through a try/catch on [MissingPluginException] with an in-memory
/// fallback so `flutter test` (which has no platform channel) still passes -
/// mirroring the pattern in
/// `lib/modules/storage/insecure_local_storage/insecure_storage.dart`.
class PasskeyEvidenceStore {
  PasskeyEvidenceStore._();

  /// Namespaced prefix so every passkey artifact key is easy to grep for in the
  /// pulled `shared_prefs/*.xml`.
  static const String keyPrefix = 'dvma_passkey_';

  /// In-memory mirror used when the SharedPreferences plugin is unavailable
  /// (unit tests / desktop hosts without the channel).
  static final Map<String, String> _fallback = <String, String>{};

  /// Persists [value] to real SharedPreferences under `keyPrefix + suffix`,
  /// records the artifact to the evidence sink (fire-and-forget), and returns
  /// the full prefs key so callers can surface the exact adb-recoverable path.
  ///
  /// Never throws: a missing platform channel falls back to the in-memory map.
  static Future<String> persist({
    required String vulnId,
    required String kind,
    required String keySuffix,
    required String value,
  }) async {
    final prefsKey = '$keyPrefix$keySuffix';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, value);
    } on MissingPluginException {
      // No platform channel (unit test / unsupported host): keep it in memory
      // so the vulnerable path still "persists" for the demo + assertions.
      _fallback[prefsKey] = value;
    } catch (_) {
      _fallback[prefsKey] = value;
    }
    // Mirror the real artifact (incl. the shared_prefs key) to the evidence
    // sink so the harness can pull it. Fire-and-forget; never perturbs the demo.
    unawaited(
      DvmaEvidence.record(vulnId, kind, 'shared_prefs key=$prefsKey :: $value'),
    );
    return prefsKey;
  }

  /// Reads back a persisted artifact (prefs first, then the in-memory
  /// fallback), so a screen/test can show exactly what sits on disk.
  static Future<String?> read(String keySuffix) async {
    final prefsKey = '$keyPrefix$keySuffix';
    try {
      final prefs = await SharedPreferences.getInstance();
      return prefs.getString(prefsKey) ?? _fallback[prefsKey];
    } on MissingPluginException {
      return _fallback[prefsKey];
    } catch (_) {
      return _fallback[prefsKey];
    }
  }
}

/// Minimal, offline simulation of a WebAuthn/passkey (FIDO2) ceremony, wired up
/// with the DVMA passkey weaknesses. This is not a real authenticator - it
/// models just enough of registration (attestation) and authentication
/// (assertion) to make the vulnerabilities demonstrable and unit-testable
/// without a device, biometric prompt, or network.
///
/// Scope of what these modules teach: the FIDO2 signature verification is
/// intentionally stubbed, [PasskeyAssertion.signatureValid] is
/// hardcoded `true` (the authenticator's private-key signature is assumed to
/// check out). These modules deliberately exercise the relying-party-side
/// authorization flaws that sit on top of a valid signature: origin/RP-ID
/// binding, challenge freshness/reuse, sign-count/replay, user-verification
/// enforcement, attestation trust, and credential-management authz, on real
/// attacker-controlled inputs. They are not a demonstration of signature-crypto
/// forgery; a full FIDO2 crypto stack (real P-256/ES256 keypair + assertion
/// signing/verification) would be required for that and is out of scope here.
///
/// The individual insecure behaviors live in the passkey module screens; this
/// class provides the shared primitives they build on.
class PasskeyCeremony {
  PasskeyCeremony._();

  /// Shared disclosure appended to each passkey module's on-screen explanation.
  /// These demos exercise relying-party authorization on real attacker inputs;
  /// the FIDO2 signature check itself is assumed valid (out of scope), so this
  /// is stated in the UI rather than only in code.
  static const String scopeNote =
      'Scope: the FIDO2 signature is assumed valid (signature verification is '
      'out of scope); the flaw demonstrated is in the relying-party '
      'authorization logic on top of it.';

  /// A registration/attestation result from a (simulated) authenticator.
  static PasskeyAttestation register({
    required String rpId,
    required String userName,
    String attestationFormat = 'none',
  }) {
    // Non-secure id generation is fine for a simulation; the *vulnerability*
    // is in how the relying party (app) validates what comes back.
    final rnd = Random(userName.hashCode ^ rpId.hashCode);
    final credId = base64Url
        .encode(List<int>.generate(16, (_) => rnd.nextInt(256)))
        .replaceAll('=', '');
    return PasskeyAttestation(
      credentialId: credId,
      rpId: rpId,
      userName: userName,
      // 'none' means the authenticator provided no attestation statement -
      // there is nothing to verify the authenticator's provenance.
      attestationFormat: attestationFormat,
      attestationStatement: attestationFormat == 'none'
          ? const {}
          : {'x5c': 'simulated-cert'},
    );
  }

  /// An authentication/assertion produced against [rpId] / [origin].
  static PasskeyAssertion assertion({
    required String credentialId,
    required String rpId,
    required String origin,
  }) {
    return PasskeyAssertion(
      credentialId: credentialId,
      rpId: rpId,
      origin: origin,
      // The authenticator's private-key signature is ASSUMED valid here (the
      // FIDO2 signature crypto is out of scope / stubbed); each module's
      // vulnerability is in the relying party's authorization checks ON TOP of
      // a valid signature, never in forging the signature itself.
      signatureValid: true,
    );
  }
}

/// Result of a passkey registration ceremony.
class PasskeyAttestation {
  PasskeyAttestation({
    required this.credentialId,
    required this.rpId,
    required this.userName,
    required this.attestationFormat,
    required this.attestationStatement,
  });

  final String credentialId;
  final String rpId;
  final String userName;
  final String attestationFormat;
  final Map<String, Object?> attestationStatement;
}

/// Result of a passkey authentication ceremony.
class PasskeyAssertion {
  PasskeyAssertion({
    required this.credentialId,
    required this.rpId,
    required this.origin,
    required this.signatureValid,
  });

  final String credentialId;
  final String rpId;
  final String origin;
  final bool signatureValid;
}
