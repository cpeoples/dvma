/// Silent SDK Auto-Update helper (Post-Deploy Behavior Change).
///
/// INTENTIONALLY VULNERABLE (CWE-494 / CWE-829 / MASVS-CODE-3): a benign-looking
/// SDK fetches a "behavior descriptor" from a remote at runtime and swaps it in
/// WITHOUT verifying a signature or checksum. This is the SpinOK-style pattern:
/// the app passes store review and installs cleanly with benign behavior, then
/// - with no app update, no new store submission, and no signature check - the
/// SDK silently downloads new instructions and turns malicious AFTER install.
/// The shipped binary never changes; the behavior does.
///
/// This is offline + deterministic: the "remote" is just a plain [Map] you pass
/// in (no real network), so a test can assert that applying a malicious,
/// unsigned payload flips behavior to exfiltrate data.
///
///  * VULN: [UpdatableSdk.checkForUpdate] applies any payload it is handed,
///    unsigned. After a malicious payload, [UpdatableSdk.run] exfiltrates the
///    device contacts / auth token.
///  * SECURE contrast: [SignedSdkUpdater.applyIfVerified] requires a valid
///    signature (deterministic HMAC-ish check) and REJECTS the unsigned/forged
///    payload, so behavior stays benign.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

/// Device-local data the SDK should never touch, used to prove exfiltration.
class DeviceData {
  DeviceData._();

  static const List<String> contacts = ['Alice <alice@example.com>', 'Bob'];
  static const String authToken = 'auth_token=eyJhbGciOiJIUzI1NiJ9.session';
}

/// A remote "behavior descriptor". In the wild this is fetched over the
/// network; here it is a plain object handed to the SDK offline.
class RemotePayload {
  const RemotePayload({required this.behavior, this.signature});

  /// 'ads' (benign) or 'exfiltrate' (malicious).
  final String behavior;

  /// Optional signature. The vulnerable path ignores it entirely.
  final String? signature;

  Map<String, Object?> toMap() => {
    'behavior': behavior,
    'signature': signature,
  };
}

/// The result of invoking the SDK's current behavior.
class SdkResult {
  const SdkResult({required this.behavior, required this.output});

  final String behavior;
  final String output;

  bool get exfiltrated => behavior == 'exfiltrate';

  @override
  String toString() => '[$behavior] $output';
}

/// VULN: a benign-looking SDK that self-updates its behavior at runtime with no
/// integrity check.
class UpdatableSdk {
  /// Starts benign: it just serves an ad and touches no device data.
  String _behavior = 'ads';

  String get behavior => _behavior;

  /// VULN: fetch + apply a new behavior descriptor from the "remote" with no
  /// signature/checksum verification. Whatever the remote says, we become.
  void checkForUpdate(RemotePayload remotePayload) {
    // No verification of remotePayload.signature. No checksum. No allowlist.
    _behavior = remotePayload.behavior;
  }

  /// VULN (real network): actually fetch the behavior descriptor from the
  /// remote update server at `$base/sdk-update` and apply it with no signature
  /// check. The GET hits the wire (observable in mitmproxy/tcpdump); the parsed
  /// descriptor is applied verbatim. Returns the [RemotePayload] that was
  /// applied (falling back to the local descriptor if the fetch/parse fails so
  /// the offline/test path still flips behavior).
  Future<RemotePayload> fetchAndApplyUpdate(
    String base, {
    required RemotePayload fallback,
  }) async {
    final url = '$base/sdk-update';
    RemotePayload applied = fallback;
    try {
      final resp = await http
          .get(Uri.parse(url))
          .timeout(const Duration(seconds: 6));
      // Parse whatever the "remote" returned. No signature/checksum check.
      final decoded = jsonDecode(resp.body);
      if (decoded is Map && decoded['behavior'] is String) {
        applied = RemotePayload(
          behavior: decoded['behavior'] as String,
          signature: decoded['signature'] as String?,
        );
      }
    } catch (_) {
      // Listener may not reply with a valid descriptor; the request still hit
      // the wire. Fall back to the local malicious descriptor.
      applied = fallback;
    }
    // VULN: apply unconditionally, unsigned.
    checkForUpdate(applied);
    return applied;
  }

  /// Invoke the SDK's current behavior. After a malicious update this
  /// exfiltrates device data even though the app binary never changed.
  SdkResult run() {
    switch (_behavior) {
      case 'exfiltrate':
        final stolen =
            '${DeviceData.contacts.join(', ')}; ${DeviceData.authToken}';
        return SdkResult(
          behavior: 'exfiltrate',
          output: 'exfiltrated: $stolen',
        );
      case 'ads':
      default:
        return const SdkResult(behavior: 'ads', output: 'served ad banner');
    }
  }
}

/// SECURE contrast: an updater that only applies a payload whose signature
/// verifies. The malicious/unsigned payload is rejected, so behavior stays
/// benign.
class SignedSdkUpdater {
  SignedSdkUpdater(this._sdk);

  final UpdatableSdk _sdk;

  /// A trusted secret baked into the app for verifying update signatures. In
  /// production this is an asymmetric public key pinned in the binary.
  static const String _trustedKey = 'DVMA-UPDATE-SIGNING-KEY-v1';

  /// Deterministic HMAC-ish signature over a behavior descriptor. Only the
  /// signing service (which holds [_trustedKey]) can produce a valid value.
  static String expectedSignature(String behavior) {
    // Simple, deterministic, offline stand-in for HMAC(key, behavior).
    var hash = 0x811c9dc5;
    for (final code in '$behavior|$_trustedKey'.codeUnits) {
      hash = (hash ^ code) & 0xffffffff;
      hash = (hash * 0x01000193) & 0xffffffff;
    }
    return 'sig_${hash.toRadixString(16)}';
  }

  /// SECURE: apply the payload only if its signature verifies. Returns true if
  /// applied. A missing/forged signature (the malicious auto-update) is
  /// rejected and the SDK keeps its benign behavior.
  bool applyIfVerified(RemotePayload payload) {
    final expected = expectedSignature(payload.behavior);
    if (payload.signature == null || payload.signature != expected) {
      return false; // reject unsigned/forged update
    }
    _sdk.checkForUpdate(payload);
    return true;
  }
}
