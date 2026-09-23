/// JS Bridge Exposes a Privileged Native API helper.
///
/// INTENTIONALLY VULNERABLE (CWE-749 / CWE-862 / CWE-926): a WebView native
/// bridge exposes a privileged capability - reading the auth token from the
/// Keychain/Keystore, reading a local file, camera/location - as a plain bridge
/// method callable by ANY loaded web content. There is no origin allowlist and
/// no capability/permission gate, so a page (or an injected script / malicious
/// ad) simply calls `getAuthToken()` or `readFile()` and gets the result. This
/// is the exposed-interface half of the Home Assistant Companion
/// CVE-2026-44698 class.
///
/// The [PrivilegedBridge] models the exposed methods for the deterministic
/// offline contrast (unit tests assert an untrusted origin reads the token on
/// the vuln path and is denied on the secure path). On a real device the screen
/// additionally reads the token from a genuine app-private file via
/// [readAuthTokenFromDisk], so the value handed to untrusted page JS is real,
/// adb-pullable on-disk contents rather than a constant.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// A privileged bridge capability the fixed bridge gates per-origin.
enum BridgeCapability { readAuthToken, readFile }

/// The outcome of a bridge invocation.
class BridgeCallResult {
  const BridgeCallResult({
    required this.invoked,
    required this.blocked,
    this.value,
    this.blockReason,
  });

  /// Whether the privileged method actually ran and returned data.
  final bool invoked;

  /// Whether the bridge refused the call (secure path).
  final bool blocked;

  /// The sensitive value the method returned (null unless leaked).
  final String? value;

  /// Why the call was refused (secure path only).
  final String? blockReason;

  /// True when a sensitive value was returned to an origin that is not on the
  /// trusted allowlist - the actual exposure hit.
  bool leakedTo(String origin, Set<String> allowlist) =>
      invoked && value != null && !allowlist.contains(origin);
}

/// A minimal, in-memory model of a WebView bridge that exposes native methods.
class PrivilegedBridge {
  PrivilegedBridge({Set<String>? allowlist})
    : allowedOrigins = allowlist ?? const {'https://app.dvma.example'};

  /// Origins permitted to call privileged methods (secure path only).
  final Set<String> allowedOrigins;

  /// The auth token held in the (simulated) Keychain/Keystore.
  static const String authToken = 'Bearer at-77c1-keychain-secret';

  static const String _tokenFileName = 'js_bridge_auth_token.txt';

  /// Reads the auth token the exposed bridge leaks from a real app-private
  /// file (seeded once on first use), so the value handed to untrusted page JS
  /// on-device is genuine, adb-pullable disk contents. Falls back to the
  /// in-memory [authToken] under `flutter test` (no writable dir).
  static Future<String> readAuthTokenFromDisk() async {
    try {
      final base = await DvmaEvidence.writableBaseDir();
      if (base != null) {
        final f = File('${base.path}/$_tokenFileName');
        if (!await f.exists()) {
          await f.writeAsString(authToken, flush: true);
        }
        return await f.readAsString();
      }
    } catch (_) {
      // fall through to the in-memory model token
    }
    return authToken;
  }

  /// A private on-device file the bridge can read.
  static const String secretFilePath = 'file:///data/data/com.dvma.app/session';
  static const String secretFileBody = '{"session":"sid-4410-secret"}';

  final Map<String, String> _files = const {secretFilePath: secretFileBody};

  /// VULN: any origin can invoke the privileged method; there is no origin
  /// allowlist and no capability gate. The token/file is returned to whoever
  /// asked.
  BridgeCallResult invoke({
    required BridgeCapability capability,
    required String callerOrigin,
    String? fileArg,
  }) {
    switch (capability) {
      case BridgeCapability.readAuthToken:
        return const BridgeCallResult(
          invoked: true,
          blocked: false,
          value: authToken,
        );
      case BridgeCapability.readFile:
        final body = _files[fileArg];
        return BridgeCallResult(
          invoked: true,
          blocked: false,
          value: body ?? '(file not found: $fileArg)',
        );
    }
  }

  /// SECURE contrast: gate every privileged method behind an origin allowlist
  /// AND a capability check. Untrusted origins are denied before any native
  /// capability runs.
  BridgeCallResult invokeSafe({
    required BridgeCapability capability,
    required String callerOrigin,
    String? fileArg,
    Set<BridgeCapability> grantedCapabilities = const {},
  }) {
    if (!allowedOrigins.contains(callerOrigin)) {
      return BridgeCallResult(
        invoked: false,
        blocked: true,
        blockReason: 'origin $callerOrigin not on allowlist',
      );
    }
    if (!grantedCapabilities.contains(capability)) {
      return BridgeCallResult(
        invoked: false,
        blocked: true,
        blockReason: 'capability ${capability.name} not granted to origin',
      );
    }
    return invoke(
      capability: capability,
      callerOrigin: callerOrigin,
      fileArg: fileArg,
    );
  }
}
