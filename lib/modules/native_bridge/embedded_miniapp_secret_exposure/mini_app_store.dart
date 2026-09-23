/// Embedded Mini-App Secret Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-522 / CWE-294, MASVS-STORAGE-1,
/// OWASP M9): an embedded web-app / Mini-App persists PLAINTEXT, REPLAYABLE auth
/// tokens - and a recovery secret such as a wallet mnemonic - in WebView
/// storage (localStorage / IndexedDB) reachable over the JS<->native bridge
/// with no origin isolation. Any embedded content or a co-resident inspector
/// (another Mini-App in the same WebView, an injected script, r2frida) simply
/// reads the storage and replays the token, or exfiltrates the mnemonic. This
/// is the Telegram Mini App / TENET research class.
///
/// The secure contrast never persists the raw token or the mnemonic in
/// WebView-reachable storage. Instead the native side mints a short-lived,
/// origin-bound, single-use HANDLE (HMAC'd over the origin + a nonce). A bridge
/// getter returns only that handle to the calling origin, and redeeming it
/// requires the SAME origin and consumes the nonce, so a replay - from another
/// origin, or a second time - fails, and the mnemonic is never reachable over
/// the bridge at all.
///
/// Offline + deterministic: [MiniAppStore] models WebView storage and a
/// keyed-hash mint/redeem in pure Dart (a tiny FNV-based MAC over origin+nonce
/// stands in for a real HMAC - no crypto libs). A test can assert the vuln
/// getter leaks the plaintext token + mnemonic and that a cross-origin / repeat
/// replay of the secure handle fails.
library;

/// A request made over the JS<->native bridge by embedded web content.
class BridgeRequest {
  const BridgeRequest({required this.callerOrigin, this.handle});

  /// The origin of the embedded content making the call.
  final String callerOrigin;

  /// A previously-issued secure handle being redeemed (secure path only).
  final String? handle;
}

/// The outcome of a bridge getter / redemption.
class MiniAppResult {
  const MiniAppResult({
    required this.granted,
    required this.blocked,
    this.token,
    this.mnemonic,
    this.handle,
    this.reason,
  });

  /// Whether the call returned usable auth material.
  final bool granted;

  /// Whether the call was refused (secure path).
  final bool blocked;

  /// The plaintext, replayable auth token (leaked on the vuln path only).
  final String? token;

  /// The recovery secret / wallet mnemonic (leaked on the vuln path only).
  final String? mnemonic;

  /// The short-lived, origin-bound handle handed back on the secure path.
  final String? handle;

  /// Why the call was refused (secure path only).
  final String? reason;

  /// True when replayable secret material was returned to embedded content -
  /// the actual exposure hit.
  bool get secretExposed => granted && (token != null || mnemonic != null);
}

/// A minimal, in-memory model of a Mini-App's WebView storage + native bridge.
class MiniAppStore {
  MiniAppStore({this.trustedOrigin = defaultTrustedOrigin});

  /// The first-party origin the Mini-App was launched for.
  final String trustedOrigin;

  static const String defaultTrustedOrigin = 'https://miniapp.dvma.example';

  /// The long-lived, replayable auth token (as a real Mini-App would persist).
  static const String authToken = 'ma-auth-7f21-REPLAYABLE';

  /// A high-value recovery secret: a wallet mnemonic.
  static const String walletMnemonic =
      'legal winner thank year wave sausage worth useful legal winner thank yellow';

  /// VULN: WebView storage (localStorage/IndexedDB) holding the secrets in
  /// PLAINTEXT. Anything running in the WebView can read this map.
  final Map<String, String> webViewStorage = {
    'auth_token': authToken,
    'wallet_mnemonic': walletMnemonic,
  };

  /// Native-side secret vault used only by the secure path. never exposed to
  /// the bridge; the mnemonic lives here and never leaves.
  final Map<String, String> _nativeVault = {
    'auth_token': authToken,
    'wallet_mnemonic': walletMnemonic,
  };

  /// Origin-bound, single-use handles minted by the secure path: handle -> the
  /// origin it is bound to. Consumed on redemption so a handle cannot be
  /// replayed.
  final Map<String, String> _liveHandles = {};

  int _nonce = 0;

  /// VULN: a bridge getter callable by ANY embedded origin that reads the
  /// plaintext token AND the mnemonic straight out of WebView storage. No
  /// origin isolation, fully replayable.
  MiniAppResult getStoredAuth(BridgeRequest req) {
    return MiniAppResult(
      granted: true,
      blocked: false,
      token: webViewStorage['auth_token'],
      mnemonic: webViewStorage['wallet_mnemonic'],
      reason: 'read plaintext from WebView storage (no origin isolation)',
    );
  }

  /// SECURE contrast (mint): the native side returns only a short-lived,
  /// origin-bound, single-use handle - never the raw token, never the mnemonic.
  /// A non-trusted origin gets nothing.
  MiniAppResult mintAuthHandle(BridgeRequest req) {
    if (req.callerOrigin != trustedOrigin) {
      return MiniAppResult(
        granted: false,
        blocked: true,
        reason: 'origin ${req.callerOrigin} not the Mini-App origin',
      );
    }
    final handle = _mint(req.callerOrigin);
    _liveHandles[handle] = req.callerOrigin;
    return MiniAppResult(
      granted: true,
      blocked: false,
      handle: handle,
      reason: 'issued short-lived, origin-bound, single-use handle',
    );
  }

  /// SECURE contrast (redeem): exchange a handle for the token, but only if it
  /// was issued to the SAME origin and has not been used before. The mnemonic
  /// is never redeemable over the bridge. A replay from another origin, or a
  /// second redemption, fails.
  MiniAppResult redeemAuthHandle(BridgeRequest req) {
    final handle = req.handle;
    if (handle == null) {
      return const MiniAppResult(
        granted: false,
        blocked: true,
        reason: 'no handle presented',
      );
    }
    final boundOrigin = _liveHandles[handle];
    if (boundOrigin == null) {
      return MiniAppResult(
        granted: false,
        blocked: true,
        reason: 'handle unknown, expired, or already consumed (no replay)',
      );
    }
    if (boundOrigin != req.callerOrigin) {
      return MiniAppResult(
        granted: false,
        blocked: true,
        reason:
            'handle bound to $boundOrigin, presented by '
            '${req.callerOrigin} (cross-origin replay blocked)',
      );
    }
    if (!_verify(handle, boundOrigin)) {
      return const MiniAppResult(
        granted: false,
        blocked: true,
        reason: 'handle MAC failed verification',
      );
    }
    _liveHandles.remove(handle); // single-use: consume it
    return MiniAppResult(
      granted: true,
      blocked: false,
      token: _nativeVault['auth_token'],
      reason: 'redeemed single-use, origin-bound handle',
    );
  }

  // --- tiny keyed-hash "MAC" over origin + nonce (no crypto libs) ------------

  static const String _macKey = 'dvma-miniapp-mac-key';

  String _mint(String origin) {
    final nonce = _nonce++;
    final mac = _mac('$origin|$nonce');
    return 'h.$nonce.$mac';
  }

  bool _verify(String handle, String origin) {
    final parts = handle.split('.');
    if (parts.length != 3) return false;
    final nonce = parts[1];
    return parts[2] == _mac('$origin|$nonce');
  }

  /// A small deterministic FNV-1a-based MAC keyed with [_macKey]. Stands in for
  /// an HMAC purely so the demo stays offline with no crypto dependency.
  static String _mac(String data) {
    var hash = 0x811c9dc5;
    for (final code in '$_macKey|$data'.codeUnits) {
      hash ^= code;
      hash = (hash * 0x01000193) & 0xFFFFFFFF;
    }
    return hash.toRadixString(16).padLeft(8, '0');
  }
}
