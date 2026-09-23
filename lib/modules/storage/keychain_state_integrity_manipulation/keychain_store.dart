/// Keychain State Integrity Manipulation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-565 / CWE-472): the app TRUSTS a
/// Keychain/Keystore item as authoritative and acts on it (grants privilege)
/// with no integrity check. A LOCAL attacker who can MODIFY the stored item -
/// not merely read it - flips an `admin` entitlement blob and is silently
/// granted elevated access. This is an INTEGRITY failure distinct from secret
/// confidentiality: the value is not secret, it is trusted (the iOS Keychain
/// state-modification CVE-2026-28860 class).
///
/// This is an offline + deterministic SIMULATION. [KeychainStore] holds items
/// as raw strings alongside an integrity tag (a real HMAC-SHA256 over the value
/// with an app-held key the attacker does not possess). The vulnerable
/// [readTrusted] returns whatever bytes are stored and the app acts on them
/// with no MAC verification; the secure [readVerified] recomputes and compares
/// the MAC and REJECTS a tampered item.
///
/// real ARTIFACT: [persist] writes the current item's `value` and its
/// HMAC-SHA256 `mac` into SharedPreferences. On Android that backing
/// file, `/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml`, is a
/// plain, adb-pullable/objection-writable file, so a LOCAL attacker can edit
/// the stored entitlement blob directly on disk (the integrity-manipulation
/// surface). The MissingPluginException path keeps `flutter test` deterministic.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

/// A stored keychain item: an opaque value plus an integrity tag.
class KeychainItem {
  const KeychainItem({required this.value, required this.tag});

  /// The stored payload the app reads (e.g. an entitlement blob).
  final String value;

  /// The integrity tag (MAC) that was written alongside [value]. When an
  /// attacker rewrites [value] via [KeychainStore.attackerModify] WITHOUT the
  /// app key, this tag is left stale so a verifier can detect tampering.
  final String tag;
}

/// The outcome of resolving an entitlement from a keychain item.
class TrustDecision {
  const TrustDecision({
    required this.key,
    required this.storedValue,
    required this.privilegeGranted,
    required this.integrityVerified,
    required this.tampered,
    this.reason,
  });

  /// The key that was read.
  final String key;

  /// The raw value the read returned.
  final String storedValue;

  /// Whether the app granted the elevated privilege based on the value.
  final bool privilegeGranted;

  /// Whether an integrity/MAC check was actually performed and passed.
  final bool integrityVerified;

  /// True when a tampered item was ACTED ON (privilege granted on forged
  /// state) - the integrity-manipulation hit.
  final bool tampered;

  /// Why the secure path rejected / allowed.
  final String? reason;
}

/// An in-memory model of a Keychain/Keystore holding trusted state.
class KeychainStore {
  KeychainStore(Map<String, KeychainItem> seed)
    : _items = Map<String, KeychainItem>.from(seed);

  final Map<String, KeychainItem> _items;

  /// The key holding the entitlement blob the app trusts.
  static const String entitlementKey = 'admin_entitlement';

  /// The legitimate (non-admin) entitlement blob written by the app.
  static const String genuineValue = 'role=user;tier=standard';

  /// The forged blob a local attacker writes to escalate to admin.
  static const String forgedValue = 'role=admin;tier=platinum';

  /// The app-held MAC key. The attacker who can WRITE the item does not know
  /// this, so a forged value cannot carry a valid tag.
  static const String _appMacKey = 'app-hmac-key-7c1f';

  /// A real HMAC-SHA256 over [value] keyed by the app-held [key]. The attacker
  /// who can WRITE the item does not know the key, so a rewritten value cannot
  /// carry a matching tag and the verifier detects the tampering.
  static String mac(String value, {String key = _appMacKey}) {
    final digest = Hmac(sha256, utf8.encode(key)).convert(utf8.encode(value));
    return 'mac:${digest.toString()}';
  }

  /// A store seeded with a genuine, correctly-MACed entitlement.
  factory KeychainStore.seeded() {
    return KeychainStore({
      entitlementKey: KeychainItem(value: genuineValue, tag: mac(genuineValue)),
    });
  }

  /// The raw item currently stored at [key] (for evidence / assertions).
  KeychainItem? itemAt(String key) => _items[key];

  /// LOCAL ATTACKER: overwrite the stored value WITHOUT the app MAC key. The
  /// existing tag is left stale (the attacker cannot forge a valid MAC), so a
  /// verifier can detect this - but the vulnerable reader never checks.
  void attackerModify(String key, String newValue) {
    final existing = _items[key];
    _items[key] = KeychainItem(
      value: newValue,
      // Stale tag: still the MAC over the OLD value.
      tag: existing?.tag ?? '',
    );
  }

  static bool _grantsAdmin(String value) => value.contains('role=admin');

  /// VULN: read the item and act on it as authoritative with no integrity
  /// check. A tampered value therefore grants the privilege it encodes.
  TrustDecision readTrusted(String key) {
    final item = _items[key];
    final value = item?.value ?? '';
    final granted = _grantsAdmin(value);
    return TrustDecision(
      key: key,
      storedValue: value,
      privilegeGranted: granted,
      integrityVerified: false,
      // The app acted on a forged blob whose tag does not match.
      tampered: granted && item != null && mac(value) != item.tag,
      reason: 'trusted stored value with no MAC verification',
    );
  }

  /// SECURE contrast: recompute the MAC over the stored value with the app key
  /// and compare it to the stored tag. A tampered item fails verification and
  /// the privilege is REFUSED; only a genuine, correctly-MACed value is acted
  /// on.
  TrustDecision readVerified(String key) {
    final item = _items[key];
    if (item == null) {
      return TrustDecision(
        key: key,
        storedValue: '',
        privilegeGranted: false,
        integrityVerified: false,
        tampered: false,
        reason: 'no such item',
      );
    }
    final expected = mac(item.value);
    if (expected != item.tag) {
      return TrustDecision(
        key: key,
        storedValue: item.value,
        privilegeGranted: false,
        integrityVerified: false,
        tampered: false,
        reason:
            'integrity tag mismatch - stored state was modified locally; '
            'privilege refused',
      );
    }
    return TrustDecision(
      key: key,
      storedValue: item.value,
      privilegeGranted: _grantsAdmin(item.value),
      integrityVerified: true,
      tampered: false,
      reason: 'MAC verified - value is authentic',
    );
  }

  /// SharedPreferences keys the trusted entitlement blob and its tag persist
  /// under. Both land in the adb-pullable shared_prefs XML so a LOCAL attacker
  /// can rewrite the value on disk (the integrity-manipulation surface).
  static String prefsValueKey(String key) => 'keychain_state_${key}_value';
  static String prefsTagKey(String key) => 'keychain_state_${key}_tag';

  /// real ARTIFACT: persist the item at [key] (its `value` and its weak `tag`)
  /// into SharedPreferences so the trusted state lives in a plain on-disk file
  /// that a local attacker can edit. Returns the two `k=v` lines actually
  /// written. Degrades to just returning the lines under `flutter test`.
  Future<String> persist(String key) async {
    final item = _items[key];
    final value = item?.value ?? '';
    final tag = item?.tag ?? '';
    final lines = '${prefsValueKey(key)}=$value\n${prefsTagKey(key)}=$tag';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsValueKey(key), value);
      await prefs.setString(prefsTagKey(key), tag);
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`): lines still returned.
    } catch (_) {
      // Best effort: never perturb the demo.
    }
    return lines;
  }
}
