/// Keychain Access-Group Authorization Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-522 / CWE-284 / CWE-668): keychain items are
/// stored under an over-broad `kSecAttrAccessGroup` (a WILDCARD or a widely-
/// shared group) and/or marked `synchronizable`, so another app, an app
/// extension, or another user profile that presents a different access group
/// can still READ items that should be isolated to the owning app. The bug is
/// an AUTHORIZATION confusion at the access-group boundary - distinct from weak
/// item accessibility (kSecAttrAccessible) misuse.
///
/// [KeychainService] holds items each tagged with an `accessGroup` + a
/// `synchronizable` flag. The vulnerable [read] returns items whose group is a
/// wildcard / shared group to ANY caller; the secure [readScoped] requires an
/// EXACT app-private access-group match and refuses cross-group reads.
///
/// real ARTIFACT: [persistSeeded] writes the isolated secret into
/// SharedPreferences under a key that embeds the over-broad WILDCARD access
/// group (`keychain_accessgroup_*_refresh_token`). On Android that lands in
/// `/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml`, a plain,
/// unencrypted, adb-pullable file where the "isolated" credential and the
/// wildcard group it was mistakenly scoped to are both visible to any app /
/// objection. A `MissingPluginException` (under `flutter test`) is swallowed so
/// the deterministic simulation keeps working offline.
library;

import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

/// A stored keychain item tagged with its access group.
class KeychainRecord {
  const KeychainRecord({
    required this.key,
    required this.value,
    required this.accessGroup,
    this.synchronizable = false,
  });

  final String key;

  /// The sensitive secret.
  final String value;

  /// The `kSecAttrAccessGroup` the item was stored under. A wildcard (`*`) or
  /// a broad shared group means any caller can match it.
  final String accessGroup;

  /// Whether the item is iCloud-synced (`kSecAttrSynchronizable`), widening
  /// exposure across a user's other devices / profiles.
  final bool synchronizable;
}

/// The outcome of a keychain read attempt by some caller.
class KeychainReadResult {
  const KeychainReadResult({
    required this.callerAccessGroup,
    required this.key,
    required this.granted,
    required this.crossGroupLeak,
    this.value,
    this.itemAccessGroup,
    this.denyReason,
  });

  /// The access group the CALLER presented.
  final String callerAccessGroup;

  final String key;

  /// Whether the read returned the item.
  final bool granted;

  /// True when a caller read an item stored under a group it should not match
  /// (over-broad / wildcard) - the authorization-confusion hit.
  final bool crossGroupLeak;

  /// The secret returned (null when refused).
  final String? value;

  /// The access group the item was actually stored under.
  final String? itemAccessGroup;

  /// Why the scoped read refused.
  final String? denyReason;
}

/// An in-memory model of a Keychain queried with an access group.
class KeychainService {
  KeychainService(Iterable<KeychainRecord> seed)
    : _records = {for (final r in seed) r.key: r};

  final Map<String, KeychainRecord> _records;

  /// The owning app's private, correctly-scoped access group.
  static const String appPrivateGroup = 'TEAMID.com.dvma.private';

  /// An over-broad WILDCARD group the item was mistakenly stored under.
  static const String wildcardGroup = '*';

  /// A different app / extension that must not reach the owning app's items.
  static const String attackerGroup = 'TEAMID.com.evil.extension';

  /// The isolated secret key.
  static const String secretKey = 'refresh_token';

  /// The isolated secret's value.
  static const String secretValue = 'rt_9f31c0a7-oauth-refresh';

  /// A service where the sensitive item was stored under the WILDCARD group
  /// (the misconfiguration) and also marked synchronizable.
  factory KeychainService.seeded() {
    return KeychainService(const [
      KeychainRecord(
        key: secretKey,
        value: secretValue,
        accessGroup: wildcardGroup,
        synchronizable: true,
      ),
      KeychainRecord(
        key: 'public_pref',
        value: 'theme=dark',
        accessGroup: appPrivateGroup,
      ),
    ]);
  }

  KeychainRecord? recordAt(String key) => _records[key];

  static bool _isBroad(String group) =>
      group == wildcardGroup || group.endsWith('.shared');

  /// VULN: match on the item's stored group but treat a WILDCARD / shared
  /// group as matching ANY caller, so an attacker-group caller reads an
  /// isolated item. `synchronizable` items widen this further.
  KeychainReadResult read(String callerAccessGroup, String key) {
    final rec = _records[key];
    if (rec == null) {
      return KeychainReadResult(
        callerAccessGroup: callerAccessGroup,
        key: key,
        granted: false,
        crossGroupLeak: false,
        denyReason: 'no such item',
      );
    }
    // Over-broad matching: a wildcard/shared group is served to anyone.
    final matched =
        rec.accessGroup == callerAccessGroup || _isBroad(rec.accessGroup);
    return KeychainReadResult(
      callerAccessGroup: callerAccessGroup,
      key: key,
      granted: matched,
      crossGroupLeak: matched && rec.accessGroup != callerAccessGroup,
      value: matched ? rec.value : null,
      itemAccessGroup: rec.accessGroup,
    );
  }

  /// SECURE contrast: require an EXACT, app-private access-group match. A
  /// wildcard/shared stored group is rejected outright as a misconfiguration,
  /// and a caller whose group does not exactly equal the item's private group
  /// is refused.
  KeychainReadResult readScoped(String callerAccessGroup, String key) {
    final rec = _records[key];
    if (rec == null) {
      return KeychainReadResult(
        callerAccessGroup: callerAccessGroup,
        key: key,
        granted: false,
        crossGroupLeak: false,
        denyReason: 'no such item',
      );
    }
    if (_isBroad(rec.accessGroup)) {
      return KeychainReadResult(
        callerAccessGroup: callerAccessGroup,
        key: key,
        granted: false,
        crossGroupLeak: false,
        itemAccessGroup: rec.accessGroup,
        denyReason:
            'item stored under over-broad group "${rec.accessGroup}"; '
            'refusing to serve without an exact app-private group',
      );
    }
    if (rec.accessGroup != callerAccessGroup) {
      return KeychainReadResult(
        callerAccessGroup: callerAccessGroup,
        key: key,
        granted: false,
        crossGroupLeak: false,
        itemAccessGroup: rec.accessGroup,
        denyReason:
            'caller group "$callerAccessGroup" does not match item '
            'group "${rec.accessGroup}"',
      );
    }
    return KeychainReadResult(
      callerAccessGroup: callerAccessGroup,
      key: key,
      granted: true,
      crossGroupLeak: false,
      value: rec.value,
      itemAccessGroup: rec.accessGroup,
    );
  }

  /// The SharedPreferences key the wildcard-scoped secret is persisted under.
  /// The over-broad access group is embedded in the key name so a local
  /// attacker reading the backing XML sees both the isolated credential and
  /// the wildcard group it was mistakenly scoped to.
  static String prefsKey(String key) =>
      'keychain_accessgroup_${wildcardGroup}_$key';

  /// real ARTIFACT: persist the isolated secret into SharedPreferences under a
  /// key embedding the WILDCARD access group. On device this writes the
  /// credential in cleartext to the adb-pullable shared_prefs XML. Returns the
  /// key=value line actually written (from the seeded wildcard record). Under
  /// `flutter test` (no platform channel) it degrades to the in-memory value.
  static Future<String> persistSeeded() async {
    final line = '${prefsKey(secretKey)}=$secretValue';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey(secretKey), secretValue);
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`): line still returned.
    } catch (_) {
      // Best effort: never perturb the demo.
    }
    return line;
  }
}
