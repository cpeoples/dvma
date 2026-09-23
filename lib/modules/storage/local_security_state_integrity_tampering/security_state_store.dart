/// Local Security-State Integrity Tampering helper.
///
/// INTENTIONALLY VULNERABLE (CWE-565 / CWE-345 / CWE-602): a security decision
/// (role, entitlement, jailbreak-check result) is driven by a locally-persisted
/// value (UserDefaults / SharedPreferences / SQLite) that carries no integrity
/// protection. An attacker with local access flips the stored value (sets
/// `role=admin`, `entitlement=premium`) and the app trusts it directly - no
/// secret is stolen; the app is made to trust attacker-controlled STATE
/// (OWASP MASTG-BEST-0065 storage-integrity class).
///
/// A [SecurityStateStore] holds key->value entries, each with the real
/// HMAC-SHA256 tag (keyed by a device-held secret) that the app wrote when it
/// legitimately set the value, and the entries are persisted to a real
/// on-device SQLite db ([SecurityStateDb]). The vulnerable [readDecision]
/// returns the raw value and the gate trusts it; the secure [readDecisionSafe]
/// recomputes the keyed HMAC bound to (key, value) and rejects any entry whose
/// tag does not verify, so a locally-flipped value is refused while a
/// legitimately-MACed value is accepted.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:sqflite/sqflite.dart';

/// One persisted entry: the stored [value] plus the [mac] the app wrote for it.
class SecurityStateEntry {
  const SecurityStateEntry({required this.value, this.mac});

  final String value;

  /// Integrity tag over (key, value). Stale/absent after local tampering.
  final String? mac;
}

/// The outcome of resolving a security decision from stored state.
class SecurityDecision {
  const SecurityDecision({
    required this.key,
    required this.value,
    required this.granted,
    required this.integrityVerified,
    required this.tamperedValueTrusted,
    this.denyReason,
  });

  /// The state key that drove the decision (e.g. 'role', 'entitlement').
  final String key;

  /// The stored value the decision was based on.
  final String value;

  /// Whether the gate granted the privileged capability.
  final bool granted;

  /// Whether the read path verified the value's integrity.
  final bool integrityVerified;

  /// True when a locally-flipped value granted a privilege - the hit.
  final bool tamperedValueTrusted;

  /// Why the secure read refused (mentions 'integrity' on rejection).
  final String? denyReason;
}

class SecurityStateStore {
  SecurityStateStore(this._entries);

  /// The persisted store contents (as they live on-device after tampering).
  final Map<String, SecurityStateEntry> _entries;

  /// Device/keychain-held MAC key. An attacker editing the store on-device
  /// does not possess it, so a flipped value cannot carry a matching tag.
  static const String _macKey = 'kmac-state-2c7d-device-bound';

  static const String keyRole = 'role';
  static const String keyEntitlement = 'entitlement';

  /// The legitimate baseline the app wrote: a free, non-admin user.
  static const Map<String, String> _legitValues = {
    keyRole: 'user',
    keyEntitlement: 'free',
  };

  /// A store whose values were tampered locally (role->admin,
  /// entitlement->premium) but whose tags are STALE (still bound to the
  /// original legitimate values), so they will not verify.
  static SecurityStateStore tamperedStore() {
    return SecurityStateStore({
      keyRole: SecurityStateEntry(
        value: 'admin', // flipped from 'user'
        mac: _macFor(keyRole, _legitValues[keyRole]!), // stale tag
      ),
      keyEntitlement: SecurityStateEntry(
        value: 'premium', // flipped from 'free'
        mac: _macFor(keyEntitlement, _legitValues[keyEntitlement]!),
      ),
    });
  }

  /// A store the app wrote legitimately: values and tags agree.
  static SecurityStateStore legitimateStore() {
    return SecurityStateStore({
      keyRole: SecurityStateEntry(
        value: _legitValues[keyRole]!,
        mac: _macFor(keyRole, _legitValues[keyRole]!),
      ),
      keyEntitlement: SecurityStateEntry(
        value: _legitValues[keyEntitlement]!,
        mac: _macFor(keyEntitlement, _legitValues[keyEntitlement]!),
      ),
    });
  }

  /// A deterministic keyed MAC binding the tag to (macKey, key, value) using a
  /// real HMAC-SHA256 (device/keychain-held key). Any change to the value
  /// without the key produces a different tag, so a locally-flipped value can
  /// no longer carry a matching MAC. The secure read recomputes and compares
  /// this same tag; the vulnerable read ignores it entirely.
  static String _macFor(String key, String value) {
    final mac = Hmac(sha256, utf8.encode(_macKey));
    final digest = mac.convert(utf8.encode('$key=$value'));
    return 'mac:${digest.toString()}';
  }

  bool _grantsFor(String key, String value) {
    if (key == keyRole) return value == 'admin';
    if (key == keyEntitlement) return value == 'premium';
    return false;
  }

  bool _isTampered(String key, String value) =>
      _legitValues[key] != null && _legitValues[key] != value;

  /// VULN: read the raw stored value and let the gate trust it directly, with
  /// no integrity check. A locally-flipped `role=admin` grants admin.
  SecurityDecision readDecision(String key) {
    final entry = _entries[key];
    final value = entry?.value ?? '';
    final granted = _grantsFor(key, value);
    return SecurityDecision(
      key: key,
      value: value,
      granted: granted,
      integrityVerified: false, // never checked
      tamperedValueTrusted: granted && _isTampered(key, value),
    );
  }

  /// SECURE contrast: recompute the keyed MAC bound to (key, value) and compare
  /// against the stored tag. A locally-flipped value carries a stale tag that
  /// will not verify, so the decision is refused; a legitimately-MACed value
  /// verifies and is honored.
  SecurityDecision readDecisionSafe(String key) {
    final entry = _entries[key];
    if (entry == null) {
      return SecurityDecision(
        key: key,
        value: '',
        granted: false,
        integrityVerified: false,
        tamperedValueTrusted: false,
        denyReason: 'no state entry for "$key"',
      );
    }
    final expected = _macFor(key, entry.value);
    if (entry.mac == null || entry.mac != expected) {
      return SecurityDecision(
        key: key,
        value: entry.value,
        granted: false, // fail closed
        integrityVerified: false,
        tamperedValueTrusted: false,
        denyReason:
            'state integrity check failed: MAC mismatch for "$key", '
            'value rejected (possible local tampering)',
      );
    }
    return SecurityDecision(
      key: key,
      value: entry.value,
      granted: _grantsFor(key, entry.value),
      integrityVerified: true,
      tamperedValueTrusted: false, // only integral values reach here
    );
  }
}

/// Real on-device persistence for the security-state row, backed by SQLite.
///
/// INTENTIONALLY VULNERABLE: the app persists the security decision (role /
/// entitlement) into a plain, unprotected SQLite table. An attacker who pulls
/// the db with `adb` can open it with `sqlite3` and flip `role` to `admin` /
/// `entitlement` to `premium`, and the vulnerable read path ([readDecision])
/// will trust the edited value. Persisting to an on-device db (rather than an
/// in-memory map) is what makes the flip reachable with off-device tooling.
///
/// All operations are best-effort and never throw: under `flutter test` (where
/// no `databaseFactory` is registered) the calls no-op so the demo/tests stay
/// offline and deterministic while the in-memory [SecurityStateStore] logic
/// above remains the source of truth for the rendered decision.
class SecurityStateDb {
  SecurityStateDb._();

  static const String dbFileName = 'dvma_security_state.db';
  static const String table = 'security_decision';

  static Future<Database?> _open() async {
    try {
      final dir = await getDatabasesPath();
      final path = '$dir/$dbFileName';
      return await openDatabase(
        path,
        version: 1,
        onCreate: (db, _) async {
          // Plain table, no integrity column: an attacker edits `value` freely.
          await db.execute(
            'CREATE TABLE $table('
            'key TEXT PRIMARY KEY, value TEXT NOT NULL, mac TEXT)',
          );
        },
      );
    } catch (_) {
      // No databaseFactory (unit tests) / platform channel unavailable.
      return null;
    }
  }

  /// Absolute path of the SQLite db file (adb-pullable), or null if the
  /// platform db factory is unavailable (e.g. under `flutter test`).
  static Future<String?> dbPath() async {
    try {
      final dir = await getDatabasesPath();
      final path = '$dir/$dbFileName';
      // Ensure the file exists so `adb pull` / sqlite3 has something to open.
      if (!await File(path).exists()) {
        final db = await _open();
        await db?.close();
      }
      return path;
    } catch (_) {
      return null;
    }
  }

  /// VULN: persists each entry of [store] as a real, unprotected SQLite row.
  /// Best-effort; never throws.
  static Future<void> persist(SecurityStateStore store) async {
    Database? db;
    try {
      db = await _open();
      if (db == null) return;
      final batch = db.batch();
      store._entries.forEach((key, entry) {
        batch.insert(table, {
          'key': key,
          'value': entry.value,
          'mac': entry.mac,
        }, conflictAlgorithm: ConflictAlgorithm.replace);
      });
      await batch.commit(noResult: true);
    } catch (_) {
      // Best effort.
    } finally {
      await db?.close();
    }
  }

  /// Reads the persisted rows back (as `sqlite3` / another app would). Returns
  /// an empty map when the db is unavailable so callers can fall back to the
  /// in-memory store.
  static Future<Map<String, SecurityStateEntry>> load() async {
    Database? db;
    try {
      db = await _open();
      if (db == null) return const {};
      final rows = await db.query(table);
      return {
        for (final r in rows)
          r['key'] as String: SecurityStateEntry(
            value: r['value'] as String,
            mac: r['mac'] as String?,
          ),
      };
    } catch (_) {
      return const {};
    } finally {
      await db?.close();
    }
  }
}
