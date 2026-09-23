/// Backup Archive Integrity Tampering helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-565 / CWE-494): the app restores a
/// backup archive of persisted state WITHOUT verifying its integrity. An
/// attacker extracts the backup, edits security-relevant persisted state (flips
/// `is_premium` false->true, raises `balance_cents`, sets `is_admin`), re-packs
/// it, and restores it. Because the restore path trusts the archive contents
/// verbatim, the attacker-controlled state is applied and believed. This is the
/// INTEGRITY direction of backups (unsigned-backup tampering CVE-2025-49199
/// class, OWASP MASTG-BEST-0065), not the read/leak direction.
///
/// This is an offline + deterministic SIMULATION. A [BackupArchive] is a map of
/// key->value plus an optional keyed MAC computed over the entries. The
/// vulnerable [BackupRestorer.restore] applies the archive with no integrity
/// check; the secure [BackupRestorer.restoreSafe] recomputes a keyed MAC over
/// the entries and rejects any archive whose tag does not match (tamper
/// detected), while still accepting the genuine, correctly-tagged archive.
///
/// real ARTIFACT: [BackupRestorer.writeArchiveFile] serializes an archive to a
/// real file (`dvma_backup_archive.txt`) under the app documents directory via
/// `path_provider`, and [BackupRestorer.restoreFromFile] restores FROM that
/// file. On device this file lives in the app's data/documents container, so it
/// is swept into `adb backup` and is pullable/editable, the genuine backup-
/// tampering surface. A local attacker edits the on-disk archive (flips
/// `is_premium`/`is_admin`, raises `balance_cents`) and the unverified restore
/// trusts it. An in-memory fallback keeps `flutter test` deterministic offline.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path_provider/path_provider.dart';

/// A backup archive: persisted key/value state plus an optional integrity tag.
///
/// [mac] is the keyed MAC the app wrote when it produced the backup. On the
/// vulnerable restore path it is ignored entirely; on the secure path it is
/// recomputed and compared. A tampered archive carries a stale/absent tag.
class BackupArchive {
  const BackupArchive({required this.entries, this.mac});

  /// The persisted state key->value pairs (as they would live in the backup).
  final Map<String, String> entries;

  /// The integrity tag written alongside the archive (null when the attacker
  /// stripped it, stale when the attacker edited entries without the key).
  final String? mac;

  String? operator [](String key) => entries[key];
}

/// The state the app holds after a restore, plus integrity evidence.
class RestoreResult {
  const RestoreResult({
    required this.restored,
    required this.integrityVerified,
    required this.premium,
    required this.admin,
    required this.balanceCents,
    required this.tamperedValueTrusted,
    this.denyReason,
  });

  /// Whether the archive was applied to app state.
  final bool restored;

  /// Whether the restore path actually verified archive integrity.
  final bool integrityVerified;

  /// Applied entitlement flag (attacker target).
  final bool premium;

  /// Applied privilege flag (attacker target).
  final bool admin;

  /// Applied account balance in cents (attacker target).
  final int balanceCents;

  /// True when an attacker-modified value was applied and is now trusted -
  /// the vulnerability hit.
  final bool tamperedValueTrusted;

  /// Why the secure restore refused (mentions 'integrity' on rejection).
  final String? denyReason;
}

class BackupRestorer {
  BackupRestorer();

  /// Server/keychain-held MAC key the legitimate backup writer used. An
  /// attacker editing an extracted archive does not possess it, so they cannot
  /// forge a matching tag - which is exactly what the secure path relies on.
  static const String _macKey = 'kmac-backup-9f3a-device-bound';

  /// The genuine, untampered backup as the app legitimately wrote it: a free,
  /// non-admin account with a real balance. Carries a valid integrity tag.
  static BackupArchive genuineArchive() {
    final entries = <String, String>{
      'is_premium': 'false',
      'is_admin': 'false',
      'balance_cents': '1299',
      'account_id': 'acct-55021',
    };
    return BackupArchive(entries: entries, mac: _computeMac(entries));
  }

  /// The attacker-tampered backup: extracted, edited (premium+admin flipped on,
  /// balance raised), and re-packed. The attacker lacks [_macKey], so the tag
  /// is left stale (still bound to the ORIGINAL entries) - it will not verify.
  static BackupArchive tamperedArchive() {
    final entries = <String, String>{
      'is_premium': 'true', // flipped false -> true
      'is_admin': 'true', // flipped false -> true
      'balance_cents': '9900000', // raised from 1299
      'account_id': 'acct-55021',
    };
    // Stale tag: computed over the ORIGINAL genuine entries, not these.
    return BackupArchive(entries: entries, mac: genuineArchive().mac);
  }

  /// A real HMAC-SHA256 keyed MAC over the archive entries. Binds the tag to
  /// BOTH the app-held key and the exact entries, so any edit to the entries
  /// (without the key) invalidates the tag and the verifier detects it.
  static String _computeMac(Map<String, String> entries) {
    final keys = entries.keys.toList()..sort();
    final buffer = StringBuffer();
    for (final k in keys) {
      buffer.write('|$k=${entries[k]}');
    }
    final digest = Hmac(
      sha256,
      utf8.encode(_macKey),
    ).convert(utf8.encode(buffer.toString()));
    return 'mac:${digest.toString()}';
  }

  bool _asBool(String? v) => v == 'true';
  int _asInt(String? v) => int.tryParse(v ?? '') ?? 0;

  /// True when the archive contents differ from the genuine baseline - i.e. an
  /// attacker changed a security-relevant value.
  bool _isTampered(BackupArchive archive) {
    final genuine = genuineArchive().entries;
    for (final entry in genuine.entries) {
      if (archive[entry.key] != entry.value) return true;
    }
    return false;
  }

  /// VULN: apply the archive to app state with no integrity verification. The
  /// restore path trusts whatever the backup says, so a tampered `is_premium`,
  /// `is_admin`, or `balance_cents` is applied and believed.
  RestoreResult restore(BackupArchive archive) {
    final premium = _asBool(archive['is_premium']);
    final admin = _asBool(archive['is_admin']);
    final balance = _asInt(archive['balance_cents']);
    return RestoreResult(
      restored: true,
      integrityVerified: false, // never checked
      premium: premium,
      admin: admin,
      balanceCents: balance,
      // A tampered archive's attacker-set values are now trusted.
      tamperedValueTrusted: _isTampered(archive) && (premium || admin),
    );
  }

  /// SECURE contrast: recompute the keyed MAC over the archive entries and
  /// compare against the tag. A tampered archive's stale/absent tag will not
  /// match, so the restore is refused; the genuine archive verifies and is
  /// applied. Integrity is enforced at the restore boundary.
  RestoreResult restoreSafe(BackupArchive archive) {
    final expected = _computeMac(archive.entries);
    if (archive.mac == null || archive.mac != expected) {
      return const RestoreResult(
        restored: false,
        integrityVerified: false,
        premium: false,
        admin: false,
        balanceCents: 0,
        tamperedValueTrusted: false,
        denyReason:
            'backup integrity check failed: MAC mismatch, '
            'archive rejected (possible tampering)',
      );
    }
    return RestoreResult(
      restored: true,
      integrityVerified: true,
      premium: _asBool(archive['is_premium']),
      admin: _asBool(archive['is_admin']),
      balanceCents: _asInt(archive['balance_cents']),
      tamperedValueTrusted: false, // only integral archives reach here
    );
  }

  /// The on-disk backup archive file name (lives in the app documents dir).
  static const String archiveFileName = 'dvma_backup_archive.txt';

  /// In-memory fallback for the serialized archive under test / when no
  /// documents dir is available.
  static String? _memoryArchive;

  /// Resolves the real backup archive file path, or null under test / when the
  /// documents dir is unavailable.
  static Future<File?> _archiveFile() async {
    try {
      final docs = await getApplicationDocumentsDirectory();
      return File('${docs.path}/$archiveFileName');
    } catch (_) {
      return null;
    }
  }

  /// Serialize an archive to a `k=v` line block plus a trailing `#mac=` line.
  static String _serialize(BackupArchive archive) {
    final keys = archive.entries.keys.toList()..sort();
    final buffer = StringBuffer();
    for (final k in keys) {
      buffer.writeln('$k=${archive.entries[k]}');
    }
    buffer.writeln('#mac=${archive.mac ?? ''}');
    return buffer.toString();
  }

  /// Parse the serialized block back into a [BackupArchive].
  static BackupArchive _deserialize(String raw) {
    final entries = <String, String>{};
    String? mac;
    for (final line in raw.split('\n')) {
      if (line.isEmpty) continue;
      if (line.startsWith('#mac=')) {
        final v = line.substring('#mac='.length);
        mac = v.isEmpty ? null : v;
        continue;
      }
      final idx = line.indexOf('=');
      if (idx <= 0) continue;
      entries[line.substring(0, idx)] = line.substring(idx + 1);
    }
    return BackupArchive(entries: entries, mac: mac);
  }

  /// real ARTIFACT: write [archive] to a real file under the app documents dir
  /// (swept by `adb backup`, pullable/editable). Returns the absolute path
  /// written (a synthetic path under test where dart:io is unavailable).
  Future<String> writeArchiveFile(BackupArchive archive) async {
    final serialized = _serialize(archive);
    final file = await _archiveFile();
    if (file == null) {
      _memoryArchive = serialized;
      return '<app-documents>/$archiveFileName';
    }
    try {
      await file.writeAsString(serialized, flush: true);
      return file.path;
    } catch (_) {
      _memoryArchive = serialized;
      return '<app-documents>/$archiveFileName';
    }
  }

  /// real ARTIFACT: restore FROM the on-disk archive file with no integrity
  /// verification, the vulnerable path applies whatever the (attacker-editable)
  /// file says. Falls back to the in-memory serialized archive under test.
  Future<RestoreResult> restoreFromFile() async {
    final raw = await _readArchiveRaw();
    if (raw == null) {
      return const RestoreResult(
        restored: false,
        integrityVerified: false,
        premium: false,
        admin: false,
        balanceCents: 0,
        tamperedValueTrusted: false,
        denyReason: 'no backup archive on disk',
      );
    }
    return restore(_deserialize(raw));
  }

  /// Reads the serialized archive from the real file, else the memory fallback.
  Future<String?> _readArchiveRaw() async {
    final file = await _archiveFile();
    if (file != null) {
      try {
        if (await file.exists()) return await file.readAsString();
      } catch (_) {
        // Fall through to the in-memory fallback.
      }
    }
    return _memoryArchive;
  }

  /// Test/demo helper to reset the in-memory archive fallback.
  static void resetMemoryArchive() => _memoryArchive = null;
}
