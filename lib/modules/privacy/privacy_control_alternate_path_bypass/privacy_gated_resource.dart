/// Privacy Control Alternate-Path Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-284 / CWE-200 / CWE-668): app functionality
/// reaches protected data through an ALTERNATE path that sidesteps the platform
/// privacy control - a different API, a shared container / app group, an
/// extension, or a cached copy - instead of the gated, consent-checked path.
/// The user's privacy preference is bypassed rather than merely over-requested
/// (the iOS CVE-2026-20606 privacy-preference bypass class).
///
/// This is an offline + deterministic simulation. A [PrivacyGatedResource]
/// (here: contacts) holds a `consentGranted` flag AND a secondary app-group
/// cache holding the SAME data. The vulnerable path reads from the alternate
/// cache/app-group WITHOUT checking consent; the secure path funnels ALL reads
/// through the single consent-checked accessor so the alternate path is closed.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// A protected contact record.
class ContactRecord {
  const ContactRecord({required this.name, required this.phone});

  final String name;
  final String phone;

  @override
  String toString() => '$name <$phone>';
}

/// The outcome of a protected-data read.
class PrivacyReadResult {
  const PrivacyReadResult({
    required this.granted,
    required this.blocked,
    required this.source,
    required this.records,
    required this.consentChecked,
    this.reason,
  });

  /// Whether records were returned.
  final bool granted;

  /// Whether the secure accessor refused (secure path).
  final bool blocked;

  /// Where the data came from (gated API vs alternate cache/app-group).
  final String source;

  /// The records returned (the leaked contacts on the vuln path).
  final List<ContactRecord> records;

  /// Whether the platform consent control was actually consulted for this read.
  final bool consentChecked;

  /// Why access was granted / refused.
  final String? reason;

  /// True when protected data was returned WITHOUT the consent gate being
  /// consulted - the alternate-path bypass hit.
  bool get bypassedConsent => granted && !consentChecked;
}

class PrivacyGatedResource {
  PrivacyGatedResource({required this.consentGranted});

  /// Whether the user granted the platform contacts-privacy consent.
  final bool consentGranted;

  /// The protected contacts behind the platform privacy control.
  static const List<ContactRecord> _contacts = [
    ContactRecord(name: 'Dr. Reyes (Oncology)', phone: '+1-555-0142'),
    ContactRecord(name: 'Divorce Attorney', phone: '+1-555-0197'),
    ContactRecord(name: 'Sponsor - AA', phone: '+1-555-0110'),
  ];

  /// A secondary app-group / cache container holding the SAME data, populated
  /// by an earlier gated read and not itself consent-checked.
  static const List<ContactRecord> _appGroupCache = _contacts;

  /// The gated-API source label.
  static const String gatedSource = 'ContactsAPI (consent-gated)';

  /// The alternate app-group cache source label.
  static const String alternateSource =
      'app-group cache (group.com.dvma.shared)';

  List<ContactRecord> get contacts => List.unmodifiable(_contacts);

  /// VULN: read the contacts from the ALTERNATE app-group cache. This path
  /// never consults the platform consent control, the same data the gated API
  /// would refuse is handed over regardless of the user's preference.
  PrivacyReadResult readViaAlternatePath() {
    return PrivacyReadResult(
      granted: true,
      blocked: false,
      source: alternateSource,
      records: List.unmodifiable(_appGroupCache),
      consentChecked: false,
      reason: 'read from app-group cache, bypassing the consent gate',
    );
  }

  /// VULN (real I/O): persist the contacts read via the alternate (consent-
  /// bypassing) path to a real file on disk so the bypassed-consent read leaves
  /// a durable, adb-pullable artifact. Returns the file path. Never throws.
  static const String leakFileName = 'contacts_appgroup_bypass.txt';

  Future<String> persistAlternatePathLeak() async {
    final dump = _appGroupCache.map((c) => c.toString()).join('\n');
    final baseDir = await DvmaEvidence.writableBaseDir();
    if (baseDir == null) return '(no external dir on this host)';
    try {
      final file = File('${baseDir.path}/$leakFileName');
      await file.parent.create(recursive: true);
      await file.writeAsString(
        'contacts read via $alternateSource (consent NOT checked)\n$dump\n',
        flush: true,
      );
      return file.path;
    } catch (_) {
      return '(write failed on this host)';
    }
  }

  /// SECURE contrast: the single consent-checked accessor every path must use.
  /// The alternate cache is not read directly; all access funnels through here,
  /// so without consent nothing is returned and the alternate path is closed.
  PrivacyReadResult readGated() {
    if (!consentGranted) {
      return const PrivacyReadResult(
        granted: false,
        blocked: true,
        source: gatedSource,
        records: [],
        consentChecked: true,
        reason: 'contacts consent not granted - refused (no alternate path)',
      );
    }
    return PrivacyReadResult(
      granted: true,
      blocked: false,
      source: gatedSource,
      records: List.unmodifiable(_contacts),
      consentChecked: true,
      reason: 'consent granted - served via the single gated accessor',
    );
  }
}
