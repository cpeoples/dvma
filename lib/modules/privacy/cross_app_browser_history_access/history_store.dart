/// Cross-app browser-history access helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-359 / CWE-732): the app reads
/// browsing history that belongs to ANOTHER app / the system browser (a shared
/// or world-readable history store) with no user consent, exposing the user's
/// Safari / browser history across a privacy boundary (iOS CVE-2026-20656
/// Safari-history access class).
///
/// This is an offline, deterministic model: [HistoryStore] models the other app's
/// history entries and a permission flag in pure Dart. The vuln [read] returns
/// the other app's entries directly (world-readable / no consent). The secure
/// [readSafe] requires explicit user consent AND scoping, returning nothing
/// without it.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// A single browser-history entry.
class HistoryEntry {
  const HistoryEntry({
    required this.url,
    required this.title,
    required this.visitedAt,
  });

  final String url;
  final String title;
  final String visitedAt;

  @override
  String toString() => '$visitedAt  $title  <$url>';
}

/// The outcome of a history read.
class HistoryReadResult {
  const HistoryReadResult({
    required this.granted,
    required this.blocked,
    required this.entries,
    this.reason,
  });

  /// Whether history entries were returned.
  final bool granted;

  /// Whether the secure reader refused (no consent).
  final bool blocked;

  /// The entries returned (the other app's history on the vuln path).
  final List<HistoryEntry> entries;

  /// Why access was granted / refused.
  final String? reason;

  /// True when another app's private history was disclosed - the leak.
  bool get historyLeaked => granted && entries.isNotEmpty;
}

class HistoryStore {
  HistoryStore();

  /// The app that actually owns this history (the system browser).
  static const String owningApp = 'com.apple.mobilesafari';

  /// This app's own bundle id (the one doing the reading).
  static const String readerApp = 'com.dvma.app';

  /// The other app's private browsing history.
  static const List<HistoryEntry> _otherAppHistory = [
    HistoryEntry(
      url: 'https://clinic.example/appointments',
      title: 'Oncology appointment booking',
      visitedAt: '2026-09-01 09:12',
    ),
    HistoryEntry(
      url: 'https://bank.example/transfers',
      title: 'Wire transfer - Bank',
      visitedAt: '2026-09-03 14:47',
    ),
    HistoryEntry(
      url: 'https://dating.example/matches',
      title: 'Your matches',
      visitedAt: '2026-09-05 22:31',
    ),
  ];

  /// VULN: the history store is world-readable, so this app reads the OTHER
  /// app's history directly with no consent and no scoping.
  HistoryReadResult read() {
    return HistoryReadResult(
      granted: true,
      blocked: false,
      entries: List.unmodifiable(_otherAppHistory),
      reason: 'read $owningApp history directly (world-readable, no consent)',
    );
  }

  /// The world-readable-style file the other app's history is staged to. On
  /// Android this lands in the external files dir (`adb pull`-able without
  /// root); on other hosts it falls back to the app documents dir.
  static const String historyFileName = 'other_app_browser_history.txt';

  /// VULN (real I/O): materialize the OTHER app's private history to a real
  /// world-readable-style file on disk, then read it back, proving the
  /// cross-app history is recoverable off the device. Returns the file path and
  /// the contents read back. Never throws (test-safe).
  Future<({String path, String contents})> leakToWorldReadableFile() async {
    final dump = _otherAppHistory.map((e) => e.toString()).join('\n');
    final baseDir = await DvmaEvidence.writableBaseDir();
    if (baseDir == null) {
      return (path: '(no external dir on this host)', contents: dump);
    }
    try {
      final file = File('${baseDir.path}/$historyFileName');
      await file.parent.create(recursive: true);
      // World-readable-style staging of another app's private history.
      await file.writeAsString(
        '$owningApp history (no consent)\n$dump\n',
        flush: true,
      );
      // Read it back as another app / adb would, proving recoverability.
      final readBack = await file.readAsString();
      return (path: file.path, contents: readBack);
    } catch (_) {
      return (path: '(write failed on this host)', contents: dump);
    }
  }

  /// SECURE contrast: reading another app's history requires EXPLICIT user
  /// consent. Without it, nothing is returned. Even with consent the result is
  /// scoped (here: only the current app's own domain would be shareable) - so a
  /// blanket dump of the other app's private history never happens.
  HistoryReadResult readSafe({required bool consentGranted}) {
    if (!consentGranted) {
      return const HistoryReadResult(
        granted: false,
        blocked: true,
        entries: [],
        reason: 'no user consent to access another app\'s history',
      );
    }
    // Consent granted, but the API is scoped: another app's private history is
    // never handed over wholesale.
    return const HistoryReadResult(
      granted: true,
      blocked: false,
      entries: [],
      reason: 'consent granted but scoped: cross-app history not exposed',
    );
  }
}
