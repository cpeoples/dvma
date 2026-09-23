import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'history_store.dart';

/// Cross-App Browser History Access.
///
/// The app reads browsing history belonging to another app / the system browser
/// (a world-readable history store) with no consent. The secure path requires
/// explicit user consent AND scoping, returning nothing without it.
class CrossAppBrowserHistoryAccessScreen extends StatefulWidget {
  const CrossAppBrowserHistoryAccessScreen({super.key});

  static const String vulnId = 'cross_app_browser_history_access';

  @override
  State<CrossAppBrowserHistoryAccessScreen> createState() =>
      _CrossAppBrowserHistoryAccessScreenState();
}

class _CrossAppBrowserHistoryAccessScreenState
    extends State<CrossAppBrowserHistoryAccessScreen> {
  String? _vuln;
  String? _secure;
  String? _fileLeak;

  Future<void> _run() async {
    final store = HistoryStore();

    // VULN: read the system browser's history directly, no consent.
    final vuln = store.read();
    final vulnBuf = StringBuffer()
      ..writeln('reader app     : ${HistoryStore.readerApp}')
      ..writeln('owning app     : ${HistoryStore.owningApp}')
      ..writeln('consent asked  : no')
      ..writeln('history leaked : ${vuln.historyLeaked}')
      ..writeln('entries        :');
    for (final e in vuln.entries) {
      vulnBuf.writeln('  $e');
    }
    vulnBuf.writeln('reason         : ${vuln.reason}');

    // SECURE: without consent nothing is returned; even with consent the API is
    // scoped and does not dump the other app's private history.
    final denied = store.readSafe(consentGranted: false);
    final consented = store.readSafe(consentGranted: true);
    final secureBuf = StringBuffer()
      ..writeln('--- no consent ---')
      ..writeln('granted        : ${denied.granted}')
      ..writeln('blocked        : ${denied.blocked}')
      ..writeln('entries        : ${denied.entries.length}')
      ..writeln('reason         : ${denied.reason}')
      ..writeln('--- consent granted (still scoped) ---')
      ..writeln('granted        : ${consented.granted}')
      ..writeln('history leaked : ${consented.historyLeaked}')
      ..writeln('entries        : ${consented.entries.length}')
      ..writeln('reason         : ${consented.reason}');

    // VULN (real I/O): stage the other app's private history to a real
    // world-readable-style file and read it back, then mirror to the evidence
    // sink so `adb pull` recovers the cross-app history artifact.
    final leak = await store.leakToWorldReadableFile();
    await DvmaEvidence.record(
      CrossAppBrowserHistoryAccessScreen.vulnId,
      'history-leak',
      'cross-app history staged to: ${leak.path}\n'
          'read back:\n${leak.contents}',
    );

    if (!mounted) return;
    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
      _fileLeak =
          'written + read back from (adb-pullable):\n${leak.path}\n\n'
          '${leak.contents.trimRight()}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CrossAppBrowserHistoryAccessScreen.vulnId,
      title: 'Cross-App Browser History Access',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app reads browsing history that belongs to ANOTHER app / the '
          'system browser (a shared or world-readable history store) with NO '
          "user consent, exposing the user's Safari / browser history across a "
          'privacy boundary (iOS CVE-2026-20656 Safari-history access class). '
          'This offline demo models the other app\'s history and a permission '
          'flag in memory. The secure path requires explicit user consent AND '
          'scoping, returning nothing without consent and never dumping the '
          "other app's private history wholesale.",
      children: [
        DemoActionButton(
          label: 'Read system browser history (no consent)',
          onPressed: () => _run(),
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'read() - cross-app history leaked',
            value: _vuln!,
          ),
        if (_fileLeak != null)
          EvidencePanel(
            label: 'history written to world-readable file (recovered)',
            value: _fileLeak!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'readSafe() - consent required + scoped',
            value: _secure!,
          ),
      ],
    );
  }
}
