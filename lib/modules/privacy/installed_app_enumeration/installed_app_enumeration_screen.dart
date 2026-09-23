import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'device_probe.dart';

/// Installed-App Enumeration (Privacy Fingerprint).
///
/// The app probes which other apps are installed with no functional need,
/// building a device fingerprint. The secure path only checks the single scheme
/// it legitimately needs, with a declared purpose.
class InstalledAppEnumerationScreen extends StatefulWidget {
  const InstalledAppEnumerationScreen({super.key});

  static const String vulnId = 'installed_app_enumeration';

  @override
  State<InstalledAppEnumerationScreen> createState() =>
      _InstalledAppEnumerationScreenState();
}

class _InstalledAppEnumerationScreenState
    extends State<InstalledAppEnumerationScreen> {
  String? _vuln;
  String? _secure;
  String? _persisted;

  Future<void> _run() async {
    final probe = DeviceProbe();

    // VULN: probe the whole candidate list and return everything detected.
    final vuln = probe.enumerate(DeviceProbe.candidates);
    final vulnBuf = StringBuffer()
      ..writeln('probe          : canOpenURL over ${vuln.probedCount} schemes')
      ..writeln('detected apps  :');
    for (final app in vuln.detected) {
      vulnBuf.writeln('  - ${app.label} (${app.scheme}) [${app.category}]');
    }
    vulnBuf
      ..writeln('fingerprint    : ${vuln.fingerprint}')
      ..writeln('is fingerprint : ${vuln.isFingerprint}')
      ..writeln('reason         : ${vuln.reason}');

    // SECURE: only the one declared scheme is checked.
    final secure = probe.enumerateSafe();
    final secureBuf = StringBuffer()
      ..writeln('probe          : canOpenURL over ${secure.probedCount} scheme')
      ..writeln('detected apps  :');
    if (secure.detected.isEmpty) {
      secureBuf.writeln('  (none disclosed)');
    }
    for (final app in secure.detected) {
      secureBuf.writeln('  - ${app.label} (${app.scheme}) [${app.category}]');
    }
    secureBuf
      ..writeln('fingerprint    : ${secure.fingerprint}')
      ..writeln('is fingerprint : ${secure.isFingerprint}')
      ..writeln('reason         : ${secure.reason}');

    // VULN: the enumerated fingerprint is a durable privacy artifact, persist
    // it to the real SharedPreferences XML on disk (adb/root-readable) so the
    // cross-app fingerprint survives beyond the in-memory probe.
    final fingerprint = vuln.fingerprint;
    final detectedLine = vuln.detected
        .map((c) => '${c.label}(${c.scheme})[${c.category}]')
        .join(', ');
    var persistedPath = '(prefs unavailable on this host)';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('device_app_fingerprint', fingerprint);
      await prefs.setString('device_app_fingerprint_detail', detectedLine);
      persistedPath =
          '${PlatformLingo.current().keyValueBackingFile} '
          'key=device_app_fingerprint';
    } on MissingPluginException {
      // Test-safe: logcat mirror below still proves the effect.
    }

    // Mirror the built fingerprint to the pullable evidence sink (logcat + file)
    // so the harness/adb can recover the exact cross-app fingerprint artifact.
    await DvmaEvidence.record(
      InstalledAppEnumerationScreen.vulnId,
      'app-enum',
      'device app fingerprint = $fingerprint\n'
          'detected: $detectedLine\n'
          'persisted: $persistedPath',
    );

    if (!mounted) return;
    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
      _persisted =
          'fingerprint persisted to prefs:\n$fingerprint\n\nbacking file '
          '${PlatformLingo.current().backingReadableParenthetical}: '
          '$persistedPath';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InstalledAppEnumerationScreen.vulnId,
      title: 'Installed-App Enumeration (Privacy Fingerprint)',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app probes which OTHER apps are installed - iOS canOpenURL over '
          'a scheme list, Android queryIntentActivities / getInstalledPackages '
          '- with NO functional need. The detected set is a stable device '
          'fingerprint that reveals sensitive traits (dating, health, finance, '
          'secure-messaging apps) across a privacy boundary (iOS CVE-2026-20641 '
          'installed-apps disclosure class). This offline demo holds an '
          'installed-app set and a probe list in memory. The secure path only '
          'checks the single scheme the app legitimately needs, with a declared '
          'purpose, so no broad fingerprint is built.',
      children: [
        DemoActionButton(
          label: 'Enumerate installed apps (fingerprint)',
          onPressed: () => _run(),
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'enumerate() - full device fingerprint',
            value: _vuln!,
          ),
        if (_persisted != null)
          EvidencePanel(
            label: 'fingerprint persisted (recoverable artifact)',
            value: _persisted!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'enumerateSafe() - single declared check',
            value: _secure!,
          ),
      ],
    );
  }
}
