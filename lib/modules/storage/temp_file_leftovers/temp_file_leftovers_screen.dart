import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'temp_file_leaker.dart';

/// Temp / Cache File Leftovers.
///
/// Decrypted/sensitive content written to temp/cache dirs and never cleaned up.
class TempFileLeftoversScreen extends StatefulWidget {
  const TempFileLeftoversScreen({super.key});

  static const String vulnId = 'temp_file_leftovers';

  @override
  State<TempFileLeftoversScreen> createState() =>
      _TempFileLeftoversScreenState();
}

class _TempFileLeftoversScreenState extends State<TempFileLeftoversScreen> {
  final _leaker = TempFileLeaker();
  String? _path;
  String? _contents;
  bool _sending = false;

  Future<void> _export() async {
    setState(() {
      _sending = true;
      _path = null;
      _contents = null;
    });

    // VULN: an "export/decrypt" flow writes the decrypted, sensitive content
    // (session token + PII) as cleartext to a predictable temp/cache file and
    // never deletes it. The leftover survives on-device and is recoverable via
    // adb / a file browser / forensic tooling.
    const sensitive =
        'DECRYPTED EXPORT\n'
        'session_token=DVMA{temp_leftover}.eyJhbGciOiJIUzI1NiJ9.session\n'
        'ssn=123-45-6789\n'
        'email=victim@example.com';
    final file = await _leaker.writeDecryptedToTemp(sensitive);
    final read = await _leaker.readLeftover();

    await DvmaEvidence.record(
      TempFileLeftoversScreen.vulnId,
      'temp-file',
      'left decrypted temp file at ${file.path}\n\n${read ?? '(unreadable)'}',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _path = file.path;
      _contents = read;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: TempFileLeftoversScreen.vulnId,
      title: 'Temp / Cache File Leftovers',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An "export/decrypt" flow writes the decrypted, sensitive content to '
          'a predictable temp file in cleartext and never deletes it. This '
          'writes a file into the app temp/cache dir on-device - the '
          'leftover survives after use and is recoverable via ${lingo.pullTool} '
          '/ a file browser / forensic tooling.',
      children: [
        DemoActionButton(
          label: _sending
              ? 'Exporting…'
              : 'Export (writes decrypted temp file)',
          onPressed: _sending ? () {} : () => _export(),
        ),
        if (_path != null)
          EvidencePanel(label: 'leftover temp path', value: _path!),
        if (_contents != null)
          EvidencePanel(
            label: 'leftover contents (cleartext)',
            value: _contents!,
          ),
      ],
    );
  }
}
