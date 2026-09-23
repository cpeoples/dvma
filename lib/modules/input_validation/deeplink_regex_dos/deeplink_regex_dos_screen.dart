import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'redos_link_parser.dart';

/// Deep Link Regex DoS (ReDoS).
///
/// A catastrophically-backtracking regex parses incoming deep-link URLs, so a
/// crafted link freezes/hangs the app (Mattermost CVE-2024-3872 class).
class DeeplinkRegexDosScreen extends StatefulWidget {
  const DeeplinkRegexDosScreen({super.key});

  static const String vulnId = 'deeplink_regex_dos';

  @override
  State<DeeplinkRegexDosScreen> createState() => _DeeplinkRegexDosScreenState();
}

class _DeeplinkRegexDosScreenState extends State<DeeplinkRegexDosScreen> {
  // A crafted link: 40 'a's then a non-matching char, which drives ^(a+)+$
  // into ~2^39 backtracking steps.
  final TextEditingController _controller = TextEditingController(
    text: 'dvma://open/${'a' * 40}!',
  );

  String? _vulnResult;
  String? _secureResult;
  bool _running = false;

  Future<void> _parse() async {
    final link = _controller.text.trim();
    setState(() => _running = true);

    // real: actually execute the catastrophic-backtracking regex and measure
    // wall-clock time (bounded so it returns within a few seconds). Yield to
    // the event loop first so the "Running…" label paints before the isolate
    // is pinned by the regex engine.
    await Future<void>.delayed(Duration.zero);
    final vuln = RedosLinkParser.parseReal(link);
    final secure = RedosLinkParser.parseSafeReal(link);

    // The real effect is the measured CPU time burned in the regex engine on
    // the UI isolate. Mirror the input length + measured milliseconds so the
    // harness can observe the DoS quantitatively.
    await DvmaEvidence.record(
      DeeplinkRegexDosScreen.vulnId,
      'redos',
      'pattern: ^(a+)+\$\n'
          'input length: ${vuln.inputLength} chars\n'
          'VULN elapsed: ${vuln.elapsedMs.toStringAsFixed(1)} ms '
          '(real backtracking)\n'
          'SAFE elapsed: ${secure.elapsedMs.toStringAsFixed(3)} ms (linear)\n'
          'slowdown: ~${(secure.elapsedMs <= 0 ? 0 : vuln.elapsedMs / secure.elapsedMs).toStringAsFixed(0)}x',
    );

    if (!mounted) return;
    setState(() {
      _running = false;
      _vulnResult =
          'input length: ${vuln.inputLength} chars\n'
          'matched: ${vuln.matched}\n'
          'measured time: ${vuln.elapsedMs.toStringAsFixed(1)} ms\n'
          '${vuln.reason}';
      _secureResult =
          'input length: ${secure.inputLength} chars\n'
          'matched: ${secure.matched}\n'
          'measured time: ${secure.elapsedMs.toStringAsFixed(3)} ms\n'
          '${secure.reason}';
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeeplinkRegexDosScreen.vulnId,
      title: 'Deep Link Regex DoS (ReDoS)',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A catastrophically-backtracking regex (a nested-quantifier pattern '
          'like ^(a+)+\$) parses incoming deep-link URLs. A crafted link - a '
          'long run of a repeated character followed by one non-matching char - '
          'forces the engine into exponential backtracking (~2^(n-1) steps), '
          'freezing the app on the main isolate (the Mattermost CVE-2024-3872 '
          'class). This demo ACTUALLY executes ^(a+)+\$ against the crafted '
          'input and measures real wall-clock time with a Stopwatch; the '
          'ambiguous run is clamped to ~26 chars so the blow-up is observable '
          '(hundreds of ms to a few seconds) but bounded so it returns. The '
          'secure parser uses a linear, anchored, non-backtracking pattern '
          'whose cost grows linearly with input length.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'incoming deep link',
              hintText: 'dvma://open/aaaaaaaa...!',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        DemoActionButton(
          label: _running ? 'Running regex…' : 'Parse deep link',
          onPressed: _running ? () {} : () => _parse(),
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'backtracking parser (real measured time)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'linear parser (real measured time)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
