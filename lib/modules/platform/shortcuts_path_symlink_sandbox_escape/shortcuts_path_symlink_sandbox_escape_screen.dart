import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'sandbox_fs.dart';

/// Shortcuts / App-Intents Path + Symlink Sandbox Escape.
///
/// Untrusted Shortcuts / App-Intents input drives a file op whose path resolves
/// through a symlink or `../` traversal with no canonicalization, so the
/// automation reaches files outside the app's sandbox. The secure path
/// canonicalizes and confines the real path to the container root.
class ShortcutsPathSymlinkSandboxEscapeScreen extends StatefulWidget {
  const ShortcutsPathSymlinkSandboxEscapeScreen({super.key});

  static const String vulnId = 'shortcuts_path_symlink_sandbox_escape';

  @override
  State<ShortcutsPathSymlinkSandboxEscapeScreen> createState() =>
      _ShortcutsPathSymlinkSandboxEscapeScreenState();
}

class _ShortcutsPathSymlinkSandboxEscapeScreenState
    extends State<ShortcutsPathSymlinkSandboxEscapeScreen> {
  String? _vuln;
  String? _secure;

  Future<void> _run() async {
    final fs = SandboxFs();
    final containerRoot = await fs.activeContainerRoot();

    // VULN: two attacker inputs, a `../` traversal and a planted symlink -
    // both escape the container because the resolver never canonicalizes.
    final trav = await fs.resolve(SandboxFs.traversalInput);
    final sym = await fs.resolve(SandboxFs.symlinkInput);
    final vulnBuf = StringBuffer()
      ..writeln('container root : $containerRoot')
      ..writeln('resolver       : resolve() - no canonicalization')
      ..writeln('--- input A (../ traversal) ---')
      ..writeln('shortcut path  : ${SandboxFs.traversalInput}')
      ..writeln('real path      : ${trav.realPath}')
      ..writeln('escaped sandbox: ${trav.escapedSandbox(containerRoot)}')
      ..writeln('contents       : ${trav.contents}')
      ..writeln('--- input B (planted symlink) ---')
      ..writeln('shortcut path  : ${SandboxFs.symlinkInput}')
      ..writeln('real path      : ${sym.realPath}')
      ..writeln('escaped sandbox: ${sym.escapedSandbox(containerRoot)}')
      ..writeln('contents       : ${sym.contents}');

    // SECURE: the same inputs hit the confining resolver and are rejected; a
    // benign in-container request still succeeds.
    final safeTrav = await fs.resolveSafe(SandboxFs.traversalInput);
    final safeSym = await fs.resolveSafe(SandboxFs.symlinkInput);
    final safeOk = await fs.resolveSafe(SandboxFs.benignInput);
    final secureBuf = StringBuffer()
      ..writeln('resolver       : resolveSafe() - canonicalize + confine')
      ..writeln('--- input A (../ traversal) ---')
      ..writeln('real path      : ${safeTrav.realPath}')
      ..writeln('blocked        : ${safeTrav.blocked}')
      ..writeln('reason         : ${safeTrav.reason}')
      ..writeln('--- input B (planted symlink) ---')
      ..writeln('real path      : ${safeSym.realPath}')
      ..writeln('blocked        : ${safeSym.blocked}')
      ..writeln('reason         : ${safeSym.reason}')
      ..writeln('--- benign in-container request ---')
      ..writeln('read           : ${safeOk.read}')
      ..writeln('contents       : ${safeOk.contents}');

    if (!mounted) return;
    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ShortcutsPathSymlinkSandboxEscapeScreen.vulnId,
      title: 'Shortcuts / App Intents Path + Symlink Sandbox Escape',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Untrusted Shortcuts / App-Intents input drives a file operation '
          'whose path is resolved through a symlink or a `../` traversal with '
          'NO canonicalization, so the automation reaches files OUTSIDE the '
          "app's sandbox / container (iOS Shortcuts CVE-2026-20677 symlink "
          'race / CVE-2026-20653 path class). On device this plants a REAL '
          'symlink inside the container pointing outside it and seeds '
          'sensitive files beyond the sandbox, then reads them off the real '
          'filesystem. The secure path canonicalizes, resolves symlinks, and '
          'asserts the real path stays under the container root before reading.',
      children: [
        DemoActionButton(
          label: 'Run Shortcut file op (untrusted path)',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'resolve() - escaped the sandbox',
            value: _vuln!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'resolveSafe() - escapes rejected',
            value: _secure!,
          ),
      ],
    );
  }
}
