import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'resource_authorizer.dart';

/// Protected-Data Access via Input-Validation Confusion.
///
/// Untrusted input flows through a normalizer whose result authorizes access,
/// so an encoded/`..`/case variant of a protected id slips past a naive deny
/// rule (Apple protected-data-via-input-sanitization CVE-2026-43714 class).
class ProtectedDataAccessViaInputValidationScreen extends StatefulWidget {
  const ProtectedDataAccessViaInputValidationScreen({super.key});

  static const String vulnId = 'protected_data_access_via_input_validation';

  @override
  State<ProtectedDataAccessViaInputValidationScreen> createState() =>
      _ProtectedDataAccessViaInputValidationScreenState();
}

class _ProtectedDataAccessViaInputValidationScreenState
    extends State<ProtectedDataAccessViaInputValidationScreen> {
  String? _vulnResult;
  String? _secureResult;
  bool _running = false;

  String _render(AuthzResult r) {
    final b = StringBuffer();
    b.writeln('raw input        : ${r.rawInput}');
    b.writeln('canonical        : ${r.canonical}');
    b.writeln('granted          : ${r.granted}');
    b.writeln('protected leaked : ${r.protectedLeaked}');
    b.writeln('data             : ${r.data ?? '<refused>'}');
    if (r.denyReason != null) {
      b.writeln('reason           : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    setState(() => _running = true);
    const input = ResourceAuthorizer.evasiveInput;
    final lingo = PlatformLingo.current();

    AuthzResult vuln;
    AuthzResult secure;
    try {
      // real: write the protected + public records to an on-disk store, then
      // let the check-then-canonicalize bug read the PROTECTED one back off
      // disk via the encoded/traversal variant.
      await ResourceAuthorizer.seedStore();
      vuln = await ResourceAuthorizer.authorizeFromStore(input);
      secure = await ResourceAuthorizer.authorizeSafeFromStore(input);

      if (vuln.protectedLeaked && vuln.data != null) {
        await DvmaEvidence.record(
          ProtectedDataAccessViaInputValidationScreen.vulnId,
          'authz-bypass',
          'evasive input   : ${vuln.rawInput}\n'
              'canonicalized to: ${vuln.canonical} (protected)\n'
              'leaked record   : ${vuln.data}\n'
              'read from on-disk store key: '
              'resource:${vuln.canonical}\n'
              'backing file ${lingo.backingReadableParenthetical}: '
              '${lingo.keyValueBackingPath}',
        );
      }
    } catch (e) {
      // In-memory fallback so the demo/tests still work without the prefs
      // plugin (e.g. bare unit-test host).
      vuln = ResourceAuthorizer.seeded().authorize(input);
      secure = ResourceAuthorizer.seeded().authorizeSafe(input);
    }

    if (!mounted) return;
    setState(() {
      _running = false;
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: ProtectedDataAccessViaInputValidationScreen.vulnId,
      title: 'Protected-Data Access via Input-Validation Confusion',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Untrusted input flows through a security-sensitive normalizer whose '
          'result authorizes access to a protected resource. The vulnerable '
          'path runs a naive deny check on the RAW input and only then '
          'canonicalizes for lookup, so an encoded / `..` / mixed-case variant '
          'of a protected identifier slips past the deny rule yet canonicalizes '
          'back to the protected id and returns its data. The flaw is the '
          'authorization decision on insufficiently-validated input, not the '
          'parser itself (Apple CVE-2026-43714 class). The protected records '
          'are written to a REAL on-disk store (${lingo.keyValueStore}); the '
          'vulnerable path then reads the protected record back via the '
          'encoded/traversal variant. The secure path canonicalizes FIRST with '
          'a strict canonicalizer and checks the canonical form before any '
          'read.',
      children: [
        DemoActionButton(
          label: _running
              ? 'Requesting…'
              : 'Request protected id via encoded/traversal variant',
          onPressed: _running ? () {} : () => _run(),
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'check-before-canonicalize (protected data leaked)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'canonicalize-then-check (refused)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
