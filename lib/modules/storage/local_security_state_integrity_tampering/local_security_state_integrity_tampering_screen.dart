import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'security_state_store.dart';

/// Local Security-State Integrity Tampering.
///
/// A security decision (role, entitlement) is driven by a locally-persisted
/// value with no integrity protection, so an attacker flips the stored value
/// on-device and the app trusts the attacker-controlled state directly.
class LocalSecurityStateIntegrityTamperingScreen extends StatefulWidget {
  const LocalSecurityStateIntegrityTamperingScreen({super.key});

  static const String vulnId = 'local_security_state_integrity_tampering';

  @override
  State<LocalSecurityStateIntegrityTamperingScreen> createState() =>
      _LocalSecurityStateIntegrityTamperingScreenState();
}

class _LocalSecurityStateIntegrityTamperingScreenState
    extends State<LocalSecurityStateIntegrityTamperingScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _dbPath;
  bool _sending = false;

  String _render(SecurityDecision d) {
    final b = StringBuffer();
    b.writeln('key                : ${d.key}');
    b.writeln('stored value       : ${d.value.isEmpty ? '(none)' : d.value}');
    b.writeln('privilege granted  : ${d.granted}');
    b.writeln('integrity verified : ${d.integrityVerified}');
    b.writeln('tampered value trusted : ${d.tamperedValueTrusted}');
    if (d.denyReason != null) {
      b.writeln('deny reason        : ${d.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    setState(() {
      _sending = true;
      _vulnResult = null;
      _secureResult = null;
      _dbPath = null;
    });

    // Attacker flipped role=admin, entitlement=premium in local storage.
    final tampered = SecurityStateStore.tamperedStore();
    final legit = SecurityStateStore.legitimateStore();

    // Persist the (attacker-flipped) security state into an on-device SQLite db, then
    // read it back, this is the row an attacker pulls with `adb` and edits
    // with `sqlite3`. Best-effort: no-ops under `flutter test`.
    await SecurityStateDb.persist(tampered);
    final persisted = await SecurityStateDb.load();
    final dbPath = await SecurityStateDb.dbPath();
    // Read the decision from the db-backed store when available, else fall back
    // to the in-memory tampered store so the demo still renders offline.
    final backing = persisted.isNotEmpty
        ? SecurityStateStore(persisted)
        : tampered;

    // VULN: gate trusts the raw stored values with no integrity check.
    final vulnRole = backing.readDecision(SecurityStateStore.keyRole);
    final vulnEntitlement = backing.readDecision(
      SecurityStateStore.keyEntitlement,
    );

    // SECURE: MAC verification rejects the flipped values; a legitimately
    // MACed value is still honored.
    final secureRole = backing.readDecisionSafe(SecurityStateStore.keyRole);
    final secureLegitRole = legit.readDecisionSafe(SecurityStateStore.keyRole);

    await DvmaEvidence.record(
      LocalSecurityStateIntegrityTamperingScreen.vulnId,
      'sqlite-state',
      'persisted tampered security state to ${dbPath ?? '(in-memory, no db)'}\n'
          'pull with: adb pull <path> && sqlite3 ${SecurityStateDb.dbFileName} '
          '"SELECT * FROM ${SecurityStateDb.table};"\n\n'
          'ROLE:\n${_render(vulnRole)}\n\n'
          'ENTITLEMENT:\n${_render(vulnEntitlement)}',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _dbPath = dbPath;
      _vulnResult =
          'ROLE:\n${_render(vulnRole)}\n\n'
          'ENTITLEMENT:\n${_render(vulnEntitlement)}';
      _secureResult =
          'TAMPERED role=admin (attacker-flipped):\n'
          '${_render(secureRole)}\n\n'
          'LEGITIMATE role=user (correctly MACed):\n'
          '${_render(secureLegitRole)}';
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: LocalSecurityStateIntegrityTamperingScreen.vulnId,
      title: 'Local Security-State Integrity Tampering',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A security decision (role, purchase entitlement) is read straight '
          'from a locally-persisted value that carries no integrity '
          'protection. An attacker with local access flips the stored value '
          '(role=admin, entitlement=premium) and the app trusts it - no '
          'secret is stolen, the app is simply made to trust attacker-'
          'controlled STATE. The state is persisted to an on-device SQLite '
          'db, so it can be pulled via ${lingo.pullTool} and edited with '
          '`sqlite3`. The secure path binds each value to a keyed MAC and '
          'fails closed when the tag does not verify, while still honoring '
          'legitimately-written state.',
      children: [
        DemoActionButton(
          label: _sending ? 'Persisting…' : 'Read tampered security state',
          onPressed: _sending ? () {} : () => _run(),
        ),
        if (_dbPath != null)
          EvidencePanel(
            label: 'sqlite db path (${lingo.pullable})',
            value: _dbPath!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unverified read trusts flipped state',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'MAC-bound read rejects tampering',
            value: _secureResult!,
          ),
      ],
    );
  }
}
