import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/keychain_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'keychain_store.dart';

/// Keychain State Integrity Manipulation.
///
/// The app TRUSTS a Keychain/Keystore item as authoritative and acts on it
/// with no integrity check, so a LOCAL attacker who MODIFIES the stored blob
/// escalates privilege (iOS Keychain state-modification CVE-2026-28860 class).
class KeychainStateIntegrityManipulationScreen extends StatefulWidget {
  const KeychainStateIntegrityManipulationScreen({super.key});

  static const String vulnId = 'keychain_state_integrity_manipulation';

  @override
  State<KeychainStateIntegrityManipulationScreen> createState() =>
      _KeychainStateIntegrityManipulationScreenState();
}

class _KeychainStateIntegrityManipulationScreenState
    extends State<KeychainStateIntegrityManipulationScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(TrustDecision d) {
    final b = StringBuffer();
    b.writeln('key                : ${d.key}');
    b.writeln('stored value       : ${d.storedValue}');
    b.writeln('integrity verified : ${d.integrityVerified}');
    b.writeln('privilege granted  : ${d.privilegeGranted}');
    b.writeln('acted on tampered  : ${d.tampered}');
    if (d.reason != null) {
      b.writeln('reason             : ${d.reason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // A local attacker rewrites the stored entitlement to admin WITHOUT the
    // app's MAC key (the tag is left stale).
    final store = KeychainStore.seeded()
      ..attackerModify(KeychainStore.entitlementKey, KeychainStore.forgedValue);
    // VULN: the app trusts the tampered blob and grants admin.
    final vuln = store.readTrusted(KeychainStore.entitlementKey);
    // SECURE: the MAC no longer matches -> the forged item is rejected.
    final secure = store.readVerified(KeychainStore.entitlementKey);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real ARTIFACT: persist the tampered item (value + stale mac) via the
    // local key-value store (NSUserDefaults on iOS) so a local attacker's edit
    // lives on disk; mirror it.
    _persistAndRecord(store);
  }

  Future<void> _persistAndRecord(KeychainStore store) async {
    final storedLines = await store.persist(KeychainStore.entitlementKey);
    // On iOS, drive a real Keychain state change: store the entitlement + a
    // real HMAC-SHA256 tag, rewrite only the value via SecItemUpdate (the
    // local-attacker edit), and contrast the trusting vs. verifying read.
    final native = await KeychainBridge.stateIntegrityTamper();
    if (native != null && native.isNotEmpty && mounted) {
      setState(() => _nativeResult = native);
    }
    // On iOS the stored item lands in a Keychain/NSUserDefaults item,
    // modifiable via a device backup edit or on a jailbroken device.
    const backingFile = 'Keychain item / Library/Preferences/<bundle-id>.plist';
    final artifact =
        '$storedLines'
        '\n\nnote: value trusted with NO MAC verification; the mac above is a '
        'stale tag over the ORIGINAL value, so a local attacker can edit the '
        'value on disk and be silently escalated.'
        '\n\nbacking store (editable via an unencrypted backup, or over SSH/SCP '
        '/ Filza on a jailbroken device): $backingFile';
    DvmaEvidence.record(
      KeychainStateIntegrityManipulationScreen.vulnId,
      'keychain-integrity',
      native != null && native.isNotEmpty
          ? '$artifact\n\nreal iOS Keychain (SecItemUpdate) result:\n$native'
          : artifact,
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: KeychainStateIntegrityManipulationScreen.vulnId,
      title: 'Keychain State Integrity Manipulation',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app treats a Keychain/Keystore item as an AUTHORITATIVE source '
          'of truth and acts on it - granting an admin privilege - with no '
          'integrity check. A local attacker who can MODIFY the stored item '
          '(not merely read it) rewrites the entitlement blob to '
          '"role=admin" and is silently escalated. This is an integrity/'
          'state-manipulation failure distinct from secret confidentiality '
          '(iOS Keychain state-modification CVE-2026-28860 class). On device '
          'the trusted entitlement blob and its (weak) integrity tag are '
          'persisted to a Keychain/NSUserDefaults item, so a local attacker can '
          'edit the value via a device backup or a jailbroken device. The '
          'secure path recomputes and verifies the MAC over the stored value '
          'and rejects the tampered item.',
      children: [
        DemoActionButton(
          label: 'Tamper stored entitlement, then read',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trusted with no integrity check (privilege escalated)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'MAC verified (tampered item rejected)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real iOS Keychain tamper via SecItemUpdate + HMAC verify',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
