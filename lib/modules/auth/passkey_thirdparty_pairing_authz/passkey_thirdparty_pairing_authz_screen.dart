import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'pairing_broker.dart';

/// Third-Party Authenticator / Cross-Device Pairing Authorization Missing.
///
/// Third-party authenticator / cross-device passkey-entry pairing is approved
/// without a permission/authorization check, so an unauthorized app or device
/// is paired for passkey entry (Android CVE-2025-48640 / BLE CVE-2026-65935).
class PasskeyThirdpartyPairingAuthzScreen extends StatefulWidget {
  const PasskeyThirdpartyPairingAuthzScreen({super.key});

  static const String vulnId = 'passkey_thirdparty_pairing_authz';

  @override
  State<PasskeyThirdpartyPairingAuthzScreen> createState() =>
      _PasskeyThirdpartyPairingAuthzScreenState();
}

class _PasskeyThirdpartyPairingAuthzScreenState
    extends State<PasskeyThirdpartyPairingAuthzScreen> {
  // Default attack: an untrusted app, no permission, no consent.
  final _requesterId = TextEditingController(
    text: 'com.evil.rogue.authenticator',
  );
  bool _hasPermission = false;
  bool _userConsented = false;
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    final vuln = PairingBroker.approve(
      requesterId: _requesterId.text,
      userConsented: _userConsented,
      hasPairingPermission: _hasPermission,
    );
    final secure = PairingBroker.secureApprove(
      requesterId: _requesterId.text,
      userConsented: _userConsented,
      hasPairingPermission: _hasPermission,
    );

    String? prefsKey;
    // VULN: persist the auto-approved pairing to real SharedPreferences. The
    // recoverable artifact is a stored trust record for a rogue requester that
    // was never allow-listed, permissioned, or consented to.
    if (vuln.paired) {
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyThirdpartyPairingAuthzScreen.vulnId,
        kind: 'pairing',
        keySuffix: 'paired_requester',
        value:
            'requester=${_requesterId.text} paired=true '
            'permission=$_hasPermission consent=$_userConsented '
            'reason=${vuln.reason}',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'requester=${_requesterId.text}\n'
          'paired=${vuln.paired ? "YES" : "no"} (${vuln.reason})';
      _secureResult =
          'paired=${secure.paired ? "yes" : "no"} (${secure.reason})';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyThirdpartyPairingAuthzScreen.vulnId,
      title: 'Third-Party Pairing Authz',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The pairing broker auto-approves any third-party authenticator or '
          'cross-device requester with no allow-list, permission, or consent '
          'check, so a rogue app/device is paired for passkey entry. A correct '
          'broker requires an allow-listed requester, the pairing permission, '
          'and explicit user consent.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        TextField(
          controller: _requesterId,
          decoration: const InputDecoration(labelText: 'Requester id'),
        ),
        SwitchListTile(
          value: _hasPermission,
          onChanged: (v) => setState(() => _hasPermission = v),
          title: const Text('Has pairing permission'),
          contentPadding: EdgeInsets.zero,
        ),
        SwitchListTile(
          value: _userConsented,
          onChanged: (v) => setState(() => _userConsented = v),
          title: const Text('User consented'),
          contentPadding: EdgeInsets.zero,
        ),
        DemoActionButton(label: 'Request pairing', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable broker (no check)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the auto-approved pairing trust record for the rogue '
                'requester',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure broker (allow-list + consent)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
