import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'credential_management_service.dart';

/// Passkey Registration/Deletion Authorization Missing.
///
/// Register/replace/delete endpoints don't re-authorize the acting user, so an
/// attacker adds their own passkey or deletes the victim's (account takeover /
/// lockout) - USENIX 2026 PASSKEYS-ATTACKER class.
class PasskeyCredentialManagementAuthzScreen extends StatefulWidget {
  const PasskeyCredentialManagementAuthzScreen({super.key});

  static const String vulnId = 'passkey_credential_management_authz';

  @override
  State<PasskeyCredentialManagementAuthzScreen> createState() =>
      _PasskeyCredentialManagementAuthzScreenState();
}

class _PasskeyCredentialManagementAuthzScreenState
    extends State<PasskeyCredentialManagementAuthzScreen> {
  static const String _caller = 'attacker';
  static const String _victim = 'victim';

  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _runAttack() async {
    // Vulnerable service: attacker enrolls their own passkey onto the victim
    // and deletes the victim's existing passkey.
    final vuln = CredentialManagementService();
    final beforeVuln = vuln.credentialsOf(_victim).toList();
    vuln.registerCredential(
      callerAccount: _caller,
      targetAccount: _victim,
      credentialId: 'attacker-implanted',
    );
    vuln.deleteCredential(
      callerAccount: _caller,
      targetAccount: _victim,
      credentialId: 'victim-passkey-1',
    );
    final afterVuln = vuln.credentialsOf(_victim).toList();

    // VULN: persist the tampered victim credential set (attacker passkey
    // implanted, victim passkey deleted) to real SharedPreferences. The
    // recoverable artifact shows cross-account credential mutation.
    final prefsKey = await PasskeyEvidenceStore.persist(
      vulnId: PasskeyCredentialManagementAuthzScreen.vulnId,
      kind: 'cred-mgmt',
      keySuffix: 'victim_credentials',
      value:
          'caller=$_caller target=$_victim '
          'implanted=attacker-implanted deleted=victim-passkey-1 '
          'now=$afterVuln',
    );
    if (!mounted) return;

    // Secure service: same calls are refused by the ownership check.
    final secure = CredentialManagementService();
    final okReg = secure.secureRegisterCredential(
      callerAccount: _caller,
      targetAccount: _victim,
      credentialId: 'attacker-implanted',
    );
    final okDel = secure.secureDeleteCredential(
      callerAccount: _caller,
      targetAccount: _victim,
      credentialId: 'victim-passkey-1',
    );
    final afterSecure = secure.credentialsOf(_victim).toList();

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'caller=$_caller target=$_victim\n'
          'before=$beforeVuln\n'
          'after=$afterVuln (attacker passkey implanted, victim key deleted)\n'
          'persisted to prefs key: $prefsKey';
      _secureResult =
          'register=${okReg ? "allowed" : "DENIED"} '
          'delete=${okDel ? "allowed" : "DENIED"}\n'
          'victim credentials unchanged=$afterSecure';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyCredentialManagementAuthzScreen.vulnId,
      title: 'Passkey Credential Mgmt Authz',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The passkey register/delete endpoints trust the caller-supplied '
          'target account and never re-authorize the acting user. An attacker '
          'enrolls their own passkey onto the victim (takeover) and deletes the '
          'victim\'s passkey (lockout). A correct endpoint checks that the '
          'caller owns the target account.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        DemoActionButton(
          label: 'Attacker: implant + delete on victim',
          onPressed: _runAttack,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable endpoints (no authz)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the tampered victim credential set (attacker key '
                'implanted)',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure endpoints (owner check)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
