/// In-memory passkey credential-management "endpoints" (register / delete) that
/// fail to re-authorize the acting user against the target account.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-639): the register/replace/delete
/// operations trust the caller-supplied target account id (an IDOR-style
/// parameter) and never check that the authenticated caller owns it. An
/// attacker can therefore enroll their own passkey onto the victim's account
/// (silent account takeover) or delete the victim's passkeys (lockout / DoS).
/// Mirrors the USENIX 2026 PASSKEYS-ATTACKER class.
///
/// The `secure*` methods enforce that the caller equals the target account.
class CredentialManagementService {
  /// accountId -> set of credential ids registered to it.
  final Map<String, Set<String>> _credentials = {
    'victim': {'victim-passkey-1'},
    'attacker': {'attacker-passkey-1'},
  };

  Set<String> credentialsOf(String accountId) =>
      _credentials[accountId] ?? <String>{};

  // ---- VULNERABLE endpoints: no ownership / re-authorization check ----------

  /// VULN: registers [credentialId] onto [targetAccount] without checking that
  /// [callerAccount] owns [targetAccount].
  bool registerCredential({
    required String callerAccount,
    required String targetAccount,
    required String credentialId,
  }) {
    _credentials.putIfAbsent(targetAccount, () => <String>{}).add(credentialId);
    return true;
  }

  /// VULN: deletes [credentialId] from [targetAccount] with no authz check.
  bool deleteCredential({
    required String callerAccount,
    required String targetAccount,
    required String credentialId,
  }) {
    return _credentials[targetAccount]?.remove(credentialId) ?? false;
  }

  // ---- SECURE endpoints: caller must own the target account -----------------

  bool secureRegisterCredential({
    required String callerAccount,
    required String targetAccount,
    required String credentialId,
  }) {
    if (callerAccount != targetAccount) return false; // authz check
    _credentials.putIfAbsent(targetAccount, () => <String>{}).add(credentialId);
    return true;
  }

  bool secureDeleteCredential({
    required String callerAccount,
    required String targetAccount,
    required String credentialId,
  }) {
    if (callerAccount != targetAccount) return false; // authz check
    return _credentials[targetAccount]?.remove(credentialId) ?? false;
  }
}
