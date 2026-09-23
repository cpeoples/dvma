/// Cross-device / third-party authenticator pairing "broker" that approves a
/// pairing request with no permission or authorization check.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-306): when a third-party app or a
/// cross-device (caBLE/hybrid) authenticator asks to pair for passkey entry,
/// the broker auto-approves it without checking that the requester is on an
/// allow-list, holds the required platform permission, or that the user
/// consented. Any app/device can therefore be paired to intercept or drive
/// passkey entry. Mirrors Android CVE-2025-48640 / BLE passkey-entry
/// CVE-2026-65935.
///
/// The `secure*` method enforces an allow-list + explicit user consent.
class PairingBroker {
  PairingBroker._();

  /// Requesters the platform actually trusts for passkey pairing.
  static const Set<String> allowedRequesters = {
    'com.dvma.trusted.authenticator',
  };

  /// VULN: approve any requester unconditionally.
  static PairingResult approve({
    required String requesterId,
    required bool userConsented,
    required bool hasPairingPermission,
  }) {
    // Bug: no allow-list, permission, or consent check.
    return PairingResult(paired: true, reason: 'auto-approved');
  }

  /// SECURE: require allow-listed requester, granted permission, and consent.
  static PairingResult secureApprove({
    required String requesterId,
    required bool userConsented,
    required bool hasPairingPermission,
  }) {
    if (!allowedRequesters.contains(requesterId)) {
      return PairingResult(paired: false, reason: 'requester-not-allowlisted');
    }
    if (!hasPairingPermission) {
      return PairingResult(paired: false, reason: 'missing-permission');
    }
    if (!userConsented) {
      return PairingResult(paired: false, reason: 'no-user-consent');
    }
    return PairingResult(paired: true, reason: 'authorized');
  }
}

class PairingResult {
  PairingResult({required this.paired, required this.reason});

  final bool paired;
  final String reason;
}
