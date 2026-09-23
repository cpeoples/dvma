/// Companion Device Pairing Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-863 / CWE-284 / CWE-1188): an app pairs with a
/// nearby companion device (watch / peripheral / car / IoT) via the
/// CompanionDeviceManager flow and then treats "paired" as "authorized for
/// every capability". Pairing only establishes proximity + identity for a
/// device; it is not a grant for every privileged action. When the app skips
/// a per-capability authorization/trust binding, a spoofed or low-trust
/// companion device can request a high-privilege capability (e.g. unlock the
/// door) simply because it is paired.
///
/// This is an offline + deterministic SIMULATION. [CompanionDeviceManager]
/// tracks paired [CompanionDevice]s with a trust level. The vulnerable
/// [requestCapability] grants ANY capability to ANY paired device
/// (paired == authorized). The secure [requestCapabilitySafe] checks a
/// per-capability trust binding, so a low-trust / spoofed device is denied
/// high-privilege capabilities.
library;

/// How much the pairing flow actually vouches for a companion device.
enum TrustLevel {
  /// Freshly seen / spoofed advertiser - identity not verified.
  spoofed,

  /// Paired over an unauthenticated channel (just-works) - low assurance.
  low,

  /// Paired with authenticated out-of-band confirmation - high assurance.
  verified,
}

/// A privileged action a companion device may request from the phone app.
enum CompanionCapability { readNotifications, sendSms, unlockDoor }

extension CompanionCapabilityInfo on CompanionCapability {
  String get label {
    switch (this) {
      case CompanionCapability.readNotifications:
        return 'read-notifications';
      case CompanionCapability.sendSms:
        return 'send-sms';
      case CompanionCapability.unlockDoor:
        return 'unlock-door';
    }
  }

  /// The minimum trust a device must hold to be authorized for this capability.
  TrustLevel get requiredTrust {
    switch (this) {
      case CompanionCapability.readNotifications:
        return TrustLevel.low;
      case CompanionCapability.sendSms:
        return TrustLevel.verified;
      case CompanionCapability.unlockDoor:
        return TrustLevel.verified;
    }
  }

  /// Whether this capability is high-privilege (physical / financial impact).
  bool get highPrivilege =>
      this == CompanionCapability.unlockDoor ||
      this == CompanionCapability.sendSms;
}

/// A companion device that has completed the pairing flow.
class CompanionDevice {
  const CompanionDevice({required this.id, required this.trustLevel});

  /// A human label / advertised name for the device.
  final String id;

  /// How much the pairing actually vouches for this device.
  final TrustLevel trustLevel;
}

/// The outcome of a capability request from a companion device.
class CapabilityResult {
  const CapabilityResult({
    required this.device,
    required this.capability,
    required this.granted,
    required this.overPrivileged,
    this.denyReason,
  });

  final CompanionDevice device;
  final CompanionCapability capability;

  /// Whether the capability was granted to the device.
  final bool granted;

  /// True when a device was granted a capability above its trust - the hit.
  final bool overPrivileged;

  /// Why the secure flow refused.
  final String? denyReason;
}

class CompanionDeviceManager {
  /// A spoofed low-trust advertiser posing as the user's smartwatch.
  static const CompanionDevice spoofedWatch = CompanionDevice(
    id: 'Pixel Watch (spoofed)',
    trustLevel: TrustLevel.spoofed,
  );

  /// The genuine, verified companion device.
  static const CompanionDevice verifiedWatch = CompanionDevice(
    id: 'Pixel Watch',
    trustLevel: TrustLevel.verified,
  );

  int _rank(TrustLevel level) {
    switch (level) {
      case TrustLevel.spoofed:
        return 0;
      case TrustLevel.low:
        return 1;
      case TrustLevel.verified:
        return 2;
    }
  }

  /// VULN: grant ANY capability to ANY paired device. The app equates
  /// "paired" with "authorized", so a spoofed / low-trust device receives a
  /// high-privilege capability (e.g. unlock the door) it should never hold.
  CapabilityResult requestCapability(
    CompanionDevice device,
    CompanionCapability cap,
  ) {
    final overPrivileged = _rank(device.trustLevel) < _rank(cap.requiredTrust);
    return CapabilityResult(
      device: device,
      capability: cap,
      granted: true,
      overPrivileged: overPrivileged,
    );
  }

  /// SECURE contrast: authorize per-capability by binding the requested
  /// capability to the device's verified trust level. A low-trust / spoofed
  /// device is denied any capability above its assurance.
  CapabilityResult requestCapabilitySafe(
    CompanionDevice device,
    CompanionCapability cap,
  ) {
    if (_rank(device.trustLevel) < _rank(cap.requiredTrust)) {
      return CapabilityResult(
        device: device,
        capability: cap,
        granted: false,
        overPrivileged: false,
        denyReason:
            'device "${device.id}" (${device.trustLevel.name}) is not '
            'authorized for capability ${cap.label} '
            '(requires ${cap.requiredTrust.name})',
      );
    }
    return CapabilityResult(
      device: device,
      capability: cap,
      granted: true,
      overPrivileged: false,
    );
  }
}
