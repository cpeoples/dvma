/// Exported BroadcastReceiver Data Spoofing helper.
///
/// INTENTIONALLY VULNERABLE (CWE-925 / CWE-862 / CWE-346): an app registers a
/// BroadcastReceiver that is EXPORTED (android:exported="true" with no
/// signature-level permission), so ANY app on the device can send it a
/// broadcast. The receiver then trusts the extras it receives as authoritative
/// - e.g. a device-location update - and updates app state from them. A local
/// malicious app (com.evil.*) sends a spoofed broadcast with fake location and
/// the app believes it. This is the Home Assistant Companion GHSA
/// location-spoof class.
///
/// This is an offline + deterministic simulation. [BroadcastBus] delivers a
/// [Broadcast] to a receiver that either trusts any sender (vuln) or verifies
/// the sender package / signature-level permission (secure). No Android
/// BroadcastReceiver is used. Tests assert a spoofed broadcast is accepted on
/// the vuln path and rejected on the secure path.
library;

/// A broadcast intent sent on the (simulated) system bus.
class Broadcast {
  const Broadcast({
    required this.action,
    required this.senderPackage,
    required this.senderHoldsPermission,
    required this.extras,
  });

  /// The broadcast action (e.g. `com.dvma.action.LOCATION_UPDATE`).
  final String action;

  /// The package that sent the broadcast.
  final String senderPackage;

  /// Whether the sender holds the app's signature-level permission (secure
  /// path check).
  final bool senderHoldsPermission;

  /// The extras the receiver would read as authoritative.
  final Map<String, String> extras;
}

/// The outcome of a receiver handling a broadcast.
class ReceiveResult {
  const ReceiveResult({
    required this.accepted,
    required this.blocked,
    this.appliedExtras,
    this.blockReason,
  });

  /// Whether the receiver accepted the broadcast and applied its extras.
  final bool accepted;

  /// Whether the receiver refused the broadcast (secure path).
  final bool blocked;

  /// The extras the receiver applied to app state (null unless accepted).
  final Map<String, String>? appliedExtras;

  /// Why the broadcast was refused (secure path only).
  final String? blockReason;

  /// True when extras from an UNTRUSTED sender were applied as authoritative -
  /// the actual spoofing hit.
  bool spoofAccepted(Broadcast b, Set<String> trustedSenders) =>
      accepted && !trustedSenders.contains(b.senderPackage);
}

/// A minimal, in-memory model of the system broadcast bus + an app receiver.
class BroadcastBus {
  BroadcastBus({Set<String>? trustedSenders})
    : trustedSenders = trustedSenders ?? const {'com.dvma.app'};

  /// The app's own first-party packages, trusted as broadcast senders.
  final Set<String> trustedSenders;

  /// The action the app's exported receiver listens for.
  static const String locationAction = 'com.dvma.action.LOCATION_UPDATE';

  /// VULN: the exported receiver trusts whatever sender delivers the broadcast
  /// and applies its extras as authoritative. A com.evil.* app spoofs the
  /// device location and the app believes it.
  ReceiveResult deliver(Broadcast b) {
    return ReceiveResult(
      accepted: true,
      blocked: false,
      appliedExtras: Map<String, String>.from(b.extras),
    );
  }

  /// SECURE contrast: verify the broadcast came from a trusted first-party
  /// sender AND that the sender holds the app's signature-level permission
  /// before applying any extras. A spoofed broadcast from an untrusted app is
  /// refused.
  ReceiveResult deliverSafe(Broadcast b) {
    if (!trustedSenders.contains(b.senderPackage)) {
      return ReceiveResult(
        accepted: false,
        blocked: true,
        blockReason: 'sender ${b.senderPackage} not trusted',
      );
    }
    if (!b.senderHoldsPermission) {
      return const ReceiveResult(
        accepted: false,
        blocked: true,
        blockReason: 'sender lacks signature-level permission',
      );
    }
    return ReceiveResult(
      accepted: true,
      blocked: false,
      appliedExtras: Map<String, String>.from(b.extras),
    );
  }
}
