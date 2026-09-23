/// Exported Component -> Unauthorized State Manipulation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-639 / CWE-284): an EXPORTED
/// component accepts an attacker-controlled identifier in its intent extras and
/// performs a security-sensitive STATE CHANGE - cancelling a notification - with
/// no caller/ownership validation. Because the component is exported, ANY
/// co-resident app can send it an intent naming a notification id it does not
/// own and have the system mutate that state on its behalf (the Datadog Android
/// CVE-2026-47361 class: an unprivileged app cancels the victim app's AI-chat
/// notification).
///
/// This is an offline + deterministic simulation. [NotificationCenter] is an
/// in-memory store of notifications keyed by id, each OWNED by a package id.
/// The vulnerable [handleIntent] cancels any id regardless of caller; the
/// secure [handleIntentSafe] verifies the notification's owner package matches
/// the caller (or the caller holds a signature permission) before mutating.
library;

/// A notification held by the (simulated) system, owned by a package.
class ManagedNotification {
  const ManagedNotification({
    required this.id,
    required this.ownerPackage,
    required this.title,
    this.active = true,
  });

  final String id;

  /// The package that posted (and therefore owns) this notification.
  final String ownerPackage;

  final String title;

  /// Whether the notification is currently posted (not cancelled).
  final bool active;

  ManagedNotification copyWith({bool? active}) => ManagedNotification(
    id: id,
    ownerPackage: ownerPackage,
    title: title,
    active: active ?? this.active,
  );
}

/// The result of an exported component handling a state-change intent.
class ControllerResult {
  const ControllerResult({
    required this.mutated,
    required this.caller,
    required this.targetId,
    this.targetOwner,
    this.denyReason,
  });

  /// Whether the state change (cancellation) was carried out.
  final bool mutated;

  /// The package that sent the intent.
  final String caller;

  /// The notification id the intent targeted.
  final String targetId;

  /// The owner of the targeted notification (null if it did not exist).
  final String? targetOwner;

  /// Why the request was denied (secure path).
  final String? denyReason;

  /// True when a caller mutated state it does not own - the actual bug hit.
  bool get crossOwnerMutation =>
      mutated && targetOwner != null && targetOwner != caller;
}

/// An in-memory model of an exported notification-controller component.
class NotificationCenter {
  NotificationCenter(Iterable<ManagedNotification> seed)
    : _notifications = {for (final n in seed) n.id: n};

  final Map<String, ManagedNotification> _notifications;

  /// The victim app whose AI-chat notification is the target.
  static const String victimPackage = 'com.dvma.aichat';

  /// The co-resident attacker app crafting the intent.
  static const String attackerPackage = 'com.evil.localapp';

  /// The victim's sensitive notification id.
  static const String victimNotificationId = 'aichat-msg-8842';

  /// A realistic center: the victim AI-chat app's notification plus one the
  /// attacker legitimately owns.
  factory NotificationCenter.seeded() {
    return NotificationCenter(const [
      ManagedNotification(
        id: victimNotificationId,
        ownerPackage: victimPackage,
        title: 'New message from Dr. Reyes: your results are ready',
      ),
      ManagedNotification(
        id: 'evil-promo-1',
        ownerPackage: attackerPackage,
        title: 'You won a prize!',
      ),
    ]);
  }

  /// Whether the notification [id] is currently active (posted).
  bool isActive(String id) => _notifications[id]?.active ?? false;

  ManagedNotification? notification(String id) => _notifications[id];

  /// VULN: cancel the notification named by [targetNotificationId] purely from
  /// the intent extras. The exported component never checks that
  /// [callerPackage] owns the target, so any co-resident app cancels anyone's
  /// notification.
  ControllerResult handleIntent(
    String callerPackage,
    String targetNotificationId,
  ) {
    final existing = _notifications[targetNotificationId];
    if (existing == null) {
      return ControllerResult(
        mutated: false,
        caller: callerPackage,
        targetId: targetNotificationId,
        denyReason: 'no such notification',
      );
    }
    // No ownership/permission check -> mutate state the caller does not own.
    _notifications[targetNotificationId] = existing.copyWith(active: false);
    return ControllerResult(
      mutated: true,
      caller: callerPackage,
      targetId: targetNotificationId,
      targetOwner: existing.ownerPackage,
    );
  }

  /// SECURE contrast: verify the caller OWNS the targeted notification (or holds
  /// a signature-level permission) before mutating it. A cross-owner request is
  /// refused and the state is left intact.
  ControllerResult handleIntentSafe(
    String callerPackage,
    String targetNotificationId, {
    bool callerHoldsSignaturePermission = false,
  }) {
    final existing = _notifications[targetNotificationId];
    if (existing == null) {
      return ControllerResult(
        mutated: false,
        caller: callerPackage,
        targetId: targetNotificationId,
        denyReason: 'no such notification',
      );
    }
    final owns = existing.ownerPackage == callerPackage;
    if (!owns && !callerHoldsSignaturePermission) {
      return ControllerResult(
        mutated: false,
        caller: callerPackage,
        targetId: targetNotificationId,
        targetOwner: existing.ownerPackage,
        denyReason:
            'caller $callerPackage does not own ${existing.ownerPackage}\'s '
            'notification and lacks signature permission',
      );
    }
    _notifications[targetNotificationId] = existing.copyWith(active: false);
    return ControllerResult(
      mutated: true,
      caller: callerPackage,
      targetId: targetNotificationId,
      targetOwner: existing.ownerPackage,
    );
  }
}
