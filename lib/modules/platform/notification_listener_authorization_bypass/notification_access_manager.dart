/// Notification Listener Authorization Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-306 / CWE-284): notification-listener
/// access is effectively granted with no proper user grant - above the lock
/// screen, or via an UNVERIFIED NotificationListenerService intent filter - so
/// a listener reads notification contents with no authorization and no user
/// interaction (the Android CVE-2025-22427 above-lock grant / CVE-2025-26442
/// intent-filter verification class).
///
/// This is an offline + deterministic simulation. [NotificationAccessManager]
/// holds posted notifications and any recorded user grants. The vulnerable
/// [bindListener] grants access without a real user-consent record (e.g. the
/// grant is written while the device is LOCKED, or the listener component was
/// never verified) and the listener then reads all notifications. The secure
/// [bindListenerSafe] requires a persisted user grant recorded while UNLOCKED
/// and a verified listener component, refusing the read otherwise.
library;

/// A posted notification the listener could read.
class PostedNotification {
  const PostedNotification({
    required this.package,
    required this.title,
    required this.text,
  });

  final String package;
  final String title;
  final String text;

  @override
  String toString() => '[$package] $title - $text';
}

/// A recorded user grant for notification-listener access.
class ListenerGrant {
  const ListenerGrant({
    required this.component,
    required this.recordedWhileUnlocked,
    required this.userConfirmed,
  });

  /// The listener component the grant is for.
  final String component;

  /// Whether the grant was recorded while the device was UNLOCKED (a real
  /// user could see and confirm the consent dialog).
  final bool recordedWhileUnlocked;

  /// Whether the user actually confirmed the consent dialog.
  final bool userConfirmed;
}

/// The outcome of a listener binding + read attempt.
class ListenerReadResult {
  const ListenerReadResult({
    required this.granted,
    required this.blocked,
    required this.read,
    this.denyReason,
  });

  /// Whether listener access was granted and the read proceeded.
  final bool granted;

  /// Whether the secure manager refused (secure path).
  final bool blocked;

  /// The notification contents the listener read (empty when refused).
  final List<PostedNotification> read;

  /// Why access was refused.
  final String? denyReason;

  /// True when notification contents were disclosed without a valid grant -
  /// the authorization-bypass hit.
  bool get contentsLeaked => granted && read.isNotEmpty;
}

class NotificationAccessManager {
  NotificationAccessManager(
    Iterable<PostedNotification> notifications, {
    Iterable<ListenerGrant> grants = const [],
    required this.deviceUnlocked,
  }) : _notifications = List.of(notifications),
       _grants = {for (final g in grants) g.component: g};

  final List<PostedNotification> _notifications;
  final Map<String, ListenerGrant> _grants;

  /// Whether the device is currently unlocked.
  final bool deviceUnlocked;

  /// The attacker's listener component (never legitimately verified/granted).
  static const String attackerListener =
      'com.evil.listener/.SilentNotificationListener';

  /// A verified, legitimately-granted listener component.
  static const String trustedListener =
      'com.dvma.assist/.AssistNotificationListener';

  /// Components the platform has verified (valid service + intent filter).
  static const Set<String> verifiedComponents = {trustedListener};

  factory NotificationAccessManager.seeded({
    bool deviceUnlocked = false,
    Iterable<ListenerGrant> grants = const [],
  }) {
    return NotificationAccessManager(
      const [
        PostedNotification(
          package: 'com.bank.app',
          title: 'Your one-time code',
          text: 'OTP 4471 - do not share',
        ),
        PostedNotification(
          package: 'com.chat.app',
          title: 'Dr. Reyes',
          text: 'Your test results are ready to view',
        ),
      ],
      grants: grants,
      deviceUnlocked: deviceUnlocked,
    );
  }

  List<PostedNotification> get notifications =>
      List.unmodifiable(_notifications);

  /// VULN: bind [listener] and read all notifications with no real
  /// authorization. The manager never checks for a persisted, user-confirmed
  /// grant, never verifies the listener component, and never checks the lock
  /// state, so an unverified listener silently reads every notification.
  ListenerReadResult bindListener(String listener) {
    return ListenerReadResult(
      granted: true,
      blocked: false,
      read: List.unmodifiable(_notifications),
    );
  }

  /// SECURE contrast: require a PERSISTED user grant that was recorded while the
  /// device was UNLOCKED and confirmed by the user, AND require the listener
  /// component to be verified. Any missing/invalid condition refuses the read.
  ListenerReadResult bindListenerSafe(String listener) {
    if (!verifiedComponents.contains(listener)) {
      return const ListenerReadResult(
        granted: false,
        blocked: true,
        read: [],
        denyReason: 'listener component is not verified',
      );
    }
    final grant = _grants[listener];
    if (grant == null || !grant.userConfirmed) {
      return const ListenerReadResult(
        granted: false,
        blocked: true,
        read: [],
        denyReason: 'no persisted, user-confirmed listener grant',
      );
    }
    if (!grant.recordedWhileUnlocked) {
      return const ListenerReadResult(
        granted: false,
        blocked: true,
        read: [],
        denyReason: 'grant was recorded above the lock screen (device locked)',
      );
    }
    return ListenerReadResult(
      granted: true,
      blocked: false,
      read: List.unmodifiable(_notifications),
    );
  }
}
