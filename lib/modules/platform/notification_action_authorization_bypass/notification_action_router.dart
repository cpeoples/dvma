/// Notification Action Authorization Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-306 / CWE-863): a notification action
/// fires a `PendingIntent` (Android: possibly trampolining an exported
/// receiver -> activity; iOS: a `UNNotificationAction`) that performs a
/// privileged operation - approve transaction / unlock / delete / change
/// account - WITHOUT a fresh authentication decision. The intermediate
/// component (the trampoline receiver) has WEAKER authorization than the
/// equivalent in-app UI: it simply trusts that the notification originated the
/// request. That makes the notification action surface an unauthenticated entry
/// point into a sensitive operation.
///
/// This is an offline SIMULATION. [NotificationActionRouter] models a
/// notification whose actions map to handlers, reachable either through a
/// weakly-authorized "trampoline" path (receiver -> activity -> op) or through
/// the in-app path that requires auth. The vulnerable [invokeAction] runs the
/// op via the trampoline with no auth check; the secure [invokeActionSafe]
/// routes every entry surface through the same authorization check and
/// re-authenticates destructive actions.
library;

/// The outcome of firing a notification action.
class NotificationActionResult {
  const NotificationActionResult({
    required this.action,
    required this.performed,
    required this.freshAuthRequired,
    required this.freshAuthPresented,
    required this.viaTrampoline,
    this.denyReason,
  });

  /// The action key that was invoked (e.g. 'approve_transfer').
  final String action;

  /// Whether the privileged operation actually ran.
  final bool performed;

  /// Whether this action SHOULD require a fresh authentication decision.
  final bool freshAuthRequired;

  /// Whether a fresh auth decision was actually presented before running.
  final bool freshAuthPresented;

  /// Whether the op was reached through the weakly-authorized trampoline.
  final bool viaTrampoline;

  /// Why the secure path refused to run the op.
  final String? denyReason;
}

class NotificationActionRouter {
  /// The sensitive action wired to a notification button.
  static const String sensitiveAction = 'approve_transfer';

  /// The effect of the sensitive action (approve a pending transfer).
  static const int transferAmount = 2500;

  /// The pending transfer's destination account.
  static const String transferAccount = 'acct-payee-042';

  /// Whether the user has completed a fresh authentication in this flow.
  bool _authenticated = false;

  /// Simulate the user completing a fresh auth (biometric / device credential).
  void completeFreshAuth() => _authenticated = true;

  /// Whether a given action is destructive/sensitive enough to demand re-auth.
  bool _isSensitive(String action) => action == sensitiveAction;

  /// VULN: the notification action fires a PendingIntent through an exported
  /// receiver that trampolines to the operation. The trampoline trusts that
  /// the notification originated the request and performs the privileged op
  /// with no fresh authentication - weaker than the in-app path.
  NotificationActionResult invokeAction(String action) {
    // Trampoline: exported receiver -> activity -> op, no auth gate.
    return NotificationActionResult(
      action: action,
      performed: true,
      freshAuthRequired: _isSensitive(action),
      freshAuthPresented: false,
      viaTrampoline: true,
    );
  }

  /// SECURE contrast: route every entry surface (notification, deep link,
  /// in-app button) through the SAME authorization check, and require a fresh
  /// authentication decision before any destructive action runs. Until the
  /// user re-authenticates, the sensitive op is refused.
  NotificationActionResult invokeActionSafe(String action) {
    final sensitive = _isSensitive(action);
    if (sensitive && !_authenticated) {
      return NotificationActionResult(
        action: action,
        performed: false,
        freshAuthRequired: true,
        freshAuthPresented: false,
        viaTrampoline: false,
        denyReason:
            'notification action routed through the shared '
            'authorization check - fresh authentication required before '
            '"$action" (transfer \$$transferAmount to $transferAccount) can run',
      );
    }
    return NotificationActionResult(
      action: action,
      performed: true,
      freshAuthRequired: sensitive,
      freshAuthPresented: sensitive,
      viaTrampoline: false,
    );
  }
}
