/// RemoteViews Widget Action Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-862 / CWE-863): an app-widget builds
/// `RemoteViews` whose click `PendingIntent` is derived from
/// attacker-influenceable widget-config state (config-activity extras,
/// collection-item data). Because that external state flows straight into the
/// action and its parameters, tapping the widget invokes a privileged in-app
/// operation (transfer / unlock / delete) with attacker-chosen parameters and
/// no re-authentication. A mutable / implicit `PendingIntent` makes it worse:
/// the payload can be filled in later, so untrusted widget state becomes a
/// privileged, unauthenticated action.
///
/// This is an offline SIMULATION. [WidgetRemoteViews] models configuring a
/// widget from untrusted extras and then "tapping" it to fire the built
/// PendingIntent into a privileged handler. The vulnerable [configure] builds a
/// mutable/implicit action from the extras and [tap] performs the transfer with
/// attacker values; the secure [configureSafe] binds only an immutable,
/// explicit PendingIntent to a fixed safe action and re-authenticates
/// destructive operations, so attacker extras are ignored / blocked.
library;

/// The privileged action a widget tap resolves to.
class WidgetPendingIntent {
  const WidgetPendingIntent({
    required this.action,
    required this.amount,
    required this.toAccount,
    required this.mutable,
    required this.explicit,
    required this.requiresReauth,
  });

  /// The in-app operation this tap performs (e.g. 'transfer').
  final String action;

  /// The amount parameter for the operation.
  final int amount;

  /// The destination account parameter for the operation.
  final String toAccount;

  /// Whether the PendingIntent payload can still be mutated by the sender.
  final bool mutable;

  /// Whether the PendingIntent targets an explicit, fixed component.
  final bool explicit;

  /// Whether the resolved action demands a fresh authentication decision.
  final bool requiresReauth;
}

/// The outcome of tapping the configured widget.
class WidgetTapResult {
  const WidgetTapResult({
    required this.actionPerformed,
    required this.reauthenticated,
    required this.action,
    required this.amount,
    required this.toAccount,
    this.denyReason,
  });

  /// Whether the privileged operation actually ran.
  final bool actionPerformed;

  /// Whether a fresh auth decision was presented before the op ran.
  final bool reauthenticated;

  /// The action that the widget tap invoked.
  final String action;

  /// The amount the operation ran with.
  final int amount;

  /// The destination account the operation ran with.
  final String toAccount;

  /// Why the secure path refused to perform the operation.
  final String? denyReason;
}

class WidgetRemoteViews {
  /// The privileged transfer action wired behind the widget.
  static const String transferAction = 'com.dvma.app.widget.action.TRANSFER';

  /// The safe, non-destructive action a hardened widget should perform.
  static const String safeAction = 'com.dvma.app.widget.action.OPEN_DASHBOARD';

  /// The attacker-chosen transfer amount injected via widget-config extras.
  static const int attackerAmount = 5000;

  /// The attacker-controlled destination account.
  static const String attackerAccount = 'acct-attacker-999';

  /// The benign default amount for the safe action.
  static const int benignAmount = 0;

  /// The benign default account for the safe action.
  static const String benignAccount = 'acct-self';

  WidgetPendingIntent? _pending;

  /// VULN: build the widget's click PendingIntent directly from untrusted
  /// config extras. The action and its params come from attacker-influenceable
  /// state, and the intent is mutable/implicit, so nothing constrains the
  /// payload.
  WidgetPendingIntent configure(Map<String, Object?> extras) {
    final pending = WidgetPendingIntent(
      action: (extras['action'] as String?) ?? transferAction,
      amount: (extras['amount'] as int?) ?? attackerAmount,
      toAccount: (extras['toAccount'] as String?) ?? attackerAccount,
      mutable: true,
      explicit: false,
      requiresReauth: false,
    );
    _pending = pending;
    return pending;
  }

  /// SECURE contrast: ignore untrusted extras entirely. Bind an immutable,
  /// explicit PendingIntent to a single fixed safe action; destructive
  /// operations are never wired to a widget tap and always require re-auth.
  WidgetPendingIntent configureSafe(Map<String, Object?> extras) {
    final pending = WidgetPendingIntent(
      action: safeAction,
      amount: benignAmount,
      toAccount: benignAccount,
      mutable: false,
      explicit: true,
      requiresReauth: true,
    );
    _pending = pending;
    return pending;
  }

  /// VULN tap: fire the configured PendingIntent into the privileged handler.
  /// A mutable/implicit intent for a destructive action runs with the
  /// attacker's parameters and no auth.
  WidgetTapResult tap() {
    final p = _pending;
    if (p == null) {
      return const WidgetTapResult(
        actionPerformed: false,
        reauthenticated: false,
        action: '(unconfigured)',
        amount: 0,
        toAccount: '(none)',
        denyReason: 'widget not configured',
      );
    }
    return WidgetTapResult(
      actionPerformed: true,
      reauthenticated: false,
      action: p.action,
      amount: p.amount,
      toAccount: p.toAccount,
    );
  }

  /// SECURE tap: an explicit, immutable intent only reaches the fixed safe
  /// action; any destructive action is refused unless re-authenticated first.
  WidgetTapResult tapSafe() {
    final p = _pending;
    if (p == null) {
      return const WidgetTapResult(
        actionPerformed: false,
        reauthenticated: false,
        action: '(unconfigured)',
        amount: 0,
        toAccount: '(none)',
        denyReason: 'widget not configured',
      );
    }
    // A destructive action wired to a widget tap is refused outright.
    if (p.action == transferAction || p.mutable || !p.explicit) {
      return WidgetTapResult(
        actionPerformed: false,
        reauthenticated: false,
        action: p.action,
        amount: p.amount,
        toAccount: p.toAccount,
        denyReason:
            'destructive/mutable/implicit widget action refused - '
            'only an explicit, immutable safe action is permitted and '
            'destructive ops require fresh authentication',
      );
    }
    return WidgetTapResult(
      actionPerformed: true,
      reauthenticated: true,
      action: p.action,
      amount: p.amount,
      toAccount: p.toAccount,
    );
  }
}
