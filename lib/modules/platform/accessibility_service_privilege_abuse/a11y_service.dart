/// AccessibilityService Privilege Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-284 / CWE-862 / CWE-269): an
/// AccessibilityService performs a PRIVILEGED action - launching an activity
/// from the background, hiding/suppressing UI, injecting a gesture/click - with
/// INSUFFICIENT caller / service-state validation. The a11y capability is thus
/// abused for privilege escalation or UI manipulation (the Android
/// AccessibilityServiceConnection CVE-2025-26462 / CVE-2023-21109 class).
///
/// This is an offline + deterministic simulation. [A11yService] models a
/// service with a user-enabled flag and a set of granted capabilities. The
/// vulnerable [perform] executes background-activity-launch / hide-app /
/// inject-gesture with no check that the action originates from a genuine a11y
/// event or that the service is in a valid state. The secure [performSafe]
/// requires the service to be user-enabled AND the action to be tied to a real
/// foreground a11y event AND on an allowlist of permitted actions, refusing
/// background launches / UI hiding.
library;

/// The kind of privileged operation an a11y service can perform.
enum A11yActionKind {
  /// Launch an activity from the background (no foreground event).
  launchActivityFromBackground,

  /// Hide / suppress on-screen UI (e.g. a security prompt).
  hideUi,

  /// Inject a synthetic gesture / click.
  injectGesture,

  /// A benign, in-scope assistive read of the focused node.
  readFocusedNode,
}

/// A requested a11y action.
class A11yAction {
  const A11yAction({
    required this.kind,
    required this.target,
    this.fromForegroundEvent = false,
  });

  final A11yActionKind kind;

  /// What the action operates on (activity name, view id, etc.).
  final String target;

  /// Whether this action was triggered by a genuine foreground a11y event
  /// (true) rather than fabricated by the service in the background.
  final bool fromForegroundEvent;
}

/// The outcome of an a11y service performing an action.
class A11yResult {
  const A11yResult({
    required this.performed,
    required this.blocked,
    required this.kind,
    required this.effect,
    this.denyReason,
  });

  /// Whether the privileged action was carried out.
  final bool performed;

  /// Whether the secure path refused (secure path).
  final bool blocked;

  /// The action kind that was requested.
  final A11yActionKind kind;

  /// A human-readable description of what happened.
  final String effect;

  /// Why the secure path refused.
  final String? denyReason;

  /// True when a privileged (non-assistive) action ran - the abuse hit.
  bool get privilegeAbused =>
      performed && kind != A11yActionKind.readFocusedNode;
}

class A11yService {
  A11yService({
    required this.userEnabled,
    Set<A11yActionKind>? grantedCapabilities,
  }) : grantedCapabilities = grantedCapabilities ?? _defaultCapabilities;

  /// Whether the user actually enabled this service in Accessibility settings.
  final bool userEnabled;

  /// The capabilities the service declares / was granted.
  final Set<A11yActionKind> grantedCapabilities;

  static const Set<A11yActionKind> _defaultCapabilities = {
    A11yActionKind.launchActivityFromBackground,
    A11yActionKind.hideUi,
    A11yActionKind.injectGesture,
    A11yActionKind.readFocusedNode,
  };

  /// The only actions a well-behaved assistive service should ever perform on
  /// its own: reading the focused node. Everything else must be tied to a real
  /// foreground event and is otherwise privilege abuse.
  static const Set<A11yActionKind> allowlistedActions = {
    A11yActionKind.readFocusedNode,
  };

  /// A crafted background action: launch a phishing/consent activity with no
  /// genuine foreground a11y event behind it.
  static const A11yAction maliciousLaunch = A11yAction(
    kind: A11yActionKind.launchActivityFromBackground,
    target: 'com.dvma/.FakeConsentActivity',
    fromForegroundEvent: false,
  );

  /// A benign assistive action tied to a real foreground event.
  static const A11yAction benignRead = A11yAction(
    kind: A11yActionKind.readFocusedNode,
    target: 'node:submit_button',
    fromForegroundEvent: true,
  );

  String _describe(A11yAction action) {
    switch (action.kind) {
      case A11yActionKind.launchActivityFromBackground:
        return 'launched ${action.target} from background (task hijack surface)';
      case A11yActionKind.hideUi:
        return 'suppressed UI ${action.target} (hid security prompt)';
      case A11yActionKind.injectGesture:
        return 'injected synthetic gesture on ${action.target}';
      case A11yActionKind.readFocusedNode:
        return 'read focused node ${action.target}';
    }
  }

  /// VULN: perform the [action] with no validation. The service does not check
  /// that it is user-enabled, that the action came from a genuine foreground
  /// a11y event, or that the action is one it should ever self-initiate. A
  /// background activity launch / UI suppression therefore just runs.
  A11yResult perform(A11yAction action) {
    return A11yResult(
      performed: true,
      blocked: false,
      kind: action.kind,
      effect: _describe(action),
    );
  }

  /// SECURE contrast: only perform when (1) the service is user-enabled, (2) the
  /// service was granted the capability, (3) the action is on the allowlist of
  /// actions a service may self-initiate OR it is backed by a genuine
  /// foreground a11y event, and (4) it is never a background launch / UI hide
  /// without such an event. Otherwise the privileged action is refused.
  A11yResult performSafe(A11yAction action) {
    if (!userEnabled) {
      return A11yResult(
        performed: false,
        blocked: true,
        kind: action.kind,
        effect: 'no-op',
        denyReason: 'accessibility service is not user-enabled',
      );
    }
    if (!grantedCapabilities.contains(action.kind)) {
      return A11yResult(
        performed: false,
        blocked: true,
        kind: action.kind,
        effect: 'no-op',
        denyReason: 'service was not granted capability ${action.kind.name}',
      );
    }
    final allowedSelfInitiated = allowlistedActions.contains(action.kind);
    if (!allowedSelfInitiated && !action.fromForegroundEvent) {
      return A11yResult(
        performed: false,
        blocked: true,
        kind: action.kind,
        effect: 'no-op',
        denyReason:
            '${action.kind.name} requires a genuine foreground a11y event; '
            'background launches / UI hiding refused',
      );
    }
    return A11yResult(
      performed: true,
      blocked: false,
      kind: action.kind,
      effect: _describe(action),
    );
  }
}
