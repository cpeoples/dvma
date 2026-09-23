/// Privileged Input-Provider (IME) Event Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-284 / CWE-863): the default
/// input-method (IME) service is a privileged surface that can synthesize key
/// and motion events into whatever app currently has focus. When the IME
/// accepts injected events from an untrusted CALLER without verifying that the
/// caller holds the required system permission (INJECT_EVENTS / is the system),
/// a co-resident app can INJECT synthetic input - typing, taps, confirmations -
/// into other apps for local privilege escalation. This is the INJECT direction
/// of the keyboard boundary (attacker drives the privileged IME), the opposite
/// of read/exfil interception (Android IME event-injection CVE-2025-26450
/// class).
///
/// This is an offline + deterministic SIMULATION. [ImeEventInjector] receives a
/// batch of [InputEvent]s from a caller package. The vulnerable [inject]
/// performs them regardless of caller (no permission check), so an untrusted
/// caller can auto-confirm a sensitive action (e.g. tap "approve payment"). The
/// secure [injectSafe] requires the caller to be the system / hold the
/// injection permission and refuses untrusted callers.
library;

/// A synthetic input event an IME can dispatch into the focused app.
class InputEvent {
  const InputEvent({required this.kind, required this.target});

  /// The kind of event (e.g. `key`, `tap`).
  final String kind;

  /// The UI target the event drives (e.g. a button label or field).
  final String target;

  /// A synthetic tap on a named UI target.
  factory InputEvent.tap(String target) =>
      InputEvent(kind: 'tap', target: target);

  /// A synthetic key press delivered to a named field.
  factory InputEvent.key(String target) =>
      InputEvent(kind: 'key', target: target);

  @override
  String toString() => '$kind($target)';
}

/// The outcome of injecting a batch of events through the IME.
class InjectionResult {
  const InjectionResult({
    required this.callerPackage,
    required this.performed,
    required this.callerAuthorized,
    required this.performedEvents,
    this.sensitiveActionConfirmed = false,
    this.denyReason,
  });

  /// The package that requested the injection.
  final String callerPackage;

  /// Whether the events were actually dispatched into the focused app.
  final bool performed;

  /// Whether the caller was authorized (system / held injection permission).
  final bool callerAuthorized;

  /// The events that were dispatched (empty when refused).
  final List<InputEvent> performedEvents;

  /// True when injection drove the sensitive victim action - the hit.
  final bool sensitiveActionConfirmed;

  /// Why the secure flow refused.
  final String? denyReason;
}

class ImeEventInjector {
  /// The untrusted co-resident app requesting the injection.
  static const String attackerPackage = 'com.evil.injector';

  /// The privileged principal allowed to synthesize input (the system).
  static const String systemPackage = 'android.uid.system';

  /// The permission an event injector must hold.
  static const String injectPermission = 'android.permission.INJECT_EVENTS';

  /// The sensitive victim UI the attacker wants to auto-confirm.
  static const String victimAction = 'approve payment';

  /// A realistic attacker batch: type into the amount field then tap approve.
  static const List<InputEvent> attackerBatch = [
    InputEvent(kind: 'key', target: 'amount=5000.00'),
    InputEvent(kind: 'tap', target: victimAction),
  ];

  /// Callers the system grants the injection permission.
  static const Set<String> _authorizedCallers = {systemPackage};

  /// VULN: dispatch every injected event into the focused app WITHOUT checking
  /// that the caller is the system or holds INJECT_EVENTS. Any co-resident app
  /// can therefore drive taps/keys in other apps and auto-confirm actions.
  InjectionResult inject(String callerPackage, List<InputEvent> events) {
    final confirmed = events.any(
      (e) => e.kind == 'tap' && e.target == victimAction,
    );
    return InjectionResult(
      callerPackage: callerPackage,
      performed: true,
      callerAuthorized: false,
      performedEvents: List<InputEvent>.unmodifiable(events),
      sensitiveActionConfirmed: confirmed,
    );
  }

  /// SECURE contrast: only the system / a caller holding INJECT_EVENTS may
  /// synthesize input into other apps. Untrusted callers are refused, so no
  /// synthetic tap reaches the sensitive victim action.
  InjectionResult injectSafe(String callerPackage, List<InputEvent> events) {
    if (!_authorizedCallers.contains(callerPackage)) {
      return InjectionResult(
        callerPackage: callerPackage,
        performed: false,
        callerAuthorized: false,
        performedEvents: const [],
        sensitiveActionConfirmed: false,
        denyReason:
            'caller $callerPackage lacks system injection permission '
            '($injectPermission) - refusing to inject events',
      );
    }
    return InjectionResult(
      callerPackage: callerPackage,
      performed: true,
      callerAuthorized: true,
      performedEvents: List<InputEvent>.unmodifiable(events),
      sensitiveActionConfirmed: false,
    );
  }
}
