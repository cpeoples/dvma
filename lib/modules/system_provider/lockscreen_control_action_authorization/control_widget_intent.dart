/// Lock-screen Control Widget / App Intent authorization helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-284 / CWE-863): a WidgetKit Control
/// / interactive widget exposed on the Lock Screen, Control Center, or Action
/// Button can invoke an `AppIntent`. If a SENSITIVE intent (unlock the front
/// door, disable the alarm) runs WITHOUT the authentication the full app would
/// require, a physically-present attacker triggers a privileged operation from
/// a LOCKED device. The system surface offering the control is not the same as
/// the app's own auth gate; sensitive intents must still require unlock /
/// biometric regardless of which surface invoked them.
///
/// This is an offline + deterministic SIMULATION. [ControlWidgetIntentRunner]
/// invokes an [AppIntent] from a [Surface] with a `deviceLocked` flag. The
/// vulnerable [invoke] runs sensitive intents from the lock screen with no
/// auth; the secure [invokeSafe] defers sensitive intents until the device is
/// authenticated, while still allowing non-sensitive ones.
library;

/// Where the intent was invoked from.
enum Surface { lockScreen, controlCenter, actionButton, inApp }

/// A single App Intent a control can invoke.
class AppIntent {
  const AppIntent({required this.name, required this.sensitive});

  final String name;

  /// True for privileged operations that need the app's auth gate.
  final bool sensitive;
}

/// The outcome of invoking an intent from a surface.
class IntentInvocationResult {
  const IntentInvocationResult({
    required this.intent,
    required this.surface,
    required this.deviceLocked,
    required this.performed,
    required this.authRequired,
    required this.unsafe,
    this.denyReason,
  });

  final AppIntent intent;
  final Surface surface;
  final bool deviceLocked;

  /// True when the operation actually ran.
  final bool performed;

  /// True when authentication was required before performing.
  final bool authRequired;

  /// True when a sensitive intent ran without auth on a locked device - the
  /// hit.
  final bool unsafe;

  /// Why the secure path deferred (null on the vulnerable path).
  final String? denyReason;
}

class ControlWidgetIntentRunner {
  ControlWidgetIntentRunner();

  /// Sensitive intent: unlock the front door lock.
  static const AppIntent unlockFrontDoor = AppIntent(
    name: 'unlockFrontDoor',
    sensitive: true,
  );

  /// Sensitive intent: disable the home alarm.
  static const AppIntent disableAlarm = AppIntent(
    name: 'disableAlarm',
    sensitive: true,
  );

  /// Non-sensitive intent: toggle a flashlight - fine from the lock screen.
  static const AppIntent togglePublicFlashlight = AppIntent(
    name: 'togglePublicFlashlight',
    sensitive: false,
  );

  /// VULN: invoke the intent immediately based on the surface offering it. A
  /// sensitive intent triggered from the lock screen on a locked device runs
  /// with no authentication - the system surface is mistaken for authorization.
  IntentInvocationResult invoke(
    AppIntent intent,
    Surface surface, {
    required bool deviceLocked,
  }) {
    return IntentInvocationResult(
      intent: intent,
      surface: surface,
      deviceLocked: deviceLocked,
      performed: true,
      authRequired: false,
      unsafe: intent.sensitive && deviceLocked,
    );
  }

  /// SECURE contrast: require device unlock / biometric for SENSITIVE intents
  /// regardless of surface. A sensitive intent on a locked device is deferred
  /// until authenticated; non-sensitive intents run freely.
  IntentInvocationResult invokeSafe(
    AppIntent intent,
    Surface surface, {
    required bool deviceLocked,
  }) {
    if (intent.sensitive && deviceLocked) {
      return IntentInvocationResult(
        intent: intent,
        surface: surface,
        deviceLocked: deviceLocked,
        performed: false,
        authRequired: true,
        unsafe: false,
        denyReason:
            'authentication required: unlock device to run "${intent.name}"',
      );
    }
    return IntentInvocationResult(
      intent: intent,
      surface: surface,
      deviceLocked: deviceLocked,
      performed: true,
      // Sensitive-but-already-unlocked ran behind the app's auth gate.
      authRequired: intent.sensitive,
      unsafe: false,
    );
  }
}
