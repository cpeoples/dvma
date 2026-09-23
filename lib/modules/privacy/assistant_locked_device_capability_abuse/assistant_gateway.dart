/// System Assistant -> Locked-Device Capability Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-863 / CWE-284 / CWE-200): the system assistant
/// (Siri / App-Intents / a voice shortcut / Google Assistant) exposes sensitive
/// information or performs a privileged capability while the device is LOCKED,
/// because the assistant invocation path never RE-CHECKS the keyguard / auth
/// state. An attacker holding a locked phone triggers the assistant ("read my
/// messages", "what's my balance", "run my transfer intent") and gets
/// sensitive data or a privileged action without unlocking.
///
/// This is the ASSISTANT / voice-intent surface specifically - distinct from
/// the accessibility / notification / widget lock-state module. It models an
/// assistant gateway that dispatches App-Intents.
///
/// This is an offline + deterministic SIMULATION. [AssistantGateway] holds a
/// `deviceLocked` flag and a set of capabilities, each tagged sensitive or not.
/// The vulnerable [invoke] runs any capability even while locked (it skips the
/// keyguard); the secure [invokeSafe] re-checks the lock state and requires
/// unlock/authentication for sensitive capabilities, returning only
/// non-sensitive results while locked.
library;

/// A capability the assistant can dispatch via an App-Intent / voice shortcut.
enum AssistantCapability {
  /// Read the user's private messages aloud (sensitive).
  readMessages,

  /// Read the account balance aloud (sensitive).
  readBalance,

  /// Run a money-transfer App-Intent (sensitive, privileged).
  runTransferIntent,

  /// Report the weather (non-sensitive, fine while locked).
  readWeather,
}

extension _CapabilityInfo on AssistantCapability {
  bool get sensitive => this != AssistantCapability.readWeather;

  String get result {
    switch (this) {
      case AssistantCapability.readMessages:
        return 'Messages: Dr. Reyes - "Your biopsy results are ready"; '
            'Bank - "OTP 552134"';
      case AssistantCapability.readBalance:
        return 'Checking balance: \$8,204.19; last: transfer -\$1,200';
      case AssistantCapability.runTransferIntent:
        return 'Transfer intent executed: \$1,200 -> acct DVMA-MERCHANT';
      case AssistantCapability.readWeather:
        return 'Weather: 72°F, clear';
    }
  }
}

/// The outcome of an assistant capability invocation.
class AssistantResult {
  const AssistantResult({
    required this.capability,
    required this.deviceLocked,
    required this.performed,
    required this.output,
    required this.sensitiveExposedWhileLocked,
    this.denyReason,
  });

  final AssistantCapability capability;

  /// Whether the device was locked at invocation time.
  final bool deviceLocked;

  /// Whether the capability ran / returned data.
  final bool performed;

  /// What the assistant returned to the (possibly unauthenticated) user.
  final String output;

  /// True when a SENSITIVE capability produced sensitive output on a LOCKED
  /// device - the locked-assistant abuse hit.
  final bool sensitiveExposedWhileLocked;

  /// Why the secure gateway refused / redacted.
  final String? denyReason;
}

/// An in-memory model of the system-assistant intent gateway.
class AssistantGateway {
  const AssistantGateway({required this.deviceLocked});

  /// Whether the keyguard is currently engaged.
  final bool deviceLocked;

  /// A locked device (the attacker is holding it at the lock screen).
  static const AssistantGateway lockedSample = AssistantGateway(
    deviceLocked: true,
  );

  /// The response shown for a sensitive capability while locked (secure path).
  static const String lockedNotice =
      'Unlock your device to use this with the assistant.';

  /// VULN: dispatch the capability regardless of lock state. The assistant
  /// path never re-checks the keyguard, so sensitive App-Intents run while the
  /// phone is locked.
  AssistantResult invoke(AssistantCapability capability) {
    return AssistantResult(
      capability: capability,
      deviceLocked: deviceLocked,
      performed: true,
      output: capability.result,
      sensitiveExposedWhileLocked: deviceLocked && capability.sensitive,
      denyReason: null,
    );
  }

  /// SECURE contrast: re-check the lock state on the assistant path. While
  /// locked, sensitive capabilities require authentication and are refused
  /// (only a non-sensitive notice is returned); non-sensitive capabilities
  /// still work. Once unlocked, everything is permitted.
  AssistantResult invokeSafe(AssistantCapability capability) {
    if (deviceLocked && capability.sensitive) {
      return AssistantResult(
        capability: capability,
        deviceLocked: true,
        performed: false,
        output: lockedNotice,
        sensitiveExposedWhileLocked: false,
        denyReason:
            'assistant re-checked keyguard: sensitive capability '
            'requires unlock/authentication',
      );
    }
    return AssistantResult(
      capability: capability,
      deviceLocked: deviceLocked,
      performed: true,
      output: capability.result,
      sensitiveExposedWhileLocked: false,
      denyReason: null,
    );
  }
}
