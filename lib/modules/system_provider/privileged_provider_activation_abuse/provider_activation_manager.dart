/// Privileged Provider Activation Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1021 / CWE-441 / CWE-863): an app becomes an
/// enabled SYSTEM PROVIDER (accessibility service / notification listener / VPN
/// / IME / device-admin / call-screening / phone-account / MediaProjection /
/// credential-provider) through an ENABLEMENT flow that is the real security
/// boundary. The flow can be COERCED - the confirming tap is tapjacked /
/// obscured by an overlay - and it is never re-confirmed. Once enabled, the
/// granted capability is a confused deputy: an untrusted caller drives it on
/// the user's behalf (Android tapjack-to-enable phone-account CVE-2023-20913
/// class).
///
/// This is an offline + deterministic SIMULATION. [ProviderActivationManager]
/// tracks a set of provider types, each with an `enabled` flag and a record of
/// how enablement was confirmed. The vulnerable [enable] grants enablement even
/// when the confirming tap was obscured by an overlay (no genuine
/// user-confirmation record), and [invoke] then drives the capability for ANY
/// caller. The secure [enableSafe] refuses enablement when the tap is obscured
/// / lacks a real confirmation, and [invokeSafe] re-checks the caller.
library;

/// The kinds of system provider an app can be enabled as.
enum ProviderType {
  accessibility,
  notificationListener,
  vpn,
  inputMethod,
  deviceAdmin,
  callScreening,
  phoneAccount,
  mediaProjection,
  credentialProvider,
}

extension ProviderTypeLabel on ProviderType {
  String get label {
    switch (this) {
      case ProviderType.accessibility:
        return 'accessibility-service';
      case ProviderType.notificationListener:
        return 'notification-listener';
      case ProviderType.vpn:
        return 'vpn-service';
      case ProviderType.inputMethod:
        return 'input-method (IME)';
      case ProviderType.deviceAdmin:
        return 'device-admin';
      case ProviderType.callScreening:
        return 'call-screening';
      case ProviderType.phoneAccount:
        return 'phone-account';
      case ProviderType.mediaProjection:
        return 'media-projection';
      case ProviderType.credentialProvider:
        return 'credential-provider';
    }
  }

  /// The privileged capability the provider drives once enabled.
  String get capability {
    switch (this) {
      case ProviderType.accessibility:
        return 'read+inject UI events in every app';
      case ProviderType.notificationListener:
        return 'read every notification (OTPs, messages)';
      case ProviderType.vpn:
        return 'intercept all network traffic';
      case ProviderType.inputMethod:
        return 'observe all typed input';
      case ProviderType.deviceAdmin:
        return 'wipe / lock the device';
      case ProviderType.callScreening:
        return 'screen / redirect incoming calls';
      case ProviderType.phoneAccount:
        return 'place & route outgoing calls';
      case ProviderType.mediaProjection:
        return 'record the screen';
      case ProviderType.credentialProvider:
        return 'release stored credentials';
    }
  }
}

/// The state recorded for a provider enablement.
class ProviderState {
  const ProviderState({
    required this.type,
    required this.enabled,
    required this.confirmedByGenuineTap,
  });

  final ProviderType type;

  /// Whether the app is currently enabled as this provider.
  final bool enabled;

  /// Whether enablement was confirmed by a genuine (un-obscured) user tap.
  final bool confirmedByGenuineTap;

  ProviderState copyWith({bool? enabled, bool? confirmedByGenuineTap}) =>
      ProviderState(
        type: type,
        enabled: enabled ?? this.enabled,
        confirmedByGenuineTap:
            confirmedByGenuineTap ?? this.confirmedByGenuineTap,
      );
}

/// The outcome of an enablement attempt.
class EnablementResult {
  const EnablementResult({
    required this.type,
    required this.enabled,
    required this.coerced,
    this.denyReason,
  });

  final ProviderType type;

  /// Whether the app is now enabled as this provider.
  final bool enabled;

  /// True when enablement was granted despite an obscured/coerced tap - the
  /// tapjack-to-enable hit.
  final bool coerced;

  /// Why the secure flow refused.
  final String? denyReason;
}

/// The outcome of driving the granted capability (confused deputy check).
class InvocationResult {
  const InvocationResult({
    required this.type,
    required this.caller,
    required this.performed,
    required this.confusedDeputy,
    this.denyReason,
  });

  final ProviderType type;

  /// The (untrusted) caller driving the capability.
  final String caller;

  /// Whether the capability was actually driven.
  final bool performed;

  /// True when a capability enabled via coercion ran for an untrusted caller.
  final bool confusedDeputy;

  /// Why the secure flow refused.
  final String? denyReason;
}

class ProviderActivationManager {
  ProviderActivationManager()
    : _states = {
        for (final t in ProviderType.values)
          t: ProviderState(
            type: t,
            enabled: false,
            confirmedByGenuineTap: false,
          ),
      };

  final Map<ProviderType, ProviderState> _states;

  /// The untrusted local app that overlays the enablement toggle and later
  /// drives the granted capability.
  static const String attackerPackage = 'com.evil.overlay';

  /// The set of callers the app actually trusts to drive its capabilities.
  static const Set<String> trustedCallers = {'com.dvma.app'};

  ProviderState stateOf(ProviderType type) => _states[type]!;

  bool isEnabled(ProviderType type) => _states[type]!.enabled;

  /// VULN: enable the app as [type] regardless of whether the confirming tap
  /// was obscured by an overlay. The system never verifies the tap was
  /// genuine, so a tapjack coerces the user into granting a system provider.
  EnablementResult enable(ProviderType type, {bool obscuredByOverlay = true}) {
    // No FLAG_WINDOW_IS_OBSCURED check: the toggle flips even under an overlay.
    _states[type] = _states[type]!.copyWith(
      enabled: true,
      confirmedByGenuineTap: !obscuredByOverlay,
    );
    return EnablementResult(
      type: type,
      enabled: true,
      coerced: obscuredByOverlay,
    );
  }

  /// SECURE contrast: refuse enablement when the confirming tap was obscured by
  /// an overlay (FLAG_WINDOW_IS_OBSCURED) or otherwise lacks a genuine
  /// user-confirmation record. Only a real, un-obscured tap enables the
  /// provider.
  EnablementResult enableSafe(
    ProviderType type, {
    bool obscuredByOverlay = true,
  }) {
    if (obscuredByOverlay) {
      return EnablementResult(
        type: type,
        enabled: _states[type]!.enabled,
        coerced: false,
        denyReason:
            'confirming tap was obscured by an overlay '
            '(FLAG_WINDOW_IS_OBSCURED) - refusing to enable ${type.label}',
      );
    }
    _states[type] = _states[type]!.copyWith(
      enabled: true,
      confirmedByGenuineTap: true,
    );
    return EnablementResult(type: type, enabled: true, coerced: false);
  }

  /// VULN: drive the granted capability for [caller] with no re-check. Because
  /// the provider is enabled (possibly via coercion), any untrusted caller
  /// becomes the principal of a confused deputy.
  InvocationResult invoke(ProviderType type, String caller) {
    final state = _states[type]!;
    if (!state.enabled) {
      return InvocationResult(
        type: type,
        caller: caller,
        performed: false,
        confusedDeputy: false,
        denyReason: 'provider not enabled',
      );
    }
    final untrusted = !trustedCallers.contains(caller);
    return InvocationResult(
      type: type,
      caller: caller,
      performed: true,
      // The deputy is confused when enablement was coerced OR the caller is
      // untrusted: either way the capability runs for someone it should not.
      confusedDeputy: untrusted || !state.confirmedByGenuineTap,
    );
  }

  /// SECURE contrast: re-check that enablement was genuinely confirmed AND that
  /// the caller is trusted before driving the capability.
  InvocationResult invokeSafe(ProviderType type, String caller) {
    final state = _states[type]!;
    if (!state.enabled || !state.confirmedByGenuineTap) {
      return InvocationResult(
        type: type,
        caller: caller,
        performed: false,
        confusedDeputy: false,
        denyReason:
            'provider not enabled via a genuine, un-obscured '
            'confirmation',
      );
    }
    if (!trustedCallers.contains(caller)) {
      return InvocationResult(
        type: type,
        caller: caller,
        performed: false,
        confusedDeputy: false,
        denyReason: 'caller $caller is not trusted to drive ${type.label}',
      );
    }
    return InvocationResult(
      type: type,
      caller: caller,
      performed: true,
      confusedDeputy: false,
    );
  }
}
