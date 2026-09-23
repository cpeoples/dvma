/// Telephony Capability Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-926 / CWE-284): a loosely-guarded /
/// exported Telecom-like component lets an untrusted caller drive a telephony
/// capability (place a call, send an SMS, register/manipulate a phone account)
/// with no per-invocation permission check. A local app therefore dials a
/// premium-rate number, sends an SMS, or registers a phone account on the
/// user's behalf (Android Telecom permission-bypass CVE-2026-28615 class).
///
/// This is an offline + deterministic SIMULATION. [TelephonyGateway] exposes
/// capabilities to a [TelephonyCaller]. The vulnerable [invoke] runs regardless
/// of caller trust / declared permission; the secure [invokeSafe] requires the
/// caller to hold the matching permission AND a per-invocation user
/// confirmation for sensitive actions.
library;

/// The telephony capabilities the gateway can drive.
enum TelephonyCapability { placeCall, sendSms, registerPhoneAccount }

extension TelephonyCapabilityMeta on TelephonyCapability {
  String get label {
    switch (this) {
      case TelephonyCapability.placeCall:
        return 'place-call';
      case TelephonyCapability.sendSms:
        return 'send-sms';
      case TelephonyCapability.registerPhoneAccount:
        return 'register-phone-account';
    }
  }

  /// The Android permission the capability nominally requires.
  String get requiredPermission {
    switch (this) {
      case TelephonyCapability.placeCall:
        return 'android.permission.CALL_PHONE';
      case TelephonyCapability.sendSms:
        return 'android.permission.SEND_SMS';
      case TelephonyCapability.registerPhoneAccount:
        return 'android.permission.REGISTER_SIM_SUBSCRIPTION';
    }
  }

  /// Whether the capability is sensitive enough to demand user confirmation.
  bool get sensitive => true;
}

/// A caller invoking the gateway.
class TelephonyCaller {
  const TelephonyCaller({required this.package, required this.heldPermissions});

  final String package;

  /// The permissions the caller actually holds.
  final Set<String> heldPermissions;
}

/// The outcome of driving a telephony capability.
class TelephonyResult {
  const TelephonyResult({
    required this.capability,
    required this.caller,
    required this.arg,
    required this.performed,
    required this.abused,
    this.denyReason,
  });

  final TelephonyCapability capability;
  final String caller;

  /// The action argument (dialed number, SMS destination, account id).
  final String arg;

  /// Whether the telephony action was carried out.
  final bool performed;

  /// True when the action ran for a caller lacking the permission - the hit.
  final bool abused;

  /// Why the secure gateway refused.
  final String? denyReason;
}

class TelephonyGateway {
  const TelephonyGateway();

  /// An untrusted local app with no telephony permissions.
  static const TelephonyCaller untrustedCaller = TelephonyCaller(
    package: 'com.evil.dialer',
    heldPermissions: <String>{},
  );

  /// The premium-rate number the attacker dials.
  static const String premiumNumber = '+1-900-555-0142 (premium-rate)';

  /// VULN: perform the requested capability with no per-invocation permission
  /// check. The exported Telecom component trusts whatever intent arrives, so
  /// an untrusted caller dials a premium number / sends SMS / registers a
  /// phone account.
  TelephonyResult invoke(
    TelephonyCaller caller,
    TelephonyCapability capability,
    String arg,
  ) {
    final holdsPerm = caller.heldPermissions.contains(
      capability.requiredPermission,
    );
    return TelephonyResult(
      capability: capability,
      caller: caller.package,
      arg: arg,
      performed: true,
      abused: !holdsPerm,
    );
  }

  /// SECURE contrast: require the caller to hold the matching permission AND a
  /// per-invocation user confirmation for sensitive actions.
  TelephonyResult invokeSafe(
    TelephonyCaller caller,
    TelephonyCapability capability,
    String arg, {
    bool userConfirmed = false,
  }) {
    if (!caller.heldPermissions.contains(capability.requiredPermission)) {
      return TelephonyResult(
        capability: capability,
        caller: caller.package,
        arg: arg,
        performed: false,
        abused: false,
        denyReason:
            'caller ${caller.package} lacks '
            '${capability.requiredPermission}',
      );
    }
    if (capability.sensitive && !userConfirmed) {
      return TelephonyResult(
        capability: capability,
        caller: caller.package,
        arg: arg,
        performed: false,
        abused: false,
        denyReason:
            'sensitive ${capability.label} requires per-invocation '
            'user confirmation',
      );
    }
    return TelephonyResult(
      capability: capability,
      caller: caller.package,
      arg: arg,
      performed: true,
      abused: false,
    );
  }
}
