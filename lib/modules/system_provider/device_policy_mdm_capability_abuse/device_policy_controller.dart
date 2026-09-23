/// Device Policy / MDM Capability Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-269 / CWE-841): a Device Admin /
/// DevicePolicyManager receiver is a device-wide policy authority (it can wipe
/// data, disable the camera, weaken the password policy, etc.). When it applies
/// policy changes WITHOUT verifying that the caller is the currently-registered
/// active admin, and WITHOUT validating the policy parameters, an app-controlled
/// or untrusted caller can escalate privilege - e.g. trigger a device wipe or
/// weaken password quality (Android DevicePolicyManagerService logic-flaw
/// CVE-2025-48553 class).
///
/// This is an offline + deterministic SIMULATION. [DevicePolicyController]
/// tracks the registered active admin and a set of policy values. The
/// vulnerable [applyPolicy] applies changes for any caller and never validates
/// the parameter; the secure [applyPolicySafe] verifies the caller is the
/// active admin AND validates the parameter before applying.
library;

/// A device-wide policy a Device Admin can set.
enum DevicePolicy { disableCamera, wipeData, setPasswordQuality }

extension DevicePolicyInfo on DevicePolicy {
  String get label {
    switch (this) {
      case DevicePolicy.disableCamera:
        return 'disable-camera';
      case DevicePolicy.wipeData:
        return 'wipe-data';
      case DevicePolicy.setPasswordQuality:
        return 'set-password-quality';
    }
  }
}

/// The outcome of applying a policy change.
class PolicyResult {
  const PolicyResult({
    required this.callerPackage,
    required this.policy,
    required this.value,
    required this.applied,
    required this.callerIsActiveAdmin,
    this.denyReason,
  });

  /// The caller that requested the policy change.
  final String callerPackage;

  final DevicePolicy policy;

  /// The requested value (e.g. 'true' / password-quality rank).
  final Object? value;

  /// Whether the policy change was applied.
  final bool applied;

  /// Whether the caller is the registered active admin.
  final bool callerIsActiveAdmin;

  /// Why the secure flow refused.
  final String? denyReason;
}

class DevicePolicyController {
  DevicePolicyController({this.activeAdmin = registeredAdmin});

  /// The single registered active device-admin.
  static const String registeredAdmin = 'com.dvma.mdm';

  /// An untrusted app that never completed device-admin registration.
  static const String attackerPackage = 'com.evil.mdm';

  /// Password-quality ranks (higher == stronger). Anything below
  /// [minPasswordQuality] weakens the device below policy.
  static const int passwordQualityWeak = 0;
  static const int passwordQualityAlphanumeric = 3;
  static const int minPasswordQuality = passwordQualityAlphanumeric;

  final String activeAdmin;

  final Map<DevicePolicy, Object?> _policies = <DevicePolicy, Object?>{};

  Object? valueOf(DevicePolicy policy) => _policies[policy];

  bool _isActiveAdmin(String caller) => caller == activeAdmin;

  /// VULN: apply the policy for ANY caller with no validation. Because the
  /// caller is never checked against the registered active admin and the value
  /// is never validated, an untrusted caller can trigger a device wipe or push
  /// a weak password-quality value.
  PolicyResult applyPolicy(
    String callerPackage,
    DevicePolicy policy,
    Object? value,
  ) {
    _policies[policy] = value;
    return PolicyResult(
      callerPackage: callerPackage,
      policy: policy,
      value: value,
      applied: true,
      callerIsActiveAdmin: _isActiveAdmin(callerPackage),
    );
  }

  /// SECURE contrast: verify the caller is the registered active admin AND
  /// validate the parameter (e.g. reject a password-quality below the minimum)
  /// before applying. Untrusted callers and invalid parameters are refused.
  PolicyResult applyPolicySafe(
    String callerPackage,
    DevicePolicy policy,
    Object? value,
  ) {
    if (!_isActiveAdmin(callerPackage)) {
      return PolicyResult(
        callerPackage: callerPackage,
        policy: policy,
        value: value,
        applied: false,
        callerIsActiveAdmin: false,
        denyReason:
            'caller $callerPackage is not the registered active admin '
            '($registeredAdmin) - refusing ${policy.label}',
      );
    }
    if (policy == DevicePolicy.setPasswordQuality) {
      final rank = value is int ? value : -1;
      if (rank < minPasswordQuality) {
        return PolicyResult(
          callerPackage: callerPackage,
          policy: policy,
          value: value,
          applied: false,
          callerIsActiveAdmin: true,
          denyReason:
              'invalid parameter: password quality $value is below '
              'minimum ($minPasswordQuality) - refusing to weaken policy',
        );
      }
    }
    _policies[policy] = value;
    return PolicyResult(
      callerPackage: callerPackage,
      policy: policy,
      value: value,
      applied: true,
      callerIsActiveAdmin: true,
    );
  }
}
