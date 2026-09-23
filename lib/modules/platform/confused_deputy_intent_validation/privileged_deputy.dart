/// Confused-Deputy Intent Validation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-441 / CWE-863 / CWE-862): a PRIVILEGED
/// component (it can perform an action a normal app cannot, e.g. toggle a
/// protected setting) is exported and performs that action on behalf of a
/// caller after only a SUPERFICIAL Intent check - it inspects the requested
/// action string but never verifies the caller's identity/permission. A local,
/// unprivileged app crafts an Intent and the deputy carries out the privileged
/// operation for it (Android Settings CVE-2025-32326 / CVE-2025-32321
/// confused-deputy class).
///
/// This is an offline + deterministic simulation. [PrivilegedDeputy] models the
/// exported component; it returns whether the privileged action was performed
/// and for whom. Tests can assert an unprivileged caller succeeds on the vuln
/// path and is rejected on the secure path (caller permission check).
library;

/// An Intent arriving at the exported privileged component.
class DeputyRequest {
  const DeputyRequest({
    required this.callerPackage,
    required this.callerHoldsPermission,
    required this.action,
    required this.targetSetting,
  });

  /// The app that sent the Intent.
  final String callerPackage;

  /// Whether the caller actually holds the permission the action requires.
  final bool callerHoldsPermission;

  /// The requested privileged action (the only thing the vuln path checks).
  final String action;

  /// The protected setting the action would change.
  final String targetSetting;
}

/// The result of the deputy handling a request.
class DeputyResult {
  const DeputyResult({
    required this.performed,
    required this.onBehalfOf,
    required this.setting,
    this.denyReason,
  });

  /// Whether the privileged action was carried out.
  final bool performed;

  /// The caller the action was performed for (null if denied).
  final String? onBehalfOf;

  /// The setting that was changed (null if denied).
  final String? setting;

  /// Why the request was denied (secure path).
  final String? denyReason;

  /// True when the action ran for a caller that did not hold the permission.
  bool get abusedByUnprivileged => performed && onBehalfOf != null;
}

class PrivilegedDeputy {
  const PrivilegedDeputy._();

  /// The privileged action the deputy knows how to perform.
  static const String privilegedAction = 'com.dvma.action.WRITE_SECURE_SETTING';

  /// VULN: only checks that the ACTION string is one it handles, then performs
  /// the privileged operation. It never verifies the caller holds the required
  /// permission, so any local app becomes a confused deputy's principal.
  static DeputyResult handle(DeputyRequest req) {
    if (req.action != privilegedAction) {
      return const DeputyResult(
        performed: false,
        onBehalfOf: null,
        setting: null,
        denyReason: 'unknown action',
      );
    }
    // Superficial check passed -> perform the privileged action. No caller
    // identity/permission verification whatsoever.
    return DeputyResult(
      performed: true,
      onBehalfOf: req.callerPackage,
      setting: req.targetSetting,
    );
  }

  /// SECURE contrast: verify the caller actually holds the permission the
  /// privileged action requires BEFORE performing it. An unprivileged caller
  /// is rejected.
  static DeputyResult handleSafe(DeputyRequest req) {
    if (req.action != privilegedAction) {
      return const DeputyResult(
        performed: false,
        onBehalfOf: null,
        setting: null,
        denyReason: 'unknown action',
      );
    }
    if (!req.callerHoldsPermission) {
      return DeputyResult(
        performed: false,
        onBehalfOf: null,
        setting: null,
        denyReason: 'caller ${req.callerPackage} lacks required permission',
      );
    }
    return DeputyResult(
      performed: true,
      onBehalfOf: req.callerPackage,
      setting: req.targetSetting,
    );
  }
}
