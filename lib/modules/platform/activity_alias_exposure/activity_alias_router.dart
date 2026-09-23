/// Activity Alias Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-200 / CWE-284): a protected/internal
/// Activity (`android:exported="false"`, guarded by a permission) is left
/// reachable through an `<activity-alias>` that is itself `exported="true"` and
/// declares no permission. Because an alias's export/permission attributes
/// stand on their own and do not inherit the target's, an attacker can launch
/// the sensitive target THROUGH the alias even though the real component looks
/// protected. This is a manifest-level, deterministic misconfiguration.
///
/// This is an offline SIMULATION. [ActivityAliasRouter] models a target
/// Activity with its own protection and an alias pointing at it with its own
/// flags. The vulnerable [launchViaAlias] reaches the target through an
/// exported, unprotected alias; the secure [launchViaAliasSafe] makes the alias
/// echo the target's protection (not exported / same permission), refusing the
/// external launch.
library;

/// A component's manifest protection: export flag + optional permission.
class ComponentProtection {
  const ComponentProtection({
    required this.exported,
    required this.requiredPermission,
  });

  /// Whether the component is reachable from other apps.
  final bool exported;

  /// A permission the launcher must hold, or null for none.
  final String? requiredPermission;
}

/// The outcome of attempting to launch the target via the alias.
class AliasLaunchResult {
  const AliasLaunchResult({
    required this.callerPackage,
    required this.launched,
    required this.targetProtected,
    required this.aliasBypassedProtection,
    this.denyReason,
  });

  /// The package attempting the launch through the alias.
  final String callerPackage;

  /// Whether the sensitive target activity was actually reached.
  final bool launched;

  /// Whether the underlying target is itself protected (not exported /
  /// permission-guarded).
  final bool targetProtected;

  /// True when a protected target was reached through the alias despite the
  /// target's own protection - the hit.
  final bool aliasBypassedProtection;

  /// Why the secure path refused the launch.
  final String? denyReason;
}

class ActivityAliasRouter {
  /// The sensitive internal target activity.
  static const String targetActivity = 'com.dvma.app.AdminSettingsActivity';

  /// The alias that routes to the protected target.
  static const String aliasName = 'com.dvma.app.PublicShortcutAlias';

  /// The signature permission that guards the real target.
  static const String targetPermission =
      'com.dvma.app.permission.ADMIN_SETTINGS';

  /// An external app that launches the target through the alias.
  static const String attackerPackage = 'com.evil.launcher';

  /// The target's real protection: internal-only, permission-guarded.
  static const ComponentProtection targetProtection = ComponentProtection(
    exported: false,
    requiredPermission: targetPermission,
  );

  /// Whether [callerPackage] holds the target's signature permission. Only the
  /// app's own package is same-signature here.
  bool _holdsPermission(String callerPackage) =>
      callerPackage == 'com.dvma.app';

  /// VULN: the alias is exported with no permission of its own. Since alias
  /// attributes do not inherit the target's, launching the alias routes an
  /// external caller straight to the protected target activity.
  AliasLaunchResult launchViaAlias(String callerPackage) {
    const alias = ComponentProtection(exported: true, requiredPermission: null);

    // Alias is world-reachable and demands nothing -> external launch reaches
    // the protected target.
    final reached = alias.exported;
    return AliasLaunchResult(
      callerPackage: callerPackage,
      launched: reached,
      targetProtected:
          !targetProtection.exported ||
          targetProtection.requiredPermission != null,
      aliasBypassedProtection: reached,
    );
  }

  /// SECURE contrast: the alias echoes the target's protection - not exported
  /// (or requiring the same signature permission). An external caller without
  /// the permission is refused, so the alias cannot bypass the target's guard.
  AliasLaunchResult launchViaAliasSafe(String callerPackage) {
    const alias = ComponentProtection(
      exported: false,
      requiredPermission: targetPermission,
    );

    // Not exported: only same-app callers reach it; even if exported, the
    // permission must be held.
    final external = callerPackage != 'com.dvma.app';
    if (!alias.exported && external) {
      return AliasLaunchResult(
        callerPackage: callerPackage,
        launched: false,
        targetProtected: true,
        aliasBypassedProtection: false,
        denyReason:
            'alias mirrors target: exported=false - external caller '
            '$callerPackage cannot reach $targetActivity',
      );
    }
    if (alias.requiredPermission != null && !_holdsPermission(callerPackage)) {
      return AliasLaunchResult(
        callerPackage: callerPackage,
        launched: false,
        targetProtected: true,
        aliasBypassedProtection: false,
        denyReason:
            'alias requires ${alias.requiredPermission} - caller '
            '$callerPackage does not hold it',
      );
    }
    return AliasLaunchResult(
      callerPackage: callerPackage,
      launched: true,
      targetProtected: true,
      aliasBypassedProtection: false,
    );
  }
}
