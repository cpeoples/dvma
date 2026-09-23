/// Custom Signature-Permission Squatting helper.
///
/// INTENTIONALLY VULNERABLE (CWE-732 / CWE-280 / CWE-284): an IPC component is
/// "protected" by a custom permission whose `protectionLevel` is `normal` or
/// `dangerous` rather than `signature`, OR by a permission NAME that a
/// malicious app can DEFINE FIRST (install-order squatting). A `normal`
/// permission is auto-granted to any app that requests it, and a squatted
/// permission is owned by the attacker with whatever weak level they choose -
/// so the guard the developer believes protects the interface is trivially
/// obtained or attacker-controlled, and the component is externally reachable.
/// This is a manifest-level, deterministic misconfiguration.
///
/// This is an offline SIMULATION. [CustomPermissionGuard] models a permission
/// declaration (name, protectionLevel, definer), a set of installed apps that
/// may hold or define it, and a guarded IPC call. The vulnerable [call] honors
/// a weak/squatted permission and lets the attacker through; the secure
/// [callSafe] requires `protectionLevel: signature` AND verifies the caller's
/// signing identity matches the app's, refusing the squatter.
library;

/// A permission's manifest protection level.
enum PermissionProtectionLevel { normal, dangerous, signature }

/// A declaration of a custom permission by some package.
class PermissionDeclaration {
  const PermissionDeclaration({
    required this.name,
    required this.level,
    required this.definerPackage,
  });

  /// The permission name string.
  final String name;

  /// The declared protection level.
  final PermissionProtectionLevel level;

  /// The package that defined (owns) this permission.
  final String definerPackage;
}

/// An installed app that may hold or define the permission.
class InstalledApp {
  const InstalledApp({
    required this.package,
    required this.signature,
    required this.requestsPermission,
  });

  /// The app's package name.
  final String package;

  /// The app's signing identity.
  final String signature;

  /// Whether the app requests the guarded permission in its manifest.
  final bool requestsPermission;
}

/// The outcome of an IPC call against the guarded component.
class GuardedCallResult {
  const GuardedCallResult({
    required this.callerPackage,
    required this.callAllowed,
    required this.guardEffective,
    required this.attackerHeldPermission,
    this.denyReason,
  });

  /// The package making the IPC call.
  final String callerPackage;

  /// Whether the guarded operation was allowed to run.
  final bool callAllowed;

  /// Whether the permission guard actually kept untrusted callers out.
  final bool guardEffective;

  /// True when the attacker was able to hold/obtain the guarding permission -
  /// the hit.
  final bool attackerHeldPermission;

  /// Why the secure path refused the call.
  final String? denyReason;
}

class CustomPermissionGuard {
  /// The custom permission name the developer relies on.
  static const String permissionName = 'com.dvma.app.permission.SYNC_ACCOUNTS';

  /// The protected operation exposed over IPC.
  static const String protectedOperation = 'readAccountSyncTokens';

  /// The app's own (legitimate) signing identity.
  static const String appSignature = 'SIG_DVMA_RELEASE';

  /// The attacker's signing identity - different from the app's.
  static const String attackerSignature = 'SIG_ATTACKER';

  /// The app's own package.
  static const String appPackage = 'com.dvma.app';

  /// The malicious co-installed package.
  static const String attackerPackage = 'com.evil.sync';

  /// VULN declaration: the developer declares the permission as `normal`, so
  /// the platform AUTO-GRANTS it to any app that requests it. (The
  /// install-order-squatting variant is equivalent: the attacker's definition
  /// with a weak level wins.)
  static const PermissionDeclaration weakDeclaration = PermissionDeclaration(
    name: permissionName,
    level: PermissionProtectionLevel.normal,
    definerPackage: appPackage,
  );

  /// SECURE declaration: `signature` level, so only same-signature apps are
  /// granted the permission at all.
  static const PermissionDeclaration signatureDeclaration =
      PermissionDeclaration(
        name: permissionName,
        level: PermissionProtectionLevel.signature,
        definerPackage: appPackage,
      );

  /// Whether [app] is granted [decl] by the platform's rules.
  bool _isGranted(PermissionDeclaration decl, InstalledApp app) {
    if (!app.requestsPermission) return false;
    switch (decl.level) {
      case PermissionProtectionLevel.normal:
      case PermissionProtectionLevel.dangerous:
        // normal is auto-granted; dangerous is user-granted and modeled as
        // obtainable by any requesting app in this offline simulation.
        return true;
      case PermissionProtectionLevel.signature:
        // Only apps signed with the definer's signature are granted.
        return app.signature == appSignature;
    }
  }

  /// VULN: guard the IPC call with the weak (`normal`) permission. The attacker
  /// merely declares `<uses-permission>` and is auto-granted, so the guard is
  /// ineffective and the protected operation runs for the attacker.
  GuardedCallResult call(InstalledApp caller) {
    final granted = _isGranted(weakDeclaration, caller);
    final external = caller.signature != appSignature;
    return GuardedCallResult(
      callerPackage: caller.package,
      callAllowed: granted,
      guardEffective: false,
      attackerHeldPermission: granted && external,
    );
  }

  /// SECURE contrast: require `protectionLevel: signature` AND verify the
  /// caller's signing identity matches the app's. A squatter with a different
  /// signature is never granted the permission and the call is refused.
  GuardedCallResult callSafe(InstalledApp caller) {
    final granted = _isGranted(signatureDeclaration, caller);
    final sameSignature = caller.signature == appSignature;
    if (!granted || !sameSignature) {
      return GuardedCallResult(
        callerPackage: caller.package,
        callAllowed: false,
        guardEffective: true,
        attackerHeldPermission: false,
        denyReason:
            '$permissionName is signature-level and caller '
            '${caller.package} (${caller.signature}) does not match the app '
            'signature $appSignature - $protectedOperation refused',
      );
    }
    return GuardedCallResult(
      callerPackage: caller.package,
      callAllowed: true,
      guardEffective: true,
      attackerHeldPermission: false,
    );
  }

  /// The malicious app as an installed, permission-requesting caller.
  static InstalledApp attackerApp() => const InstalledApp(
    package: attackerPackage,
    signature: attackerSignature,
    requestsPermission: true,
  );

  /// The app's own trusted caller.
  static InstalledApp trustedApp() => const InstalledApp(
    package: appPackage,
    signature: appSignature,
    requestsPermission: true,
  );
}
