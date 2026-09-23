/// Default-Role / Role-Holder Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-346 origin validation / CWE-940 improper
/// verification of source / CWE-284 improper access control, Android
/// dynamic-role class): the app resolves a system role (default browser /
/// dialer / SMS / wallet / credential provider / NFC handler) with
/// `PackageManager.resolveActivity()` or an implicit intent and TRUSTS
/// whichever activity the OS returns. It then hands that target a sensitive
/// URI / credential / IPC WITHOUT checking the current `RoleManager` role
/// holder or pinning the target's package + signature. A co-resident app that
/// simply registers the matching intent-filter with a higher priority becomes
/// the resolved "default" and receives the secret.
///
/// This is an offline + deterministic SIMULATION. [RoleResolver] models the set
/// of installed apps, each declaring whether it registered the role's
/// intent-filter and what signature it was signed with. The vulnerable
/// [delegateSecret] resolves the highest-priority matching app and delivers the
/// secret to it with no verification. The secure [delegateSecretSafe] consults
/// the authoritative RoleManager holder AND pins the expected package +
/// signature, refusing to deliver to an unexpected holder.
library;

/// A single installed app that may declare a role's intent-filter.
class InstalledApp {
  const InstalledApp({
    required this.package,
    required this.declaresRoleIntentFilter,
    required this.signature,
    required this.priority,
  });

  /// The app's package name.
  final String package;

  /// The signing certificate identity the app was signed with.
  final String signature;

  /// Whether this app declares the matching role intent-filter.
  final bool declaresRoleIntentFilter;

  /// Intent-filter priority; a co-resident attacker sets this high to win
  /// implicit resolution.
  final int priority;
}

/// The outcome of delegating a secret to a resolved role holder.
class RoleDelegationResult {
  const RoleDelegationResult({
    required this.role,
    required this.delivered,
    required this.roleHolderVerified,
    required this.recipientPackage,
    this.deliveredSecret,
    this.denyReason,
  });

  /// The system role that was resolved (e.g. `browser`).
  final String role;

  /// Whether the secret was actually handed to the recipient.
  final bool delivered;

  /// Whether the recipient was verified against the authoritative RoleManager
  /// holder and a pinned signature before delivery.
  final bool roleHolderVerified;

  /// The package that received (or would have received) the secret.
  final String recipientPackage;

  /// The secret value delivered to the recipient, when [delivered] is true.
  final String? deliveredSecret;

  /// Why the secure path refused to delegate.
  final String? denyReason;
}

class RoleResolver {
  /// The role being resolved in this demo.
  static const String role = 'browser';

  /// The sensitive value the app delegates to the role holder (e.g. a signed
  /// deep link carrying a one-time credential).
  static const String secret = 'onetime-credential://token=8b3f-DE21-A907';

  /// The app the user actually trusts as the role holder, pinned by signature.
  static const String trustedDefaultPackage = 'com.android.chrome';
  static const String trustedSignature = 'sig:GOOGLE-RELEASE-38F1';

  /// A co-resident malicious app that registered the same intent-filter.
  static const String attackerPackage = 'com.evil.roletrap';
  static const String attackerSignature = 'sig:SELFSIGNED-ATTACKER';

  /// The RoleManager's authoritative current holder for [role]. In a real
  /// system this is what `RoleManager.getRoleHolders()` returns; the attacker
  /// cannot forge it, only win implicit intent resolution.
  static const String roleManagerHolder = trustedDefaultPackage;

  /// The installed apps that resolve for [role]. The attacker declares the
  /// filter with a higher priority than the legitimate default, so it wins
  /// `resolveActivity()`.
  final List<InstalledApp> installedApps;

  RoleResolver({List<InstalledApp>? installedApps})
    : installedApps =
          installedApps ??
          const [
            InstalledApp(
              package: trustedDefaultPackage,
              declaresRoleIntentFilter: true,
              signature: trustedSignature,
              priority: 0,
            ),
            InstalledApp(
              package: attackerPackage,
              declaresRoleIntentFilter: true,
              signature: attackerSignature,
              priority: 100,
            ),
          ];

  /// Mimics `PackageManager.resolveActivity()` / implicit-intent resolution:
  /// return the highest-priority app that declares the role's intent-filter.
  /// This is attacker-influenceable and is not the authoritative role holder.
  InstalledApp? resolve(String requestedRole) {
    final matches =
        installedApps.where((a) => a.declaresRoleIntentFilter).toList()
          ..sort((a, b) => b.priority.compareTo(a.priority));
    return matches.isEmpty ? null : matches.first;
  }

  /// VULN: resolve the role via implicit intent and hand the secret to whatever
  /// activity comes back, trusting resolution as if it were authorization. A
  /// co-resident app that out-prioritizes the real default silently receives
  /// the secret. No RoleManager check, no signature pin.
  RoleDelegationResult delegateSecret(String requestedRole) {
    final target = resolve(requestedRole);
    if (target == null) {
      return const RoleDelegationResult(
        role: role,
        delivered: false,
        roleHolderVerified: false,
        recipientPackage: '(none)',
        denyReason: 'no activity resolved',
      );
    }
    return RoleDelegationResult(
      role: requestedRole,
      delivered: true,
      roleHolderVerified: false,
      recipientPackage: target.package,
      deliveredSecret: secret,
    );
  }

  /// SECURE contrast: resolve, then verify the resolved target IS the
  /// authoritative RoleManager holder AND that its package + signature match
  /// the pinned expected default. Refuse to deliver to any unexpected holder.
  RoleDelegationResult delegateSecretSafe(String requestedRole) {
    final target = resolve(requestedRole);
    if (target == null) {
      return const RoleDelegationResult(
        role: role,
        delivered: false,
        roleHolderVerified: true,
        recipientPackage: '(none)',
        denyReason: 'no activity resolved',
      );
    }
    // Check 1: resolved target must equal the RoleManager holder of record.
    if (target.package != roleManagerHolder) {
      return RoleDelegationResult(
        role: requestedRole,
        delivered: false,
        roleHolderVerified: true,
        recipientPackage: target.package,
        denyReason:
            'resolved ${target.package} is not RoleManager holder '
            '$roleManagerHolder - refusing delegation',
      );
    }
    // Check 2: pin the expected package + signature (defense in depth).
    if (target.package != trustedDefaultPackage ||
        target.signature != trustedSignature) {
      return RoleDelegationResult(
        role: requestedRole,
        delivered: false,
        roleHolderVerified: true,
        recipientPackage: target.package,
        denyReason: 'package/signature pin mismatch for ${target.package}',
      );
    }
    return RoleDelegationResult(
      role: requestedRole,
      delivered: true,
      roleHolderVerified: true,
      recipientPackage: target.package,
      deliveredSecret: secret,
    );
  }
}
