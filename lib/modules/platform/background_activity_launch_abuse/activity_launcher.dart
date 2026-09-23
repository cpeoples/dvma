/// Background Activity Launch Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-284 / CWE-862 / CWE-940): an untrusted / local
/// caller drives a BACKGROUND component to startActivity() and reaches a
/// security-sensitive UI - a phishing overlay, a task-hijack surface, a consent
/// dialog it can manipulate - because there is no background-activity-launch
/// (BAL) restriction (the Android background-activity-launch CVE-2025-26462
/// class).
///
/// This is an offline + deterministic simulation. [ActivityLauncher] tracks
/// whether the caller is currently in the foreground and whether it holds a
/// valid launch token. The vulnerable [launch] starts a security-sensitive
/// activity even from the background; the secure [launchSafe] enforces BAL
/// rules - the caller must be in the foreground OR present a valid launch token
/// - and refuses the background launch otherwise.
library;

/// A caller attempting to start an activity.
class LaunchCaller {
  const LaunchCaller({
    required this.package,
    required this.inForeground,
    this.launchToken,
  });

  final String package;

  /// Whether the caller currently has a foreground task / visible window.
  final bool inForeground;

  /// A token the system grants (e.g. a PendingIntent / recent user
  /// interaction) that legitimately authorizes a launch. Null when absent.
  final String? launchToken;
}

/// A target activity, possibly security-sensitive.
class TargetActivity {
  const TargetActivity({required this.name, required this.sensitive});

  final String name;

  /// Whether reaching this activity is security-sensitive (consent dialog,
  /// login overlay, etc.).
  final bool sensitive;
}

/// The outcome of a launch attempt.
class LaunchResult {
  const LaunchResult({
    required this.launched,
    required this.blocked,
    required this.activity,
    required this.callerForeground,
    required this.sensitive,
    this.denyReason,
  });

  /// Whether the activity was started.
  final bool launched;

  /// Whether the secure launcher refused (secure path).
  final bool blocked;

  /// The activity that was targeted.
  final String activity;

  /// Whether the caller was in the foreground at launch time.
  final bool callerForeground;

  /// Whether the target was security-sensitive.
  final bool sensitive;

  /// Why the secure launcher refused.
  final String? denyReason;

  /// True when a background caller reached a security-sensitive activity - the
  /// BAL-abuse hit.
  bool get backgroundLaunchAbuse => launched && !callerForeground && sensitive;
}

class ActivityLauncher {
  ActivityLauncher();

  /// The untrusted local caller driving the launch from the background.
  static const String attackerPackage = 'com.evil.localapp';

  /// A valid launch token the system mints on genuine user interaction.
  static const String validLaunchToken = 'bal-token-ok-5521';

  /// The security-sensitive activity the attacker wants to surface (a fake
  /// consent dialog / login overlay).
  static const TargetActivity fakeConsentDialog = TargetActivity(
    name: 'com.dvma/.ConsentDialogActivity',
    sensitive: true,
  );

  /// A background attacker with no launch token, the crafted caller.
  static const LaunchCaller backgroundAttacker = LaunchCaller(
    package: attackerPackage,
    inForeground: false,
  );

  /// VULN: start [activity] for [caller] with no BAL restriction. A background
  /// caller with no launch token still reaches the security-sensitive UI.
  LaunchResult launch(LaunchCaller caller, TargetActivity activity) {
    return LaunchResult(
      launched: true,
      blocked: false,
      activity: activity.name,
      callerForeground: caller.inForeground,
      sensitive: activity.sensitive,
    );
  }

  /// SECURE contrast: enforce BAL rules. The caller must be in the foreground
  /// OR present a valid launch token; a background caller with no token is
  /// refused before any security-sensitive activity is reached.
  LaunchResult launchSafe(LaunchCaller caller, TargetActivity activity) {
    final hasValidToken = caller.launchToken == validLaunchToken;
    if (!caller.inForeground && !hasValidToken) {
      return LaunchResult(
        launched: false,
        blocked: true,
        activity: activity.name,
        callerForeground: caller.inForeground,
        sensitive: activity.sensitive,
        denyReason:
            'background-activity-launch refused: caller ${caller.package} is '
            'not in the foreground and holds no valid launch token',
      );
    }
    return LaunchResult(
      launched: true,
      blocked: false,
      activity: activity.name,
      callerForeground: caller.inForeground,
      sensitive: activity.sensitive,
    );
  }
}
