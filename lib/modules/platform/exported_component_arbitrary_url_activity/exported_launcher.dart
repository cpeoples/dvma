/// Exported Component -> Arbitrary URL / Activity Launch helper.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-749): an exported component accepts
/// attacker-supplied extras naming a URL and/or an activity target and opens
/// whatever is named - with the victim app's identity/privileges. Because the
/// component is exported and applies no allowlist, another app can point it at
/// an arbitrary URL or, worse, a privileged INTERNAL activity that is only
/// meant to be reachable in-process (the ABEMA CVE-2024-28745 / Samsung Members
/// CVE-2026-20985 & CVE-2025-21079 class).
///
/// This is an offline + deterministic simulation of the real mechanism: the
/// "Intent" is a plain `Map<String, String>` of extras and "opening" returns a
/// descriptor of what would be launched rather than performing a real launch.
/// A test can assert [handleExternalIntent] opens the arbitrary target while
/// [handleExternalIntentSafe] rejects it.
class ExportedLauncher {
  ExportedLauncher._();

  /// Activities the app declares as internal/privileged - never meant to be
  /// reachable from another app.
  static const Set<String> internalActivities = {
    'InternalAdminActivity',
    'DebugConsoleActivity',
    'SessionExportActivity',
  };

  /// Activities that are safe to reach from an external intent.
  static const Set<String> publicActivities = {
    'MainActivity',
    'ShareReceiverActivity',
  };

  /// First-party https origins the app is willing to open externally.
  static const Set<String> allowedOrigins = {'https://app.dvma.example'};

  /// VULN: exported handler that opens whatever URL/activity the extras name,
  /// with this app's privileges. No allowlist, so an arbitrary URL or a
  /// privileged internal activity is launched.
  static LaunchResult handleExternalIntent(Map<String, String> extras) {
    final activity = extras['activity'];
    if (activity != null && activity.isNotEmpty) {
      final privileged = internalActivities.contains(activity);
      return LaunchResult(
        opened: true,
        target: activity,
        privileged: privileged,
        description:
            'opened activity "$activity" with app privileges'
            '${privileged ? ' (INTERNAL/privileged)' : ''}',
      );
    }
    final target = extras['target'];
    if (target != null && target.isNotEmpty) {
      return LaunchResult(
        opened: true,
        target: target,
        privileged: false,
        description: 'opened URL "$target" in the app context',
      );
    }
    return const LaunchResult(
      opened: false,
      target: '',
      privileged: false,
      description: 'no target supplied',
    );
  }

  /// SECURE contrast: only permit an allowlist of public activities and
  /// first-party https URLs. Internal activities and arbitrary URLs are
  /// rejected before anything is launched.
  static LaunchResult handleExternalIntentSafe(Map<String, String> extras) {
    final activity = extras['activity'];
    if (activity != null && activity.isNotEmpty) {
      if (!publicActivities.contains(activity)) {
        return LaunchResult(
          opened: false,
          target: activity,
          privileged: false,
          description:
              'rejected: "$activity" is not an exported public '
              'activity',
        );
      }
      return LaunchResult(
        opened: true,
        target: activity,
        privileged: false,
        description: 'opened public activity "$activity"',
      );
    }
    final target = extras['target'];
    if (target != null && target.isNotEmpty) {
      final uri = Uri.tryParse(target);
      final origin = uri == null ? null : '${uri.scheme}://${uri.host}';
      if (uri == null ||
          uri.scheme.toLowerCase() != 'https' ||
          !allowedOrigins.contains(origin)) {
        return LaunchResult(
          opened: false,
          target: target,
          privileged: false,
          description: 'rejected: URL not a first-party https origin',
        );
      }
      return LaunchResult(
        opened: true,
        target: target,
        privileged: false,
        description: 'opened first-party URL "$target"',
      );
    }
    return const LaunchResult(
      opened: false,
      target: '',
      privileged: false,
      description: 'no target supplied',
    );
  }
}

/// Outcome of a simulated external-intent launch.
class LaunchResult {
  const LaunchResult({
    required this.opened,
    required this.target,
    required this.privileged,
    required this.description,
  });

  /// Whether the target was actually opened.
  final bool opened;

  /// The resolved URL/activity that was (or would be) opened.
  final String target;

  /// Whether the opened target was a privileged internal activity.
  final bool privileged;

  /// Human-readable effect of the launch.
  final String description;
}
