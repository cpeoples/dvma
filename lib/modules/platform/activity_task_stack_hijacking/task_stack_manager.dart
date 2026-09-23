/// Activity Task Stack Hijacking helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1021 / CWE-451 / CWE-346, StrandHogg-style
/// task hijacking): loose task affinity and launch modes (a malicious Activity
/// declaring `singleTask` with a shared `taskAffinity` matching the victim, or
/// relying on `allowTaskReparenting`) let a malicious Activity insert itself
/// into a trusted app's task / back-stack. When the user returns to the victim
/// app they are shown the attacker's screen inside the victim's flow, enabling
/// phishing and UI-trust confusion. This is distinct from tapjacking: it is
/// TASK-STACK PLACEMENT, not a drawn overlay.
///
/// This is an offline + deterministic SIMULATION. [TaskStackManager] models the
/// device's tasks, each keyed by a `taskAffinity` and holding a back-stack of
/// activities. The vulnerable [launch] honours the malicious activity's spoofed
/// affinity / reparenting, so it lands atop the victim's task. The secure
/// [launchSafe] enforces a unique per-app affinity and disallows reparenting,
/// so the malicious activity gets its own task and never appears in the victim
/// flow.
library;

/// An activity declaration relevant to task placement.
class ActivityDeclaration {
  const ActivityDeclaration({
    required this.name,
    required this.package,
    required this.taskAffinity,
    required this.allowTaskReparenting,
  });

  /// The component name.
  final String name;

  /// The declaring package.
  final String package;

  /// The task affinity declared in the manifest. Sharing the victim's affinity
  /// is what lets the activity join the victim's task.
  final String taskAffinity;

  /// Whether the activity may be reparented into a task with a matching
  /// affinity (android:allowTaskReparenting).
  final bool allowTaskReparenting;
}

/// The outcome of launching an activity into the task stack.
class TaskLaunchResult {
  const TaskLaunchResult({
    required this.activity,
    required this.landedInTaskAffinity,
    required this.hijacked,
    required this.appearsInVictimTask,
    required this.topOfVictimStack,
    this.denyReason,
  });

  /// The launched activity.
  final ActivityDeclaration activity;

  /// The affinity of the task the activity actually landed in.
  final String landedInTaskAffinity;

  /// True when the malicious activity was placed into the victim's task - the
  /// StrandHogg hit.
  final bool hijacked;

  /// True when returning to the victim app surfaces the attacker screen.
  final bool appearsInVictimTask;

  /// The activity name now on top of the victim's back-stack.
  final String topOfVictimStack;

  /// Why the secure path isolated the launch.
  final String? denyReason;
}

class TaskStackManager {
  /// Device tasks keyed by affinity -> back-stack (bottom..top).
  final Map<String, List<ActivityDeclaration>> _tasks =
      <String, List<ActivityDeclaration>>{};

  /// The trusted victim app's package.
  static const String victimPackage = 'com.bank.trusted';

  /// The victim app's task affinity (default affinity == package name).
  static const String victimAffinity = 'com.bank.trusted';

  /// The malicious app's own package.
  static const String attackerPackage = 'com.evil.strandhogg';

  /// The victim app's legitimate main activity.
  static const ActivityDeclaration victimMain = ActivityDeclaration(
    name: 'com.bank.trusted.MainActivity',
    package: victimPackage,
    taskAffinity: victimAffinity,
    allowTaskReparenting: false,
  );

  /// The malicious phishing activity, declaring the VICTIM's affinity so it can
  /// slip into the victim's task (spoofed affinity + reparenting).
  static const ActivityDeclaration maliciousActivity = ActivityDeclaration(
    name: 'com.evil.strandhogg.PhishActivity',
    package: attackerPackage,
    taskAffinity: victimAffinity,
    allowTaskReparenting: true,
  );

  /// Seed the victim's task with its own main activity, as if the user had
  /// opened the trusted app.
  void seedVictimTask() {
    _tasks[victimAffinity] = <ActivityDeclaration>[victimMain];
  }

  List<ActivityDeclaration> victimStack() =>
      List.unmodifiable(_tasks[victimAffinity] ?? const []);

  /// VULN: place [activity] according to its declared affinity with no check
  /// that a task's affinity belongs to a different app. A malicious activity
  /// declaring the victim's affinity (and/or allowTaskReparenting) is pushed
  /// onto the victim's existing task, landing on top of the victim flow.
  TaskLaunchResult launch(ActivityDeclaration activity) {
    final affinity = activity.taskAffinity;
    final stack = _tasks.putIfAbsent(affinity, () => <ActivityDeclaration>[]);
    stack.add(activity);

    final victimStack = _tasks[victimAffinity] ?? const [];
    final onTopOfVictim =
        victimStack.isNotEmpty && identical(victimStack.last, activity);
    final foreign = activity.package != victimPackage;

    return TaskLaunchResult(
      activity: activity,
      landedInTaskAffinity: affinity,
      hijacked: onTopOfVictim && foreign,
      appearsInVictimTask: onTopOfVictim && foreign,
      topOfVictimStack: victimStack.isEmpty ? '(empty)' : victimStack.last.name,
    );
  }

  /// SECURE contrast: enforce a UNIQUE per-app task affinity and refuse
  /// reparenting a foreign activity into another app's task. A cross-package
  /// activity is forced into its own task (its real package affinity), so it
  /// can never surface inside the victim's flow.
  TaskLaunchResult launchSafe(ActivityDeclaration activity) {
    final foreign = activity.package != victimPackage;
    final requestsVictimTask = activity.taskAffinity == victimAffinity;

    // Force a foreign activity into its own package-scoped task regardless of
    // the affinity it declared.
    final effectiveAffinity = foreign
        ? activity.package
        : activity.taskAffinity;
    final stack = _tasks.putIfAbsent(
      effectiveAffinity,
      () => <ActivityDeclaration>[],
    );
    stack.add(activity);

    final victimStack = _tasks[victimAffinity] ?? const [];
    return TaskLaunchResult(
      activity: activity,
      landedInTaskAffinity: effectiveAffinity,
      hijacked: false,
      appearsInVictimTask: false,
      topOfVictimStack: victimStack.isEmpty ? '(empty)' : victimStack.last.name,
      denyReason: foreign && requestsVictimTask
          ? 'foreign activity ${activity.package} requested victim affinity '
                '"$victimAffinity" - forced into isolated task '
                '"$effectiveAffinity", reparenting disallowed'
          : null,
    );
  }
}
