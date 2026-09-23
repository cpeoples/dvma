import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Debuggable Release Build.
///
/// Reports the app's real debuggability instead of a hardcoded claim: a
/// debug/profile build is debuggable (`run-as` / jdwp attach works), which is
/// the honest, verifiable state.
class DebuggableReleaseBuildScreen extends StatefulWidget {
  const DebuggableReleaseBuildScreen({super.key});

  static const String vulnId = 'debuggable_release_build';

  @override
  State<DebuggableReleaseBuildScreen> createState() =>
      _DebuggableReleaseBuildScreenState();
}

class _DebuggableReleaseBuildScreenState
    extends State<DebuggableReleaseBuildScreen> {
  // Computed from the real build mode, not hardcoded. A debug/profile build is
  // debuggable; a release build is not. This mirrors the actual binary a
  // trainee inspects (Android android:debuggable via jadx; iOS get-task-allow
  // via codesign -d --entitlements).
  static const bool debuggable = !kReleaseMode;
  static const bool jsDebuggingEnabled = !kReleaseMode;
  static final String buildMode = kReleaseMode
      ? 'release'
      : kProfileMode
      ? 'profile'
      : 'debug';

  // Platform-aware phrasing (Android android:debuggable / adb+jdwp vs iOS
  // get-task-allow / lldb).
  final PlatformLingo _lingo = PlatformLingo.current();

  String get _debugFlagName =>
      _lingo.pick(ios: 'get-task-allow', android: 'android:debuggable');

  String get _verifyCmd => _lingo.pick(
    ios:
        'codesign -d --entitlements - Runner.app   '
        '# look for get-task-allow=true (allows lldb attach)',
    android:
        'adb shell run-as com.dvma id   # (works only when '
        'debuggable) - or inspect android:debuggable via jadx on the '
        'built APK',
  );

  String get _attachTool => _lingo.pick(
    ios: 'an lldb attach',
    android: '`adb shell run-as` and a jdwp/jdb attach',
  );

  String? _result;

  void _attach() {
    // Mirror the real build mode + verification command to the evidence sink.
    DvmaEvidence.record(
      DebuggableReleaseBuildScreen.vulnId,
      'debuggable',
      'build mode: $buildMode ($_debugFlagName=$debuggable) - '
          'verify: $_verifyCmd',
    );

    setState(
      () => _result = debuggable
          ? 'This is a "$buildMode" build: $_debugFlagName=true, so '
                '$_attachTool succeed - an inspector can read memory, set '
                'breakpoints and dump variables.\nverify: $_verifyCmd'
          : 'This is a release build: $_debugFlagName=false, so debugger '
                'attach is refused. Build/run in debug (or profile) to observe '
                'the debuggable path.\nverify: $_verifyCmd',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DebuggableReleaseBuildScreen.vulnId,
      title: 'Debuggable Release Build',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'A build that ships debuggable (Android android:debuggable="true" / '
          'iOS get-task-allow entitlement) lets anyone attach a debugger to '
          'inspect memory, set breakpoints and dump secrets at runtime. This '
          'screen reports the real build mode (from kReleaseMode) rather than a '
          'hardcoded claim: a debug/profile build IS debuggable, so $_attachTool '
          'work - confirm the $_debugFlagName flag with $_verifyCmd.',
      children: [
        EvidencePanel(
          label: 'build flags (real build mode)',
          value:
              'buildMode = $buildMode\n'
              '$_debugFlagName = $debuggable\n'
              'jsDebuggingEnabled = $jsDebuggingEnabled',
        ),
        DemoActionButton(label: 'Attach debugger', onPressed: _attach),
        if (_result != null)
          EvidencePanel(label: 'debugger attach', value: _result!),
      ],
    );
  }
}
