import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Exported Android Components.
///
/// Activities/services/receivers exported with no permission checks.
class ExportedAndroidComponentsScreen extends StatefulWidget {
  const ExportedAndroidComponentsScreen({super.key});

  static const String vulnId = 'exported_android_components';

  @override
  State<ExportedAndroidComponentsScreen> createState() =>
      _ExportedAndroidComponentsScreenState();
}

class _ExportedAndroidComponentsScreenState
    extends State<ExportedAndroidComponentsScreen> {
  // Mirrors AndroidManifest.xml: components exported with no permission guard,
  // so any app (drozer/adb) can start them directly.
  static const List<Map<String, String>> _components = [
    {
      'component': 'AdminActivity',
      'exported': 'true',
      'permission': 'none',
      'effect': 'opens admin panel without auth',
    },
    {
      'component': 'ExportReceiver',
      'exported': 'true',
      'permission': 'none',
      'effect': 'triggers data export via broadcast',
    },
    {
      'component': 'DebugService',
      'exported': 'true',
      'permission': 'none',
      'effect': 'runs privileged debug commands',
    },
  ];

  String? _invoked;
  String? _nativeApplied;

  Future<void> _invoke() async {
    // In-app model of the manifest-level flaw (works everywhere, incl. tests).
    final simulated =
        'adb shell am start -n com.dvma/.AdminActivity\n'
        '-> AdminActivity launched (exported=true, no permission) - admin '
        'panel shown to any caller.';

    // On Android, actively start DVMA's real exported AdminActivity in-process
    // (the same startActivity path adb/drozer/a separate app hits) and read
    // back the caller it recorded.
    final applied = await ComponentIpcBridge.startAdminActivity();
    if (applied != null) {
      await DvmaEvidence.record(
        ExportedAndroidComponentsScreen.vulnId,
        'exported-activity-reached',
        'exported AdminActivity reached: $applied',
      );
    }

    setState(() {
      _invoked = simulated;
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ExportedAndroidComponentsScreen.vulnId,
      title: 'Exported Android Components',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Activities, receivers, and services are exported with no permission '
          'guard, so any installed app (or adb/drozer) can start them directly '
          'and reach privileged flows. This is a manifest-level flaw; the table '
          'mirrors the vulnerable declarations. On Android DVMA declares an '
          'exported AdminActivity; this screen starts it in-process by '
          'component name (the same startActivity path adb/drozer/a separate '
          'app hits) and reads back the caller it recorded - reaching an '
          'internal-only screen with no permission guard.',
      children: [
        EvidencePanel(
          label: 'exported components (AndroidManifest.xml)',
          value: _components
              .map(
                (c) =>
                    '${c['component']}: exported=${c['exported']}, '
                    'permission=${c['permission']} -> ${c['effect']}',
              )
              .join('\n'),
        ),
        DemoActionButton(label: 'Invoke from another app', onPressed: _invoke),
        if (_invoked != null)
          EvidencePanel(label: 'external invocation', value: _invoked!),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'exported AdminActivity reached in-process',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
