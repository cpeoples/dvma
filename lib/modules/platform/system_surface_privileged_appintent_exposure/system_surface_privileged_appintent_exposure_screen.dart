import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_intent_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'app_intent_surface_router.dart';

/// System-Surface Privileged App-Intent Exposure.
///
/// An App Intent surfaced to many system entry points reaches a privileged
/// operation with no per-surface authorization.
class SystemSurfacePrivilegedAppintentExposureScreen extends StatefulWidget {
  const SystemSurfacePrivilegedAppintentExposureScreen({super.key});

  static const String vulnId = 'system_surface_privileged_appintent_exposure';

  @override
  State<SystemSurfacePrivilegedAppintentExposureScreen> createState() =>
      _SystemSurfacePrivilegedAppintentExposureScreenState();
}

class _SystemSurfacePrivilegedAppintentExposureScreenState
    extends State<SystemSurfacePrivilegedAppintentExposureScreen> {
  // A passive, lock-screen-reachable surface fires the privileged op.
  static const IntentSurface _surface = IntentSurface.control;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(SurfaceInvocationResult r) {
    final b = StringBuffer();
    b.writeln('surface            : ${r.surface.label}');
    b.writeln('intent             : ${r.intent.name}');
    b.writeln('sensitive          : ${r.intent.sensitive}');
    b.writeln('performed          : ${r.performed}');
    b.writeln('unauthorized surface: ${r.unauthorizedSurface}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const router = AppIntentSurfaceRouter();
    const intent = PrivilegedIntent.exportData;

    // VULN: a Control (reachable from the lock screen) fires "export data".
    final vuln = router.invokeFrom(_surface, intent);

    // SECURE: the Control surface is not allowlisted for sensitive intents.
    final secure = router.invokeFromSafe(_surface, intent);

    // real artifact: record the privileged intent fired from an unauthorized,
    // lock-screen-reachable system surface.
    await DvmaEvidence.record(
      SystemSurfacePrivilegedAppintentExposureScreen.vulnId,
      'surface-exposure',
      'surface=${vuln.surface.label} fired intent=${vuln.intent.name} '
          'sensitive=${vuln.intent.sensitive} performed=${vuln.performed} '
          'unauthorizedSurface=${vuln.unauthorizedSurface}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On iOS, report the real system surfaces the app's App Intents are exposed
    // to (read from the compiled Metadata.appintents bundle) and fire the real
    // privileged intent that any of those surfaces can reach.
    final surfaces = await AppIntentBridge.intentSurfaces();
    final fired = await AppIntentBridge.invokeSensitiveIntent();
    final native = [surfaces, fired].where((s) => s != null && s.isNotEmpty);
    if (native.isNotEmpty && mounted) {
      setState(() => _nativeResult = native.join('\n\n'));
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SystemSurfacePrivilegedAppintentExposureScreen.vulnId,
      title: 'System-Surface Privileged App-Intent Exposure',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An App Intent is surfaced to MANY system entry points - Siri, '
          'Spotlight, Shortcuts, Widget, Control, Live Activity, Action '
          'Button, Apple Intelligence - and reaches a privileged operation '
          '("export all data") with no per-surface authorization. A passive, '
          'lock-screen-reachable surface such as a Control therefore fires the '
          'privileged op with no unlock and no confirmation. This is the '
          'SURFACE fan-out problem (distinct from untrusted-parameter authz). '
          'This is an offline, deterministic simulation. The secure path '
          'enforces a per-surface allowlist and requires device authentication '
          'for sensitive intents.',
      children: [
        DemoActionButton(
          label: 'Fire "export data" from Control',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'any surface reaches the privileged op',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'per-surface allowlist + auth enforced',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real iOS App Intent surfaces (from compiled metadata)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
