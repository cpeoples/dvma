/// System-Surface Privileged App-Intent Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-284 / CWE-749): an App Intent is
/// surfaced to MANY system entry points (Siri / Spotlight / Shortcuts / Widget
/// / Control Center / Live Activity / Action Button / Apple Intelligence) and
/// reaches a PRIVILEGED operation with no per-surface authorization. Because
/// the intent is exposed everywhere, a low-friction surface such as a Widget or
/// Control fires the privileged op (e.g. "export data" / "transfer") with no
/// unlock and no confirmation.
///
/// This is distinct from parameter-authorization (the untrusted PARAMETER):
/// here it is the SURFACE fan-out that is unguarded.
///
/// This is an offline + deterministic SIMULATION. [AppIntentSurfaceRouter]
/// knows a set of surfaces and a privileged intent. The vulnerable [invokeFrom]
/// runs the privileged op from ANY surface; the secure [invokeFromSafe]
/// requires per-surface authorization (surface allowlist + auth for sensitive
/// intents).
library;

/// The system entry points an App Intent can be surfaced to.
enum IntentSurface {
  siri,
  spotlight,
  shortcuts,
  widget,
  control,
  liveActivity,
  actionButton,
  appleIntelligence,
}

extension IntentSurfaceLabel on IntentSurface {
  String get label {
    switch (this) {
      case IntentSurface.siri:
        return 'Siri';
      case IntentSurface.spotlight:
        return 'Spotlight';
      case IntentSurface.shortcuts:
        return 'Shortcuts';
      case IntentSurface.widget:
        return 'Widget';
      case IntentSurface.control:
        return 'Control';
      case IntentSurface.liveActivity:
        return 'Live Activity';
      case IntentSurface.actionButton:
        return 'Action Button';
      case IntentSurface.appleIntelligence:
        return 'Apple Intelligence';
    }
  }
}

/// A privileged App Intent.
class PrivilegedIntent {
  const PrivilegedIntent({required this.name, required this.sensitive});

  final String name;

  /// Whether the intent performs a sensitive/privileged operation.
  final bool sensitive;

  /// The "export all data / transfer funds" intent used by the demo.
  static const PrivilegedIntent exportData = PrivilegedIntent(
    name: 'export-all-data',
    sensitive: true,
  );
}

/// The outcome of invoking an intent from a surface.
class SurfaceInvocationResult {
  const SurfaceInvocationResult({
    required this.surface,
    required this.intent,
    required this.performed,
    required this.unauthorizedSurface,
    this.denyReason,
  });

  final IntentSurface surface;
  final PrivilegedIntent intent;

  /// Whether the privileged op ran.
  final bool performed;

  /// True when a sensitive op ran from a surface that had no per-surface auth
  /// (e.g. a locked-device Widget/Control) - the fan-out hit.
  final bool unauthorizedSurface;

  /// Why the secure router refused.
  final String? denyReason;
}

class AppIntentSurfaceRouter {
  const AppIntentSurfaceRouter();

  /// Surfaces permitted to reach a sensitive intent, and only after auth.
  /// Interactive, foreground, authenticated surfaces are allowlisted; passive
  /// or lock-screen-reachable surfaces (Widget/Control/Live Activity) are not.
  static const Set<IntentSurface> _sensitiveAllowlist = {
    IntentSurface.siri,
    IntentSurface.shortcuts,
    IntentSurface.appleIntelligence,
  };

  /// VULN: run the privileged op from ANY surface with no per-surface
  /// authorization. A Widget or Control fires "export data" with no unlock.
  SurfaceInvocationResult invokeFrom(
    IntentSurface surface,
    PrivilegedIntent intent,
  ) {
    return SurfaceInvocationResult(
      surface: surface,
      intent: intent,
      performed: true,
      // A sensitive intent reached from a non-allowlisted surface is the bug.
      unauthorizedSurface:
          intent.sensitive && !_sensitiveAllowlist.contains(surface),
    );
  }

  /// SECURE contrast: enforce a per-surface allowlist for sensitive intents,
  /// and require device authentication when invoking them.
  SurfaceInvocationResult invokeFromSafe(
    IntentSurface surface,
    PrivilegedIntent intent, {
    bool deviceAuthenticated = false,
  }) {
    if (intent.sensitive && !_sensitiveAllowlist.contains(surface)) {
      return SurfaceInvocationResult(
        surface: surface,
        intent: intent,
        performed: false,
        unauthorizedSurface: false,
        denyReason:
            'surface ${surface.label} is not authorized for sensitive '
            'intent ${intent.name}',
      );
    }
    if (intent.sensitive && !deviceAuthenticated) {
      return SurfaceInvocationResult(
        surface: surface,
        intent: intent,
        performed: false,
        unauthorizedSurface: false,
        denyReason:
            'sensitive intent ${intent.name} requires device '
            'authentication',
      );
    }
    return SurfaceInvocationResult(
      surface: surface,
      intent: intent,
      performed: true,
      unauthorizedSurface: false,
    );
  }
}
