/// Pure-Dart model of Android Intent redirection.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-940): an exported component receives
/// an [AppIntent] whose extras carry a nested, attacker-supplied "forward"
/// intent. The vulnerable handler blindly extracts that nested intent and
/// dispatches it to an internal component, with no validation of the target -
/// classic intent redirection. An attacker uses the app's own privileges to
/// reach a component (and action) they could not invoke directly.
///
/// This is a faithful Dart SIMULATION; the real exploit is Android-level
/// (an exported Activity/Service forwarding `getParcelableExtra("intent")`).
class AppIntent {
  AppIntent({
    required this.action,
    required this.target,
    this.extras = const {},
  });

  final String action;
  final String target;

  /// Extras may contain a nested `forward_intent` (an [AppIntent]) supplied by
  /// an untrusted caller.
  final Map<String, Object?> extras;

  AppIntent? get forwardIntent => extras['forward_intent'] as AppIntent?;

  @override
  String toString() => 'Intent(action=$action, target=$target)';
}

/// The result of an exported component handling an intent.
class IntentDispatchResult {
  IntentDispatchResult({required this.dispatchedTo, required this.redirected});

  final String dispatchedTo;
  final bool redirected;
}

/// A stand-in for the app's exported entry component and its internal targets.
class IntentRouter {
  IntentRouter._();

  /// Internal, non-exported components that should not be reachable from an
  /// untrusted external caller.
  static const List<String> internalComponents = [
    'InternalAdminActivity',
    'InternalKeyStoreService',
  ];

  /// The vulnerable exported handler.
  ///
  /// VULN: if the incoming intent carries a nested `forward_intent`, it is
  /// dispatched with no validation of its target - even internal components.
  static IntentDispatchResult handleExported(AppIntent incoming) {
    final forward = incoming.forwardIntent;
    if (forward != null) {
      // Blindly forward using the app's own identity/privileges.
      return IntentDispatchResult(
        dispatchedTo: forward.target,
        redirected: true,
      );
    }
    return IntentDispatchResult(
      dispatchedTo: incoming.target,
      redirected: false,
    );
  }

  /// A secure handler: never forwards a caller-supplied nested intent, and
  /// refuses to dispatch to internal components.
  static IntentDispatchResult secureHandleExported(AppIntent incoming) {
    final forward = incoming.forwardIntent;
    if (forward != null && internalComponents.contains(forward.target)) {
      return IntentDispatchResult(dispatchedTo: 'REJECTED', redirected: false);
    }
    return IntentDispatchResult(
      dispatchedTo: incoming.target,
      redirected: false,
    );
  }
}
