/// Ordered-Broadcast Result Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-925 / CWE-349 / CWE-348): the app sends an
/// ordered broadcast and then TRUSTS the aggregated `getResultData()` /
/// result-extras for a security decision (e.g. "isPremium" / "allowTransfer").
/// Because an ordered broadcast is delivered receiver-by-receiver in PRIORITY
/// order, a co-resident (or malicious) receiver registered at a HIGHER priority
/// runs first and calls `setResultData()` / `setResultExtras()` (or
/// `abortBroadcast()`) to poison or suppress the result before the app's own
/// receiver aggregates it. The attacker sits in the middle of the app's own
/// broadcast pipeline, so the "authoritative" result the app consumes is
/// attacker-controlled.
///
/// This is an offline SIMULATION. [OrderedBroadcastBus] models a set of
/// registered receivers, each with a package, priority, and a transform over
/// the running result. The vulnerable [sendOrdered] runs every registered
/// receiver in priority order and then trusts the final result; the secure
/// [sendOrderedSafe] protects the broadcast with a signature permission so the
/// attacker receiver never runs AND refuses to use ordered-broadcast results
/// for the security decision at all.
library;

/// A receiver participating in an ordered broadcast.
class OrderedReceiver {
  const OrderedReceiver({
    required this.package,
    required this.priority,
    required this.transform,
    this.holdsSignaturePermission = false,
  });

  /// The package that registered this receiver.
  final String package;

  /// Ordered-broadcast priority; higher runs earlier.
  final int priority;

  /// Mutation this receiver applies to the running result value.
  final String Function(String current) transform;

  /// Whether this receiver's app is signed with the broadcaster's signature.
  final bool holdsSignaturePermission;
}

/// The outcome of dispatching an ordered broadcast and reading its result.
class OrderedBroadcastResult {
  const OrderedBroadcastResult({
    required this.action,
    required this.finalValue,
    required this.resultTrusted,
    required this.resultPoisoned,
    this.firstReceiverPackage,
    this.denyReason,
  });

  /// The broadcast action string.
  final String action;

  /// The aggregated result value the app ends up consuming.
  final String finalValue;

  /// Whether the app used the ordered-broadcast result for a security
  /// decision (i.e. trusted it as authoritative).
  final bool resultTrusted;

  /// True when the trusted final value differs from the legitimate value
  /// because a higher-priority receiver rewrote it - the hit.
  final bool resultPoisoned;

  /// The package of the receiver that ran first (highest priority).
  final String? firstReceiverPackage;

  /// Why the secure path refused to trust / deliver the poisoned result.
  final String? denyReason;
}

class OrderedBroadcastBus {
  /// The security-relevant action the app broadcasts.
  static const String action = 'com.dvma.app.action.CHECK_ENTITLEMENT';

  /// The signature permission that SHOULD protect the ordered broadcast.
  static const String signaturePermission =
      'com.dvma.app.permission.ENTITLEMENT_BROADCAST';

  /// The legitimate result the app's own receiver would produce.
  static const String legitimateResult = 'isPremium=false;allowTransfer=false';

  /// The value the attacker injects to escalate the entitlement decision.
  static const String poisonedResult = 'isPremium=true;allowTransfer=true';

  /// The co-resident malicious app.
  static const String attackerPackage = 'com.evil.entitlements';

  /// A high priority that guarantees the attacker runs before the app.
  static const int attackerPriority = 1000;

  /// The app's own receiver priority.
  static const int appPriority = 0;

  final List<OrderedReceiver> _receivers = [];

  /// Register a receiver into the ordered-broadcast pipeline.
  void register(OrderedReceiver receiver) => _receivers.add(receiver);

  /// The app's own receiver: it produces the honest, un-escalated result.
  static OrderedReceiver appReceiver() => OrderedReceiver(
    package: 'com.dvma.app',
    priority: appPriority,
    transform: (_) => legitimateResult,
    holdsSignaturePermission: true,
  );

  /// A malicious higher-priority receiver that rewrites the result to escalate
  /// the entitlement before the app's receiver can set the honest value.
  static OrderedReceiver attackerReceiver() => OrderedReceiver(
    package: attackerPackage,
    priority: attackerPriority,
    transform: (_) => poisonedResult,
    holdsSignaturePermission: false,
  );

  List<OrderedReceiver> _byPriority() {
    final sorted = [..._receivers];
    sorted.sort((a, b) => b.priority.compareTo(a.priority));
    return sorted;
  }

  /// VULN: dispatch the ordered broadcast with no permission guard and then
  /// TRUST the aggregated result for a security decision. The attacker's
  /// higher-priority receiver runs first and rewrites the running result, so
  /// the app consumes the poisoned entitlement.
  OrderedBroadcastResult sendOrdered(String initialResult) {
    var running = initialResult;
    final order = _byPriority();
    for (final r in order) {
      // No permission is enforced: every registered receiver participates.
      running = r.transform(running);
    }
    return OrderedBroadcastResult(
      action: action,
      finalValue: running,
      resultTrusted: true,
      resultPoisoned: running != legitimateResult,
      firstReceiverPackage: order.isEmpty ? null : order.first.package,
    );
  }

  /// SECURE contrast: protect the ordered broadcast with a signature
  /// permission so only same-signature receivers run (the attacker never
  /// participates), AND never use an ordered-broadcast result as the
  /// authoritative source for a security decision - resolve the entitlement
  /// from a trusted local source instead.
  OrderedBroadcastResult sendOrderedSafe(String initialResult) {
    var running = initialResult;
    OrderedReceiver? first;
    for (final r in _byPriority()) {
      // Signature-permission gate: drop receivers that are not same-signature.
      if (!r.holdsSignaturePermission) continue;
      first ??= r;
      running = r.transform(running);
    }

    // Even with a clean pipeline, the security decision is not taken from the
    // ordered-broadcast result; it is resolved authoritatively elsewhere.
    return OrderedBroadcastResult(
      action: action,
      finalValue: running,
      resultTrusted: false,
      resultPoisoned: false,
      firstReceiverPackage: first?.package,
      denyReason:
          'broadcast guarded by $signaturePermission (attacker '
          'receiver dropped) and ordered-broadcast result is not trusted for '
          'the entitlement decision',
    );
  }
}
