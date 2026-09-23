library;

/// Android capability-composition chain.
///
/// No single hop here is the vulnerability - the COMPOSITION is. An untrusted
/// notification action carries a mutable `PendingIntent`, which fires an
/// exported `BroadcastReceiver`, which binds an exported Binder service, which
/// performs a privileged money transfer. Each link trusts its immediate
/// predecessor and never re-checks the ORIGINAL caller, so an attacker who can
/// trigger the first hop launders an unauthenticated request through four
/// individually-benign components into a privileged operation (CWE-441
/// confused deputy, CWE-862 missing authorization, CWE-668 exposure).

/// A single hop in the laundering chain, recorded for evidence.
class ChainHop {
  const ChainHop(
    this.name,
    this.trustedPredecessor, {
    this.reauthorized = false,
  });

  /// Human-readable component name, e.g. "exported BroadcastReceiver".
  final String name;

  /// Whether this hop simply trusted whoever invoked it (the bug), rather than
  /// re-checking the original caller.
  final bool trustedPredecessor;

  /// Whether this hop re-authorized the original caller (the fix).
  final bool reauthorized;
}

/// Result of walking the chain from the initial (untrusted) trigger to the sink.
class ChainResult {
  const ChainResult({
    required this.hops,
    required this.transferPerformed,
    required this.originalCallerReauthorized,
    required this.amount,
    required this.toAccount,
    this.denyReason,
  });

  final List<ChainHop> hops;

  /// Whether the privileged sink (the transfer) actually ran.
  final bool transferPerformed;

  /// Whether the ORIGINAL untrusted caller was ever re-authorized at the sink.
  final bool originalCallerReauthorized;

  final int amount;
  final String toAccount;
  final String? denyReason;

  /// The composed vulnerability fired: an untrusted trigger reached the
  /// privileged sink without the original caller ever being authorized.
  bool get chainExploited => transferPerformed && !originalCallerReauthorized;
}

class CapabilityCompositionChain {
  /// The untrusted principal that triggers the notification action / broadcast.
  static const String attackerCaller = 'com.evil.notif';

  /// The privileged operation at the end of the chain.
  static const int transferAmount = 9000;
  static const String transferAccount = 'acct-attacker-777';

  /// VULN: walk the full chain. The notification action's PendingIntent is
  /// mutable/implicit, the receiver is exported, and the Binder service runs
  /// the transfer using only `getCallingUid()` of its IMMEDIATE caller (the
  /// receiver, which is same-app) - so the original untrusted caller is never
  /// checked. Every hop trusts its predecessor.
  ChainResult run(String originalCaller) {
    final hops = <ChainHop>[
      const ChainHop('notification action (mutable PendingIntent)', true),
      const ChainHop('exported BroadcastReceiver', true),
      const ChainHop('bound Binder service', true),
      const ChainHop('privileged transfer sink', true),
    ];
    // The sink checks its immediate binder caller (same app), not the original
    // untrusted notification principal - classic confused deputy.
    return ChainResult(
      hops: hops,
      transferPerformed: true,
      originalCallerReauthorized: false,
      amount: transferAmount,
      toAccount: transferAccount,
    );
  }

  /// SECURE: the sink re-authorizes the ORIGINAL caller (propagated end-to-end)
  /// and the chain uses immutable/explicit intents + per-method authorization,
  /// so an untrusted trigger is refused at the first hop that matters.
  ChainResult runSafe(String originalCaller) {
    final trusted = originalCaller == 'com.dvma.app';
    final hops = <ChainHop>[
      const ChainHop(
        'notification action (immutable explicit PendingIntent)',
        false,
      ),
      const ChainHop(
        'exported BroadcastReceiver (signature-permission)',
        false,
      ),
      const ChainHop('bound Binder service (per-method authz)', false),
      ChainHop('privileged transfer sink', false, reauthorized: true),
    ];
    if (!trusted) {
      return ChainResult(
        hops: hops,
        transferPerformed: false,
        originalCallerReauthorized: true,
        amount: transferAmount,
        toAccount: transferAccount,
        denyReason:
            'original caller "$originalCaller" not authorized for the '
            'transfer sink; immutable/explicit intents + per-method '
            'authorization break the chain at the first untrusted hop',
      );
    }
    return ChainResult(
      hops: hops,
      transferPerformed: true,
      originalCallerReauthorized: true,
      amount: transferAmount,
      toAccount: transferAccount,
    );
  }
}
