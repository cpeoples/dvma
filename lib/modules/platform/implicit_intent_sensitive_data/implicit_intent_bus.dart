/// Implicit Intent Leaks Sensitive Data helper.
///
/// INTENTIONALLY VULNERABLE (CWE-927 / CWE-200): sensitive data is placed on an
/// IMPLICIT intent - one that names only an action and carries no explicit
/// component/package target - and broadcast. Android resolves an implicit
/// intent by ITS ACTION, delivering it to every installed app that registered a
/// matching intent-filter. A malicious app co-resident on the device can
/// register the same action and silently receive the extras (auth tokens,
/// account email, etc.). This is the Samsung Smart View CVE-2025-21024 class.
///
/// This is an offline + deterministic simulation: the "system" is an in-memory
/// [ImplicitIntentBus] with registered receivers, and "broadcasting" returns
/// the list of receivers that got the extras. A test can assert the malicious
/// eavesdropper receives the sensitive extras on an implicit broadcast, but
/// gets nothing on an explicit (component-targeted) send.
class ImplicitIntentBus {
  ImplicitIntentBus(this._receivers);

  final List<IntentReceiver> _receivers;

  /// A realistic bus: two trusted first-party receivers plus a malicious
  /// eavesdropper app that has registered the SAME action to sniff the data.
  factory ImplicitIntentBus.withEavesdropper() {
    return ImplicitIntentBus(const [
      IntentReceiver(
        packageName: 'com.dvma.app',
        action: 'com.dvma.action.SHARE_SESSION',
        trusted: true,
      ),
      IntentReceiver(
        packageName: 'com.dvma.companion',
        action: 'com.dvma.action.SHARE_SESSION',
        trusted: true,
      ),
      // VULN: a co-resident attacker app claims the same action.
      IntentReceiver(
        packageName: 'com.evil.eavesdropper',
        action: 'com.dvma.action.SHARE_SESSION',
        trusted: false,
      ),
    ]);
  }

  /// VULN: broadcast an IMPLICIT intent (no target package). The system routes
  /// it to every receiver whose filter matches [action] - including the
  /// malicious eavesdropper - and hands each of them the sensitive [extras].
  /// Returns the deliveries that occurred so a caller/test can see who got the
  /// data.
  List<IntentDelivery> broadcastImplicit(
    String action,
    Map<String, String> extras,
  ) {
    return _receivers
        .where((r) => r.action == action)
        .map(
          (r) => IntentDelivery(
            packageName: r.packageName,
            trusted: r.trusted,
            // The full sensitive payload is delivered verbatim.
            receivedExtras: Map<String, String>.from(extras),
          ),
        )
        .toList(growable: false);
  }

  /// SECURE contrast: send an EXPLICIT intent addressed to a single trusted
  /// [targetPackage]. Only a receiver matching BOTH the package and the action
  /// is delivered to, so the eavesdropper (a different package) gets nothing.
  List<IntentDelivery> sendExplicit(
    String targetPackage,
    String action,
    Map<String, String> extras,
  ) {
    return _receivers
        .where((r) => r.packageName == targetPackage && r.action == action)
        .map(
          (r) => IntentDelivery(
            packageName: r.packageName,
            trusted: r.trusted,
            receivedExtras: Map<String, String>.from(extras),
          ),
        )
        .toList(growable: false);
  }
}

/// A registered receiver on the (simulated) system: an app that declared an
/// intent-filter for [action].
class IntentReceiver {
  const IntentReceiver({
    required this.packageName,
    required this.action,
    required this.trusted,
  });

  /// The receiving app's package id.
  final String packageName;

  /// The action its intent-filter matches.
  final String action;

  /// Whether this receiver is a trusted first-party app.
  final bool trusted;
}

/// The result of delivering an intent to one receiver.
class IntentDelivery {
  const IntentDelivery({
    required this.packageName,
    required this.trusted,
    required this.receivedExtras,
  });

  /// The package that received the intent.
  final String packageName;

  /// Whether the recipient is a trusted first-party app.
  final bool trusted;

  /// The extras the recipient was handed (the sensitive payload).
  final Map<String, String> receivedExtras;
}
