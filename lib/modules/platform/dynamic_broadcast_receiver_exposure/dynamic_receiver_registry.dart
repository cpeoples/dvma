/// Dynamic BroadcastReceiver Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-925 / CWE-926 / CWE-200, Android
/// MASTG-TEST-0366): a receiver registered at RUNTIME with
/// `Context.registerReceiver()` WITHOUT `RECEIVER_NOT_EXPORTED` (API 33+) and
/// WITHOUT a signature-level `requiredPermission` is IMPLICITLY EXPORTED. Any
/// co-resident app can then send it a crafted broadcast to trigger sensitive
/// functionality (or the receiver processes an untrusted broadcast and leaks
/// data). This is distinct from a manifest-declared exported receiver: here the
/// REGISTRATION FLAGS are the security boundary.
///
/// This is an offline + deterministic SIMULATION. [DynamicReceiverRegistry]
/// models registering a receiver for an action with export flags and an
/// optional required permission, then delivering a broadcast from a caller
/// package. The vulnerable [register] marks the receiver exported with no
/// permission, so [deliver] runs the sensitive action for an untrusted sender.
/// The secure [registerSafe] registers with RECEIVER_NOT_EXPORTED or a
/// signature permission the untrusted caller does not hold, so the broadcast is
/// dropped.
library;

/// A runtime-registered broadcast receiver record.
class RegisteredReceiver {
  const RegisteredReceiver({
    required this.action,
    required this.exported,
    required this.requiredPermission,
  });

  /// The intent action string the receiver listens for.
  final String action;

  /// Whether the receiver is exported (reachable by other apps). When true and
  /// no permission is required, the receiver is implicitly world-reachable.
  final bool exported;

  /// A permission the sender must hold to deliver, or null for none. A
  /// signature-level permission is only granted to same-signature apps.
  final String? requiredPermission;
}

/// The outcome of delivering a broadcast to the registered receiver.
class BroadcastDeliveryResult {
  const BroadcastDeliveryResult({
    required this.action,
    required this.senderPackage,
    required this.delivered,
    required this.senderAuthorized,
    required this.actionPerformed,
    this.denyReason,
  });

  /// The broadcast action that was sent.
  final String action;

  /// The package that sent the broadcast.
  final String senderPackage;

  /// Whether the broadcast reached the receiver and its onReceive ran.
  final bool delivered;

  /// Whether the sender was actually authorized (held the permission / was the
  /// trusted app). False + delivered==true is the confused-deputy hit.
  final bool senderAuthorized;

  /// The sensitive side effect the broadcast triggered (e.g. credit granted).
  final String actionPerformed;

  /// Why the secure path dropped the broadcast.
  final String? denyReason;
}

class DynamicReceiverRegistry {
  /// The currently registered receiver (null until register* is called).
  RegisteredReceiver? _receiver;

  /// Sensitive state the broadcast mutates: the user's promo-credit balance.
  int creditBalance = 0;

  /// The receiver's action: applying a promo code grants store credit.
  static const String promoAction = 'com.dvma.app.action.APPLY_PROMO';

  /// A signature-level permission only the app's own components are granted.
  static const String signaturePermission =
      'com.dvma.app.permission.INTERNAL_BROADCAST';

  /// The app's own trusted package (holds the signature permission).
  static const String trustedPackage = 'com.dvma.app';

  /// A co-resident untrusted app that forges the broadcast.
  static const String attackerPackage = 'com.evil.coresident';

  /// Store credit granted per (forged) promo broadcast.
  static const int creditPerPromo = 500;

  RegisteredReceiver? get receiver => _receiver;

  /// VULN: register the receiver EXPORTED with no required permission, the
  /// implicit result of calling `registerReceiver(receiver, filter)` on API 33+
  /// without passing `RECEIVER_NOT_EXPORTED`. The receiver is now reachable by
  /// any co-resident app.
  RegisteredReceiver register(String action) {
    _receiver = RegisteredReceiver(
      action: action,
      exported: true,
      requiredPermission: null,
    );
    return _receiver!;
  }

  /// SECURE contrast: register with `RECEIVER_NOT_EXPORTED` (not exported) and
  /// gate delivery behind a signature-level permission, so only same-signature
  /// components of the app can reach the receiver.
  RegisteredReceiver registerSafe(String action) {
    _receiver = RegisteredReceiver(
      action: action,
      exported: false,
      requiredPermission: signaturePermission,
    );
    return _receiver!;
  }

  /// Whether [senderPackage] holds the app's signature permission. Only the
  /// app's own package is same-signature in this model.
  bool _holdsSignaturePermission(String senderPackage) =>
      senderPackage == trustedPackage;

  /// Deliver a broadcast for [action] from [senderPackage]. Delivery succeeds
  /// only if the receiver is exported (or the sender is in-process) AND any
  /// required permission is satisfied. When delivered, the sensitive action
  /// (grant credit) runs.
  BroadcastDeliveryResult deliver(String action, String senderPackage) {
    final receiver = _receiver;
    if (receiver == null || receiver.action != action) {
      return BroadcastDeliveryResult(
        action: action,
        senderPackage: senderPackage,
        delivered: false,
        senderAuthorized: false,
        actionPerformed: '(none)',
        denyReason: 'no receiver registered for $action',
      );
    }

    // A non-exported receiver only accepts broadcasts from the app itself.
    if (!receiver.exported && senderPackage != trustedPackage) {
      return BroadcastDeliveryResult(
        action: action,
        senderPackage: senderPackage,
        delivered: false,
        senderAuthorized: false,
        actionPerformed: '(none)',
        denyReason:
            'receiver registered RECEIVER_NOT_EXPORTED - external '
            'sender $senderPackage cannot reach it',
      );
    }

    // A required permission must be held by the sender.
    final permission = receiver.requiredPermission;
    if (permission != null && !_holdsSignaturePermission(senderPackage)) {
      return BroadcastDeliveryResult(
        action: action,
        senderPackage: senderPackage,
        delivered: false,
        senderAuthorized: false,
        actionPerformed: '(none)',
        denyReason: 'sender $senderPackage lacks $permission',
      );
    }

    // Delivered: run the sensitive action.
    creditBalance += creditPerPromo;
    return BroadcastDeliveryResult(
      action: action,
      senderPackage: senderPackage,
      delivered: true,
      senderAuthorized: _holdsSignaturePermission(senderPackage),
      actionPerformed:
          'granted $creditPerPromo credit (balance=$creditBalance)',
    );
  }
}
