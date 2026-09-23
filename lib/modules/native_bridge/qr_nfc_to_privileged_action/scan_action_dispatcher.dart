/// QR / NFC Scan -> Privileged Action Without Confirmation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-306 / CWE-862 / CWE-346): a scanned QR code or
/// tapped NFC tag carries a payload that names an automation / privileged action
/// (unlock door, disable alarm, run automation.evil). The app forwards that
/// payload straight to the action dispatcher with no authentication of the scan
/// SOURCE and no explicit user confirmation. So a co-resident app that can feed
/// the scanner, or a planted/overwritten NFC tag, triggers the privileged action
/// silently. This is the Home Assistant Companion GHSA NFC/QR class.
///
/// This is an offline + deterministic simulation. [ScanActionDispatcher] takes a
/// [ScanEvent] (source + caller trust + payload) and either fires the action
/// immediately (vuln) or requires the caller to be trusted AND an explicit user
/// confirmation (secure). No real QR/NFC hardware is used. Tests assert an
/// untrusted scan fires the action on the vuln path and is blocked on the secure
/// path.
library;

/// Where a scan payload came from.
enum ScanSource { qr, nfc }

/// A scan delivered to the app.
class ScanEvent {
  const ScanEvent({
    required this.source,
    required this.callerPackage,
    required this.callerTrusted,
    required this.action,
    this.userConfirmed = false,
  });

  /// QR or NFC.
  final ScanSource source;

  /// The package/app that fed the scan to the app.
  final String callerPackage;

  /// Whether that caller is a trusted first-party source.
  final bool callerTrusted;

  /// The automation/privileged action the payload names.
  final String action;

  /// Whether the user explicitly confirmed the action (secure path input).
  final bool userConfirmed;
}

/// The outcome of dispatching a scan.
class ScanActionResult {
  const ScanActionResult({
    required this.executed,
    required this.blocked,
    this.executedAction,
    this.blockReason,
  });

  /// Whether the privileged action actually fired.
  final bool executed;

  /// Whether the dispatch was refused (secure path).
  final bool blocked;

  /// The action that fired (null unless executed).
  final String? executedAction;

  /// Why the dispatch was refused (secure path only).
  final String? blockReason;

  /// True when a privileged action fired from an UNTRUSTED caller - the actual
  /// silent-trigger hit.
  bool silentlyTriggered(ScanEvent event) => executed && !event.callerTrusted;
}

/// A minimal, in-memory model of the scan -> action dispatcher.
class ScanActionDispatcher {
  const ScanActionDispatcher();

  /// A privileged automation an attacker would target.
  static const String privilegedAction = 'automation.unlock_front_door';

  /// VULN: the payload's action is fired immediately. The scan SOURCE is never
  /// authenticated and there is no user confirmation, so an untrusted caller
  /// (co-resident app / planted tag) silently triggers the automation.
  ScanActionResult dispatch(ScanEvent event) {
    return ScanActionResult(
      executed: true,
      blocked: false,
      executedAction: event.action,
    );
  }

  /// SECURE contrast: require BOTH a trusted scan source AND an explicit user
  /// confirmation before firing a privileged action. An untrusted caller is
  /// refused; even a trusted caller must be confirmed by the user.
  ScanActionResult dispatchSafe(ScanEvent event) {
    if (!event.callerTrusted) {
      return const ScanActionResult(
        executed: false,
        blocked: true,
        blockReason: 'scan source not trusted',
      );
    }
    if (!event.userConfirmed) {
      return const ScanActionResult(
        executed: false,
        blocked: true,
        blockReason: 'user did not confirm the action',
      );
    }
    return ScanActionResult(
      executed: true,
      blocked: false,
      executedAction: event.action,
    );
  }
}
