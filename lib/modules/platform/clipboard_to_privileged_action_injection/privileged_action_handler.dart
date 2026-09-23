/// Clipboard -> Privileged Action Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-77 / CWE-441): clipboard content that
/// was SOURCED from an untrusted origin flows into a PRIVILEGED action - an
/// auto-paste into a payment field, or an assistant/automation step that runs a
/// command - with no validation and no confirmation. The taint chain is:
///
///     untrusted origin -> system clipboard -> automation/auto-paste
///                       -> privileged app capability (pay / run command)
///
/// This is an offline + deterministic SIMULATION. [PrivilegedActionHandler]
/// reads a [ClipboardEntry] (value + the origin that wrote it) and executes a
/// privileged action. The vulnerable [runFromClipboard] takes tainted clipboard
/// content straight into the action with no allowlist; the secure
/// [runFromClipboardSafe] requires the value to have originated from a trusted
/// source, validates/normalizes it against an allowlist, and requires explicit
/// user confirmation.
library;

/// A clipboard entry that remembers WHO wrote it (its origin/taint).
class ClipboardEntry {
  const ClipboardEntry({required this.value, required this.origin});

  final String value;

  /// The origin that placed this value on the clipboard.
  final String origin;
}

/// The kind of privileged action a clipboard value drives.
enum PrivilegedActionKind { payment, shellCommand }

/// The outcome of driving a privileged action from the clipboard.
class ActionResult {
  const ActionResult({
    required this.kind,
    required this.executed,
    required this.payload,
    required this.injectedFromUntrusted,
    this.denyReason,
  });

  final PrivilegedActionKind kind;

  /// Whether the privileged action actually ran.
  final bool executed;

  /// The value that flowed into the action (e.g. the pay-to address / command).
  final String payload;

  /// True when tainted, untrusted-origin content reached the privileged action
  /// - the injection hit.
  final bool injectedFromUntrusted;

  /// Why the safe handler refused.
  final String? denyReason;
}

/// Executes privileged actions, optionally validating the clipboard taint.
class PrivilegedActionHandler {
  const PrivilegedActionHandler();

  /// The app's own trusted UI - the only origin allowed to seed a privileged
  /// clipboard value.
  static const String trustedOrigin = 'app://dvma.pay';

  /// A hostile origin (a WebView page / another app) that tainted the value.
  static const String untrustedOrigin = 'https://evil.example';

  /// A legitimate, allowlisted payee the user intended to pay.
  static const String legitPayee = 'pay to acct:DVMA-MERCHANT-001 amount:20.00';

  /// The attacker's injected instruction hijacking the payment.
  static const String injectedPayee =
      'pay to acct:EVIL-DRAIN-999 amount:5000.00';

  /// Payees the app is willing to auto-pay without extra scrutiny.
  static const Set<String> _allowlistedAccounts = {'DVMA-MERCHANT-001'};

  static String? _accountOf(String payload) {
    final m = RegExp(r'acct:([A-Za-z0-9\-]+)').firstMatch(payload);
    return m?.group(1);
  }

  /// VULN: read the tainted clipboard entry and execute the payment/command
  /// with the raw value - no origin check, no allowlist, no confirmation.
  ActionResult runFromClipboard(
    ClipboardEntry entry, {
    PrivilegedActionKind kind = PrivilegedActionKind.payment,
  }) {
    return ActionResult(
      kind: kind,
      executed: true,
      payload: entry.value,
      injectedFromUntrusted: entry.origin != trustedOrigin,
      denyReason: null,
    );
  }

  /// SECURE contrast: refuse clipboard content that did not originate from a
  /// trusted source, validate the normalized value against an allowlist, and
  /// require explicit user confirmation before running the privileged action.
  ActionResult runFromClipboardSafe(
    ClipboardEntry entry, {
    PrivilegedActionKind kind = PrivilegedActionKind.payment,
    bool userConfirmed = false,
  }) {
    if (entry.origin != trustedOrigin) {
      return ActionResult(
        kind: kind,
        executed: false,
        payload: entry.value,
        injectedFromUntrusted: false,
        denyReason:
            'clipboard value tainted by untrusted origin '
            '"${entry.origin}"; refusing privileged action',
      );
    }
    final account = _accountOf(entry.value);
    if (account == null || !_allowlistedAccounts.contains(account)) {
      return ActionResult(
        kind: kind,
        executed: false,
        payload: entry.value,
        injectedFromUntrusted: false,
        denyReason: 'payee "$account" is not on the allowlist',
      );
    }
    if (!userConfirmed) {
      return ActionResult(
        kind: kind,
        executed: false,
        payload: entry.value,
        injectedFromUntrusted: false,
        denyReason: 'explicit user confirmation required',
      );
    }
    return ActionResult(
      kind: kind,
      executed: true,
      payload: entry.value,
      injectedFromUntrusted: false,
      denyReason: null,
    );
  }
}
