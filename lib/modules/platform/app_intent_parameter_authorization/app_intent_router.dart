/// App Intent / Siri Parameter -> Privileged Action (No Authz) helper.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-639 / CWE-20): an App Intent / Siri /
/// Shortcuts / Spotlight entry point maps an UNTRUSTED, system-supplied
/// parameter straight to a privileged app action (transfer / delete / export)
/// with no per-invocation authorization and no ownership check. A crafted
/// shortcut therefore invokes the privileged action - moving money, exporting
/// another user's account - directly from its parameters (the Apple App Intents
/// capability-confusion class).
///
/// This is an offline + deterministic simulation. [AppIntentRouter] models the
/// intent entry point over a tiny in-memory bank. The vulnerable [invoke] runs
/// the privileged action straight from the params; the secure [invokeSafe]
/// requires the invocation to carry a VERIFIED user-authorization token AND
/// checks the acting user owns the target entity, refusing unauthorized /
/// other-user params.
library;

/// A privileged intent invocation: a shortcut parameter bundle arriving at the
/// App Intent entry point.
class AppIntentInvocation {
  const AppIntentInvocation({
    required this.intentName,
    required this.params,
    this.authToken,
  });

  /// The App Intent being invoked (e.g. `TransferFunds`, `ExportAccount`).
  final String intentName;

  /// The system-supplied parameters (attacker-controllable via a shortcut).
  final Map<String, String> params;

  /// A user-authorization token proving the current user approved THIS
  /// invocation. Null on the vulnerable/attacker path.
  final String? authToken;
}

/// The result of routing an App Intent invocation.
class InvocationResult {
  const InvocationResult({
    required this.executed,
    required this.blocked,
    required this.action,
    this.effect,
    this.denyReason,
  });

  /// Whether the privileged action ran.
  final bool executed;

  /// Whether the safe router refused (secure path).
  final bool blocked;

  /// The privileged action that was requested.
  final String action;

  /// A human-readable description of the side effect that occurred.
  final String? effect;

  /// Why the safe router refused (secure path only).
  final String? denyReason;
}

/// A tiny bank/account model the privileged actions operate on.
class AppIntentRouter {
  AppIntentRouter(Map<String, int> balances, this._accountOwners)
    : _balances = Map<String, int>.from(balances);

  final Map<String, int> _balances;
  final Map<String, String> _accountOwners;

  static const String transferIntent = 'TransferFunds';
  static const String exportIntent = 'ExportAccount';

  /// The signed-in user driving the shortcut.
  static const String currentUser = 'alice';

  /// An account belonging to a DIFFERENT user - the attacker's target.
  static const String victimAccount = 'acct-bob-01';

  /// Alice's own account.
  static const String ownAccount = 'acct-alice-01';

  /// A valid authorization token the OS mints only after the user confirms.
  static const String validAuthToken = 'authz-ok-7731';

  factory AppIntentRouter.seeded() {
    return AppIntentRouter(
      const {ownAccount: 500, victimAccount: 100000},
      const {ownAccount: currentUser, victimAccount: 'bob'},
    );
  }

  int balanceOf(String account) => _balances[account] ?? 0;

  /// VULN: run the privileged action straight from the shortcut [params] with
  /// no authorization token check and no ownership check. A crafted shortcut
  /// exports/transfers from any account it names.
  InvocationResult invoke(AppIntentInvocation invocation) {
    switch (invocation.intentName) {
      case exportIntent:
        final acct = invocation.params['accountId'] ?? '';
        return InvocationResult(
          executed: true,
          blocked: false,
          action: '$exportIntent($acct)',
          effect:
              'exported account $acct '
              '(owner: ${_accountOwners[acct] ?? 'unknown'}, '
              'balance: ${balanceOf(acct)})',
        );
      case transferIntent:
        final from = invocation.params['from'] ?? '';
        final to = invocation.params['to'] ?? '';
        final amount = int.tryParse(invocation.params['amount'] ?? '') ?? 0;
        _balances[from] = balanceOf(from) - amount;
        _balances[to] = balanceOf(to) + amount;
        return InvocationResult(
          executed: true,
          blocked: false,
          action: '$transferIntent($from -> $to, $amount)',
          effect: 'moved $amount from $from to $to',
        );
      default:
        return InvocationResult(
          executed: false,
          blocked: false,
          action: invocation.intentName,
          denyReason: 'unknown intent',
        );
    }
  }

  /// SECURE contrast: require a VERIFIED user-authorization token for the
  /// invocation AND confirm the current user OWNS the target account before
  /// running the privileged action. Unauthorized or other-user params are
  /// refused with no side effect.
  InvocationResult invokeSafe(AppIntentInvocation invocation) {
    if (invocation.authToken != validAuthToken) {
      return InvocationResult(
        executed: false,
        blocked: true,
        action: invocation.intentName,
        denyReason: 'missing/invalid per-invocation authorization token',
      );
    }
    final targetAccount = invocation.intentName == transferIntent
        ? (invocation.params['from'] ?? '')
        : (invocation.params['accountId'] ?? '');
    if (_accountOwners[targetAccount] != currentUser) {
      return InvocationResult(
        executed: false,
        blocked: true,
        action: invocation.intentName,
        denyReason: 'current user $currentUser does not own $targetAccount',
      );
    }
    // Authorized + owned -> perform via the same code path as vuln.
    return invoke(invocation);
  }
}
