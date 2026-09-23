/// Handoff / NSUserActivity injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-345 / CWE-501): the receiving app
/// restores state from a Handoff `NSUserActivity` (`userInfo` / `webpageURL`)
/// and TRUSTS it merely because it arrived over Continuity. It navigates and
/// acts on an account/resource without validating the source device, the
/// `activityType`, or the account binding, so a crafted continuation payload
/// drives the app to a privileged/attacker-chosen state (e.g. operating on
/// ANOTHER account's resource).
///
/// The Handoff continuation logic is real and runs the same way on any
/// platform: [HandoffActivityReceiver] takes an incoming activity (its
/// `activityType`, `userInfo`, and attacker-controlled `webpageURL`) and the
/// app's current authenticated account, then the vulnerable [continueActivity]
/// applies `userInfo` blindly (parsing `webpageURL` with real `Uri.parse`);
/// the secure [continueActivitySafe] validates the activityType against a known
/// set, requires the activity's `boundAccountId` to equal the current account,
/// and treats `userInfo`/`webpageURL` as untrusted. The vulnerable-vs-secure
/// decision path IS the vulnerability. (Note: DVMA does not register a
/// system-level `NSUserActivity` continuation handler, so the inbound activity
/// is supplied to the receiver in-app rather than by iOS Handoff itself.)
library;

/// Associated-domain allowlist the receiving app trusts for web continuation.
const List<String> handoffAssociatedDomains = ['app.dvma.example'];

/// A modeled incoming Handoff activity handed to the receiving app.
class HandoffUserActivity {
  const HandoffUserActivity({
    required this.activityType,
    required this.userInfo,
    required this.webpageURL,
    required this.sourceDeviceTrusted,
    required this.boundAccountId,
  });

  /// The reverse-DNS activity type declared by the sender (attacker-settable).
  final String activityType;

  /// Arbitrary continuation payload (attacker-controllable).
  final Map<String, String> userInfo;

  /// Optional web continuation URL (attacker-controllable).
  final String? webpageURL;

  /// Whether the sending device is a trusted, paired Continuity peer.
  final bool sourceDeviceTrusted;

  /// The account this activity legitimately belongs to, per the sender.
  final String boundAccountId;
}

/// Outcome of continuing a Handoff activity.
class HandoffContinuationResult {
  const HandoffContinuationResult({
    required this.action,
    required this.targetAccount,
    required this.stateApplied,
    required this.sourceValidated,
    required this.accountBound,
    this.webHost,
    this.domainAllowed = false,
    this.denyReason,
  });

  /// The action the continuation drove (e.g. "open_resource").
  final String action;

  /// The account whose resource was operated on.
  final String targetAccount;

  /// Whether the app mutated/navigated state from the payload.
  final bool stateApplied;

  /// Whether the source device + activityType were validated.
  final bool sourceValidated;

  /// Whether the activity was bound to the current authenticated account.
  final bool accountBound;

  /// Host parsed from the (attacker-controlled) `webpageURL` via `Uri.parse`.
  final String? webHost;

  /// Whether that parsed host was on the associated-domain allowlist.
  final bool domainAllowed;

  /// Why the secure path refused the continuation.
  final String? denyReason;
}

class HandoffActivityReceiver {
  HandoffActivityReceiver({String? currentAccountId})
    : currentAccountId = currentAccountId ?? loggedInAccount;

  /// The activityType this app actually knows how to continue.
  static const String expectedActivityType = 'com.dvma.app.viewAccountResource';

  /// The account currently authenticated in the receiving app.
  static const String loggedInAccount = 'acct_1001';

  /// The account an attacker's crafted payload aims to reach.
  static const String attackerTargetAccount = 'acct_2002';

  /// The authenticated account for this receiver instance.
  final String currentAccountId;

  /// Parses the (attacker-controlled) `webpageURL` with real `Uri.parse` and
  /// returns `(host, query)`. Returns nulls when there is no URL.
  static ({String? host, Map<String, String> query}) _parseWebpage(
    String? webpageURL,
  ) {
    if (webpageURL == null || webpageURL.isEmpty) {
      return (host: null, query: const {});
    }
    final uri = Uri.parse(webpageURL);
    return (
      host: uri.host.isEmpty ? null : uri.host,
      query: uri.queryParameters,
    );
  }

  /// VULN: applies the continuation payload with no checks. Because the app
  /// trusts anything arriving over Continuity, it PARSES the attacker-controlled
  /// `webpageURL`, merges its query params over `userInfo`, and honors the
  /// result - so a crafted activity whose URL/`userInfo` targets another
  /// account's resource is applied and the app operates on that foreign account.
  HandoffContinuationResult continueActivity(HandoffUserActivity activity) {
    // Real parse of the attacker-controlled continuation URL.
    final web = _parseWebpage(activity.webpageURL);

    // Payload is applied verbatim: query params from the parsed URL override
    // userInfo, and the target account is taken straight from that untrusted
    // input, not from the current session.
    final merged = <String, String>{...activity.userInfo, ...web.query};
    final target =
        merged['acct'] ?? merged['accountId'] ?? activity.boundAccountId;
    final action = merged['action'] ?? 'open_resource';
    return HandoffContinuationResult(
      action: action,
      targetAccount: target,
      stateApplied: true,
      sourceValidated: false,
      accountBound: target == currentAccountId,
      webHost: web.host,
      domainAllowed:
          web.host != null && handoffAssociatedDomains.contains(web.host),
    );
  }

  /// SECURE contrast: parses the `webpageURL`, validates its host against the
  /// associated-domain allowlist, validates the activityType against the known
  /// set, requires the activity to be bound to the current account, and never
  /// trusts payload merely because it arrived over Continuity.
  HandoffContinuationResult continueActivitySafe(HandoffUserActivity activity) {
    final web = _parseWebpage(activity.webpageURL);
    final domainAllowed =
        web.host == null || handoffAssociatedDomains.contains(web.host);

    if (!activity.sourceDeviceTrusted) {
      return HandoffContinuationResult(
        action: 'none',
        targetAccount: currentAccountId,
        stateApplied: false,
        sourceValidated: false,
        accountBound: false,
        webHost: web.host,
        domainAllowed: domainAllowed,
        denyReason: 'source device is not a trusted Continuity peer',
      );
    }
    if (!domainAllowed) {
      return HandoffContinuationResult(
        action: 'none',
        targetAccount: currentAccountId,
        stateApplied: false,
        sourceValidated: true,
        accountBound: false,
        webHost: web.host,
        domainAllowed: false,
        denyReason: 'webpageURL host ${web.host} not an associated domain',
      );
    }
    if (activity.activityType != expectedActivityType) {
      return HandoffContinuationResult(
        action: 'none',
        targetAccount: currentAccountId,
        stateApplied: false,
        sourceValidated: false,
        accountBound: false,
        webHost: web.host,
        domainAllowed: domainAllowed,
        denyReason: 'unknown activityType ${activity.activityType}',
      );
    }
    // Account binding: the activity must belong to the account already
    // authenticated in this app; untrusted userInfo/URL cannot redirect it.
    final payloadTarget = activity.userInfo['accountId'] ?? web.query['acct'];
    if (activity.boundAccountId != currentAccountId ||
        (payloadTarget != null && payloadTarget != currentAccountId)) {
      return HandoffContinuationResult(
        action: 'none',
        targetAccount: currentAccountId,
        stateApplied: false,
        sourceValidated: true,
        accountBound: false,
        webHost: web.host,
        domainAllowed: domainAllowed,
        denyReason: 'activity not bound to current account $currentAccountId',
      );
    }
    return HandoffContinuationResult(
      action: activity.userInfo['action'] ?? 'open_resource',
      targetAccount: currentAccountId,
      stateApplied: true,
      sourceValidated: true,
      accountBound: true,
      webHost: web.host,
      domainAllowed: domainAllowed,
    );
  }
}
