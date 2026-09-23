/// Sensitive Data in Crash Reports helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-532 / CWE-201, OWASP MASTG
/// sensitive-data-in-diagnostics): when the app crashes, a diagnostic pipeline
/// (Crashlytics/Sentry-style) snapshots the current app state and recent
/// breadcrumbs, serializes them into a crash payload, writes it locally, and
/// SHIPS it to a third-party crash service. Developers assume fields like the
/// auth token, the user's password, and the last HTTP request body only ever
/// lived in memory - but the crash reporter captures and EXFILTRATES exactly
/// that state on failure. This is distinct from ordinary logging: the crash
/// pipeline attaches full application state to a report that leaves the device.
///
/// This is an offline + deterministic SIMULATION. [CrashReporter] holds an
/// in-memory "uploaded reports" sink standing in for the remote crash service
/// (never actually contacted). The vulnerable [report] serializes the raw
/// [CrashAppState] (secrets, PII, request body, breadcrumbs) verbatim; the
/// secure [reportSafe] allowlists non-sensitive fields, redacts tokens/PII, and
/// drops request/response bodies before uploading.
library;

/// A single recorded breadcrumb (a step the user took before the crash).
class CrashBreadcrumb {
  const CrashBreadcrumb(this.message);

  final String message;

  @override
  String toString() => message;
}

/// The in-memory application state captured at crash time.
///
/// Mixes truly diagnostic data (screen, build) with sensitive data the
/// developer never intended to leave the device.
class CrashAppState {
  const CrashAppState({
    required this.screen,
    required this.buildNumber,
    required this.userEmail,
    required this.authToken,
    required this.password,
    required this.lastRequestBody,
    required this.breadcrumbs,
  });

  /// Non-sensitive: the screen the user was on. Safe to include.
  final String screen;

  /// Non-sensitive: app build number. Safe to include.
  final String buildNumber;

  /// PII: the signed-in user's email address.
  final String userEmail;

  /// Secret: the session bearer token held in memory.
  final String authToken;

  /// Secret: the user's plaintext password (still in a controller buffer).
  final String password;

  /// Sensitive: the last outbound HTTP request body, including a PAN.
  final String lastRequestBody;

  /// Recent user-action breadcrumbs; some contain sensitive values.
  final List<CrashBreadcrumb> breadcrumbs;
}

/// The result of assembling and "uploading" a crash report.
class CrashReportResult {
  const CrashReportResult({
    required this.payload,
    required this.sent,
    required this.scrubbed,
    required this.leaked,
    required this.leakedFields,
  });

  /// The serialized crash payload that was uploaded to the crash service.
  final String payload;

  /// Whether the payload was transmitted to the (simulated) crash service.
  final bool sent;

  /// Whether sensitive fields were scrubbed/allowlisted before sending.
  final bool scrubbed;

  /// True when at least one secret/PII value survived into the sent payload.
  final bool leaked;

  /// Names of the sensitive fields that leaked (empty on the secure path).
  final List<String> leakedFields;
}

class CrashReporter {
  /// The remote crash-collection endpoint. Never actually contacted here; it
  /// stands in for a third-party diagnostics/crash service.
  static const String crashEndpoint =
      'https://ingest.crash-collector.example/v1/reports';

  /// The in-memory sink standing in for reports uploaded to the crash service.
  final List<String> uploadedReports = <String>[];

  /// A realistic crashing app state seeded with secrets and PII.
  static CrashAppState sampleState() => const CrashAppState(
    screen: 'CheckoutScreen',
    buildNumber: '4.12.0 (2201)',
    userEmail: 'victim@example.com',
    authToken: 'Bearer eyJhbGci.9a1f77c2d4e8.b3c19f',
    password: 'Sunflower!2024',
    lastRequestBody: '{"amount":4200,"card":"4111111111111111","cvv":"731"}',
    breadcrumbs: [
      CrashBreadcrumb('tapped Pay'),
      CrashBreadcrumb('POST /charge auth=Bearer eyJhbGci.9a1f77c2d4e8'),
      CrashBreadcrumb('NPE in PaymentController.finalize()'),
    ],
  );

  /// The sensitive substrings whose presence in a payload counts as a leak.
  static List<String> _secretsIn(CrashAppState s) => <String>[
    s.authToken,
    s.password,
    s.userEmail,
    '4111111111111111', // card PAN inside the request body
  ];

  /// VULN: attach the RAW application state and every breadcrumb to the crash
  /// report, then upload it. Nothing is redacted, so tokens, the password, PII,
  /// and the full request body (with the card number) are exfiltrated to the
  /// crash service on failure.
  CrashReportResult report(CrashAppState state) {
    final b = StringBuffer();
    b.writeln('screen=${state.screen}');
    b.writeln('build=${state.buildNumber}');
    b.writeln('email=${state.userEmail}');
    b.writeln('authToken=${state.authToken}');
    b.writeln('password=${state.password}');
    b.writeln('lastRequestBody=${state.lastRequestBody}');
    for (final crumb in state.breadcrumbs) {
      b.writeln('breadcrumb=$crumb');
    }
    final payload = b.toString().trimRight();
    uploadedReports.add(payload); // "sent" to the crash service.

    final leaked = _secretsIn(state)
        .where((secret) => payload.contains(secret))
        .toList(growable: false);
    final leakedFields = <String>[
      if (payload.contains(state.authToken)) 'authToken',
      if (payload.contains(state.password)) 'password',
      if (payload.contains(state.userEmail)) 'email',
      if (payload.contains('4111111111111111')) 'card',
    ];
    return CrashReportResult(
      payload: payload,
      sent: true,
      scrubbed: false,
      leaked: leaked.isNotEmpty,
      leakedFields: leakedFields,
    );
  }

  /// SECURE contrast: allowlist only non-sensitive diagnostic fields, redact
  /// tokens/PII, and drop request/response bodies entirely. Breadcrumbs are
  /// passed through a redactor so no secret survives into the uploaded report.
  CrashReportResult reportSafe(CrashAppState state) {
    final b = StringBuffer();
    // Allowlist: only fields known to be safe are included verbatim.
    b.writeln('screen=${state.screen}');
    b.writeln('build=${state.buildNumber}');
    // PII/secrets are redacted rather than dropped so the report stays useful.
    b.writeln('email=${_maskEmail(state.userEmail)}');
    b.writeln('authToken=[REDACTED]');
    b.writeln('password=[REDACTED]');
    // Request/response bodies are dropped outright (never diagnostic-safe).
    b.writeln('lastRequestBody=[DROPPED]');
    for (final crumb in state.breadcrumbs) {
      b.writeln('breadcrumb=${_redactCrumb(crumb.message)}');
    }
    final payload = b.toString().trimRight();
    uploadedReports.add(payload);

    final leaked = _secretsIn(state)
        .where((secret) => payload.contains(secret))
        .toList(growable: false);
    return CrashReportResult(
      payload: payload,
      sent: true,
      scrubbed: true,
      leaked: leaked.isNotEmpty, // stays false: everything sensitive is gone.
      leakedFields: const [],
    );
  }

  /// Mask an email to a coarse form that is not personally identifying.
  static String _maskEmail(String email) {
    final at = email.indexOf('@');
    if (at <= 0) return '[REDACTED]';
    final first = email[0];
    return '$first***${email.substring(at)}';
  }

  /// Strip bearer tokens and long digit runs (card/CVV) from a breadcrumb.
  static String _redactCrumb(String message) {
    return message
        .replaceAll(RegExp(r'Bearer\s+\S+'), 'Bearer [REDACTED]')
        .replaceAll(RegExp(r'\d{6,}'), '[REDACTED]');
  }
}
