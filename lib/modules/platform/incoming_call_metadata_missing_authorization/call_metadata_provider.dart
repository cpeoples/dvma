/// A single incoming-call record the provider holds. In a real build the
/// number and metadata come from the telephony/call-log store; here they are
/// seeded so the missing-authorization read is demonstrable offline.
class IncomingCall {
  const IncomingCall({
    required this.number,
    required this.contactName,
    required this.timestamp,
    required this.direction,
  });

  final String number;
  final String contactName;
  final String timestamp;
  final String direction;

  @override
  String toString() => '$direction  $number  ($contactName)  @ $timestamp';
}

/// Incoming-call metadata read with a missing authorization check.
///
/// INTENTIONALLY VULNERABLE (CWE-862 / CWE-200): reproduces the app-layer
/// pattern behind CVE-2026-0057, a provider path returns an incoming call's
/// number and associated metadata without checking the caller's permission.
/// [readLatestIncoming] performs no grant check, so an unprivileged local caller
/// reads it with no user interaction; [secureReadLatestIncoming] applies the
/// permission gate the vulnerable path is missing.
class CallMetadataProvider {
  CallMetadataProvider({List<IncomingCall>? calls})
    : _calls =
          calls ??
          const [
            IncomingCall(
              number: '+1-202-555-0173',
              contactName: 'Dr. Reyes (cardiology)',
              timestamp: '2026-09-12T13:41:07Z',
              direction: 'INCOMING',
            ),
          ];

  final List<IncomingCall> _calls;

  /// VULN: returns the latest incoming call with no permission check, so any
  /// local caller reads private call metadata (`hasPermission` is ignored).
  IncomingCall? readLatestIncoming({bool hasPermission = false}) =>
      _calls.isEmpty ? null : _calls.last;

  /// A hardened provider enforces the caller's permission before returning any
  /// call metadata, denying an unprivileged read.
  IncomingCall? secureReadLatestIncoming({required bool hasPermission}) =>
      hasPermission && _calls.isNotEmpty ? _calls.last : null;
}
