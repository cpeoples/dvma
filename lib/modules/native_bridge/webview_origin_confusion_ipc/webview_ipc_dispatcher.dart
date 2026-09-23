/// WebView Origin Confusion -> Local-Only IPC helper.
///
/// INTENTIONALLY VULNERABLE (CWE-346 / CWE-863 / CWE-441): a WebView IPC layer
/// decides whether a caller is the LOCAL/trusted application origin before it
/// will run local-only, privileged IPC commands (e.g. `readFile`,
/// `invoke("delete_account")`). The vuln classifier uses a sloppy check - a
/// substring / `contains` / suffix match, or it simply trusts an
/// attacker-supplied `Origin` header - so a REMOTE page such as
/// `https://tauri.localhost.evil.com` or `app://localhost.attacker.tld` is
/// misclassified as the local origin and reaches commands it must never touch.
/// This is the Tauri WebView IPC origin-confusion CVE-2026-42184 class.
///
/// The screen drives this over a real WebView `Ipc` JavaScript channel: a page
/// tagged with an attacker-controlled `Origin` posts a local-only command
/// across the JS↔native boundary, the loose [OriginClassifier.isLocal] check
/// misclassifies it as local, and [dispatch] runs the privileged command,
/// returning the result into the page via `runJavaScript`. The origin
/// classification is real logic over the attacker-supplied origin string;
/// [WebViewIpcDispatcher] models the local-only command table and is kept as a
/// deterministic in-memory fallback so `flutter test` (and platforms without a
/// WebView) stay offline. The secure [OriginClassifier.isLocalStrict] does an
/// exact canonical-origin comparison (scheme + host + port) and [dispatchSafe]
/// rejects the remote page. Tests assert a remote origin invokes a local-only
/// command on the vuln path and is rejected on the secure path.
library;

/// Classifies whether a caller origin is the local/trusted application origin.
class OriginClassifier {
  const OriginClassifier({required this.canonicalLocalOrigin});

  /// The one true local application origin (e.g. `tauri://localhost`). Only a
  /// byte-for-byte match of scheme + host + port should ever count as local.
  final String canonicalLocalOrigin;

  /// VULN: a sloppy "does this look local?" check. It accepts any origin whose
  /// host merely CONTAINS the local host token, so a remote attacker origin
  /// like `https://tauri.localhost.evil.com` (host contains `localhost`) is
  /// misclassified as the trusted local origin.
  bool isLocal(String origin) {
    final localHost = _host(canonicalLocalOrigin);
    final callerHost = _host(origin);
    // The bug: substring containment instead of equality.
    return callerHost.contains(localHost);
  }

  /// SECURE contrast: exact canonical-origin comparison. Normalizes and then
  /// compares scheme + host + port; nothing but the true local origin passes.
  bool isLocalStrict(String origin) {
    return _canonical(origin) == _canonical(canonicalLocalOrigin);
  }

  /// Extract the host portion of an origin string, tolerating malformed input.
  static String _host(String origin) {
    final uri = Uri.tryParse(origin);
    if (uri != null && uri.host.isNotEmpty) return uri.host.toLowerCase();
    // Fall back to a crude scheme-strip for custom app:// style origins that
    // Uri may not parse a host out of.
    final noScheme = origin.contains('://')
        ? origin.substring(origin.indexOf('://') + 3)
        : origin;
    final hostPart = noScheme.split('/').first.split(':').first;
    return hostPart.toLowerCase();
  }

  /// Canonicalize an origin to `scheme://host[:port]`, lowercased.
  static String _canonical(String origin) {
    final uri = Uri.tryParse(origin);
    if (uri == null || uri.scheme.isEmpty) return origin.toLowerCase().trim();
    final scheme = uri.scheme.toLowerCase();
    final host = uri.host.toLowerCase();
    final hasPort = uri.hasPort;
    return hasPort ? '$scheme://$host:${uri.port}' : '$scheme://$host';
  }
}

/// The outcome of an IPC command dispatch.
class IpcDispatchResult {
  const IpcDispatchResult({
    required this.executed,
    required this.blocked,
    required this.classifiedLocal,
    this.output,
    this.blockReason,
  });

  /// Whether the local-only command actually ran.
  final bool executed;

  /// Whether the dispatcher refused the command (secure path).
  final bool blocked;

  /// How the caller origin was classified ("is this local?").
  final bool classifiedLocal;

  /// The privileged command output returned to the caller (null unless run).
  final String? output;

  /// Why the command was refused (secure path only).
  final String? blockReason;

  /// True when a local-only command executed for a caller that is not the
  /// canonical local origin - the actual origin-confusion hit.
  bool privilegedReachedRemote(String callerOrigin, String canonicalLocal) =>
      executed &&
      OriginClassifier._canonical(callerOrigin) !=
          OriginClassifier._canonical(canonicalLocal);
}

/// A minimal, in-memory model of a WebView IPC dispatcher that exposes
/// local-only privileged commands.
class WebViewIpcDispatcher {
  WebViewIpcDispatcher({String? canonicalLocalOrigin})
    : canonicalLocalOrigin = canonicalLocalOrigin ?? defaultLocalOrigin,
      classifier = OriginClassifier(
        canonicalLocalOrigin: canonicalLocalOrigin ?? defaultLocalOrigin,
      );

  /// The canonical local/trusted application origin.
  final String canonicalLocalOrigin;

  /// The origin classifier used to decide "is this call local?".
  final OriginClassifier classifier;

  /// The default local origin a Tauri-style app WebView runs at.
  static const String defaultLocalOrigin = 'tauri://localhost';

  /// A local-only, privileged IPC command name.
  static const String privilegedCommand = 'invoke:delete_account';

  /// The (simulated) side effect / return value of the privileged command.
  static const String privilegedOutput =
      'account cpeoples#4410 deleted; session revoked';

  /// Commands that must only ever be reachable from the local origin.
  static const Set<String> localOnlyCommands = {
    privilegedCommand,
    'invoke:read_file',
  };

  /// VULN: classify the caller with the loose [OriginClassifier.isLocal] check
  /// and run the local-only command if it "looks local". A remote page whose
  /// host merely contains `localhost` is treated as local and the privileged
  /// command executes.
  IpcDispatchResult dispatch({
    required String command,
    required String callerOrigin,
  }) {
    final looksLocal = classifier.isLocal(callerOrigin);
    if (localOnlyCommands.contains(command) && looksLocal) {
      return IpcDispatchResult(
        executed: true,
        blocked: false,
        classifiedLocal: looksLocal,
        output: privilegedOutput,
      );
    }
    return IpcDispatchResult(
      executed: false,
      blocked: false,
      classifiedLocal: looksLocal,
      blockReason: looksLocal ? null : 'command not exposed to this origin',
    );
  }

  /// SECURE contrast: classify with the exact [OriginClassifier.isLocalStrict]
  /// check. Only the byte-for-byte canonical local origin can reach a
  /// local-only command; the remote page is rejected.
  IpcDispatchResult dispatchSafe({
    required String command,
    required String callerOrigin,
  }) {
    final isLocal = classifier.isLocalStrict(callerOrigin);
    if (!localOnlyCommands.contains(command)) {
      return IpcDispatchResult(
        executed: false,
        blocked: false,
        classifiedLocal: isLocal,
        blockReason: 'unknown command',
      );
    }
    if (!isLocal) {
      return IpcDispatchResult(
        executed: false,
        blocked: true,
        classifiedLocal: isLocal,
        blockReason:
            'origin $callerOrigin is not the local origin $canonicalLocalOrigin',
      );
    }
    return IpcDispatchResult(
      executed: true,
      blocked: false,
      classifiedLocal: isLocal,
      output: privilegedOutput,
    );
  }
}
