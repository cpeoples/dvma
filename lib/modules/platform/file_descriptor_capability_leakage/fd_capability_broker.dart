/// File-Descriptor Capability Leakage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-402 transmission of private resources into a
/// new sphere / CWE-668 exposure of resource to wrong sphere / CWE-200 exposure
/// of sensitive information, Android FD-passing class): the app opens a
/// resource and passes the live `ParcelFileDescriptor` (via a Binder
/// transaction, `ContentProvider.openFile()`, or `detachFd()`) to an untrusted
/// caller for a file/socket the caller could not otherwise open. An open FD is
/// a CAPABILITY: once handed over it bypasses path-based permission checks, and
/// the recipient inherits access to whatever the FD points at - a sensitive DB,
/// a privileged unix socket, etc. This is conceptually different from path
/// traversal: no new path is resolved; an ALREADY-OPEN capability is
/// transferred wholesale.
///
/// This is an offline + deterministic SIMULATION. [FdCapabilityBroker] models a
/// small resource table (path, sensitivity, bytes) and "opening" a resource to
/// produce a fake FD handle (an int plus a backing resource ref). The
/// vulnerable [openForCaller] returns a read/write FD to a sensitive resource
/// with no caller check, so the untrusted caller reads the secret bytes. The
/// secure [openForCallerSafe] validates the caller, refuses sensitive
/// resources, and returns only a read-only FD to a narrowly-scoped,
/// non-sensitive resource.
library;

/// A resource that can be opened and handed out as an FD.
class BrokeredResource {
  const BrokeredResource({
    required this.path,
    required this.sensitive,
    required this.bytes,
  });

  /// The backing path (a DB file, a socket, etc.).
  final String path;

  /// Whether this resource is sensitive and must never leave the app sphere.
  final bool sensitive;

  /// The bytes the resource yields when read through an FD.
  final String bytes;
}

/// A simulated open file descriptor: an int handle plus the backing resource
/// and the access mode it was opened with.
class FdHandle {
  const FdHandle({
    required this.fd,
    required this.mode,
    required this.resource,
  });

  /// The (fake) numeric descriptor.
  final int fd;

  /// The access mode the FD was opened with (`r` or `rw`).
  final String mode;

  /// The backing resource the descriptor points at.
  final BrokeredResource resource;

  bool get writable => mode.contains('w');

  /// Read the bytes the FD points at - the recipient of a leaked FD gets this
  /// regardless of any path permission it lacks.
  String read() => resource.bytes;
}

/// The outcome of a broker request to open a resource for a caller.
class FdBrokerResult {
  const FdBrokerResult({
    required this.callerPackage,
    required this.resourcePath,
    required this.fdReturned,
    required this.callerChecked,
    required this.sensitiveAccessGranted,
    required this.readOnly,
    this.bytesRead,
    this.denyReason,
  });

  /// The package that requested the FD.
  final String callerPackage;

  /// The resource the caller asked to open.
  final String resourcePath;

  /// Whether a live FD was handed to the caller.
  final bool fdReturned;

  /// Whether the broker verified the caller before returning any FD.
  final bool callerChecked;

  /// Whether access to a SENSITIVE resource was granted.
  final bool sensitiveAccessGranted;

  /// Whether the returned FD was restricted to read-only.
  final bool readOnly;

  /// The bytes the caller read through the leaked FD, when one was returned.
  final String? bytesRead;

  /// Why the secure path refused to return an FD.
  final String? denyReason;
}

class FdCapabilityBroker {
  /// A sensitive DB file whose FD must never be handed to an untrusted caller.
  static const String sensitiveDbPath =
      '/data/data/com.dvma.app/databases/accounts.db';

  /// The secret bytes the sensitive DB yields when read through an FD.
  static const String sensitiveBytes =
      'accounts.db: user=admin balance=91340 token=SESS-4419-DEAD';

  /// A benign, narrowly-scoped resource safe to expose read-only.
  static const String benignPath =
      '/data/data/com.dvma.app/cache/public_manifest.json';
  static const String benignBytes = '{"version":3,"public":true}';

  /// The app's own trusted, same-signature client.
  static const String trustedCallerPackage = 'com.dvma.app';

  /// An untrusted third-party app requesting an FD over Binder.
  static const String attackerCallerPackage = 'com.evil.fdgrab';

  /// Callers permitted (signature-checked) to receive any FD from the broker.
  static const Set<String> allowedCallers = {trustedCallerPackage};

  int _nextFd = 7;

  final Map<String, BrokeredResource> _resources = const {
    sensitiveDbPath: BrokeredResource(
      path: sensitiveDbPath,
      sensitive: true,
      bytes: sensitiveBytes,
    ),
    benignPath: BrokeredResource(
      path: benignPath,
      sensitive: false,
      bytes: benignBytes,
    ),
  };

  /// Open the backing resource and mint a fake FD handle with the given mode.
  FdHandle _open(BrokeredResource resource, String mode) =>
      FdHandle(fd: _nextFd++, mode: mode, resource: resource);

  /// VULN: open the requested resource read/write and return the live FD to
  /// ANY caller with no identity check - the classic `openFile()` / `detachFd()`
  /// mistake. The untrusted caller receives a capability over the sensitive DB
  /// and reads its bytes, bypassing every path-based permission it lacks.
  FdBrokerResult openForCaller(String callerPackage, String resourcePath) {
    final resource = _resources[resourcePath];
    if (resource == null) {
      return FdBrokerResult(
        callerPackage: callerPackage,
        resourcePath: resourcePath,
        fdReturned: false,
        callerChecked: false,
        sensitiveAccessGranted: false,
        readOnly: false,
        denyReason: 'no such resource',
      );
    }
    final handle = _open(resource, 'rw');
    return FdBrokerResult(
      callerPackage: callerPackage,
      resourcePath: resourcePath,
      fdReturned: true,
      callerChecked: false,
      sensitiveAccessGranted: resource.sensitive,
      readOnly: !handle.writable,
      bytesRead: handle.read(),
    );
  }

  /// SECURE contrast: verify the caller against a signature allowlist, refuse
  /// to open any sensitive resource for FD passing at all, and hand out only a
  /// READ-only FD to a narrowly-scoped, non-sensitive resource.
  FdBrokerResult openForCallerSafe(String callerPackage, String resourcePath) {
    if (!allowedCallers.contains(callerPackage)) {
      return FdBrokerResult(
        callerPackage: callerPackage,
        resourcePath: resourcePath,
        fdReturned: false,
        callerChecked: true,
        sensitiveAccessGranted: false,
        readOnly: false,
        denyReason: 'caller $callerPackage failed signature check - no FD',
      );
    }
    final resource = _resources[resourcePath];
    if (resource == null) {
      return FdBrokerResult(
        callerPackage: callerPackage,
        resourcePath: resourcePath,
        fdReturned: false,
        callerChecked: true,
        sensitiveAccessGranted: false,
        readOnly: false,
        denyReason: 'no such resource',
      );
    }
    if (resource.sensitive) {
      return FdBrokerResult(
        callerPackage: callerPackage,
        resourcePath: resourcePath,
        fdReturned: false,
        callerChecked: true,
        sensitiveAccessGranted: false,
        readOnly: false,
        denyReason:
            'refusing to pass an FD for sensitive resource '
            '$resourcePath',
      );
    }
    final handle = _open(resource, 'r');
    return FdBrokerResult(
      callerPackage: callerPackage,
      resourcePath: resourcePath,
      fdReturned: true,
      callerChecked: true,
      sensitiveAccessGranted: false,
      readOnly: !handle.writable,
      bytesRead: handle.read(),
    );
  }
}
