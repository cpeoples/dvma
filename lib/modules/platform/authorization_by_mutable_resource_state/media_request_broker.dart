/// Authorization Based on Mutable Resource State helper.
///
/// INTENTIONALLY VULNERABLE (CWE-367 / CWE-708 / CWE-863): a security decision
/// is made on the MUTABLE existence/state of a resource (a pre-check like
/// `!exists(path)`) and only THEN is the resource created and the caller bound
/// to it. Because existence is mutable and the check is decoupled from the
/// creation, a caller obtains read/write authorization over a file it should
/// not own - it wins access by racing/winning on a not-yet-existing path
/// (the Android MediaProvider TOCTOU/logic CVE-2026-0035 class).
///
/// This is an offline + deterministic SIMULATION. [MediaRequestBroker] holds an
/// in-memory filesystem mapping path -> owner. The vulnerable [createRequest]
/// grants ownership based on `!exists(path)` and then creates the entry, so a
/// caller claims a path that a victim legitimately owns whenever the pre-check
/// disagrees with reality. The secure [createRequestSafe] binds authorization
/// to a stable owner identity captured ATOMICALLY, never to mutable existence.
library;

/// A file in the in-memory media store, owned by some identity.
class MediaFile {
  const MediaFile({required this.path, required this.owner});

  final String path;

  /// The stable identity that owns (and may read/write) this file.
  final String owner;
}

/// The outcome of a media-access request.
class RequestResult {
  const RequestResult({
    required this.caller,
    required this.path,
    required this.granted,
    required this.stolenFromOwner,
    this.effectiveOwner,
    this.denyReason,
  });

  /// The identity that made the request.
  final String caller;

  final String path;

  /// Whether read/write was granted to the caller.
  final bool granted;

  /// True when the caller was granted access to a path already owned by a
  /// DIFFERENT identity - the mutable-state authorization hit.
  final bool stolenFromOwner;

  /// The owner recorded for the path after the request.
  final String? effectiveOwner;

  /// Why the safe broker refused.
  final String? denyReason;
}

/// An in-memory model of a media-request broker with a mutable filesystem.
class MediaRequestBroker {
  MediaRequestBroker(Iterable<MediaFile> seed)
    : _files = {for (final f in seed) f.path: f};

  final Map<String, MediaFile> _files;

  /// The legitimate owner of the contested media file.
  static const String victim = 'uid:1001:com.dvma.gallery';

  /// The attacker racing for the file.
  static const String attacker = 'uid:2002:com.evil.grabber';

  /// A path the victim is ABOUT to create (does not exist yet at pre-check
  /// time) but legitimately belongs to them via a pending reservation.
  static const String contestedPath = '/media/external/DCIM/private_scan.jpg';

  /// A broker where the victim has RESERVED the contested path (stable owner)
  /// even though the file bytes do not exist yet.
  factory MediaRequestBroker.seeded() {
    return MediaRequestBroker(const [
      MediaFile(path: '/media/external/DCIM/existing.jpg', owner: victim),
    ]);
  }

  /// Reservations binding a path to its rightful owner BEFORE the bytes exist.
  /// A safe broker consults this; the vulnerable one ignores it.
  static const Map<String, String> _reservations = {contestedPath: victim};

  MediaFile? fileAt(String path) => _files[path];

  bool exists(String path) => _files.containsKey(path);

  /// VULN: authorize on MUTABLE existence. If the path does not currently
  /// exist, grant the caller ownership and create it - ignoring any stable
  /// reservation. The attacker therefore claims a path the victim reserved.
  RequestResult createRequest(String caller, String path) {
    if (exists(path)) {
      final existing = _files[path]!;
      return RequestResult(
        caller: caller,
        path: path,
        granted: false,
        stolenFromOwner: false,
        effectiveOwner: existing.owner,
        denyReason: 'path already exists',
      );
    }
    // BUG: existence pre-check decides authorization; reservation ignored.
    _files[path] = MediaFile(path: path, owner: caller);
    final rightful = _reservations[path];
    return RequestResult(
      caller: caller,
      path: path,
      granted: true,
      stolenFromOwner: rightful != null && rightful != caller,
      effectiveOwner: caller,
    );
  }

  /// SECURE contrast: bind authorization to a STABLE owner identity captured
  /// atomically. A path reserved by another identity cannot be claimed by the
  /// caller regardless of whether the bytes exist yet.
  RequestResult createRequestSafe(String caller, String path) {
    final rightful = _reservations[path] ?? _files[path]?.owner;
    if (rightful != null && rightful != caller) {
      return RequestResult(
        caller: caller,
        path: path,
        granted: false,
        stolenFromOwner: false,
        effectiveOwner: rightful,
        denyReason:
            'path is bound to owner "$rightful"; caller may not claim '
            'it via mutable existence',
      );
    }
    _files[path] = MediaFile(path: path, owner: caller);
    return RequestResult(
      caller: caller,
      path: path,
      granted: true,
      stolenFromOwner: false,
      effectiveOwner: caller,
    );
  }
}
