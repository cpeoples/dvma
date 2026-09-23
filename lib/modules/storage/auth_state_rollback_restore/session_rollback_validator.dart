/// Authentication-State Rollback / Restore helper.
///
/// INTENTIONALLY VULNERABLE (CWE-384 / CWE-613 / CWE-565): the app treats a
/// locally-persisted session blob as authoritative and never checks freshness
/// or revocation server-side. Restoring an OLD local state (from a backup,
/// snapshot, or copied app container) revives an already-ended or revoked
/// session, and the app believes the user is still authenticated - a session
/// rollback / restore attack.
///
/// This is an offline + deterministic SIMULATION. A [SessionBlob] carries a
/// token and the epoch at which it was minted. The authority (server) has
/// advanced to a current epoch and revoked older tokens. The vulnerable
/// [SessionRollbackValidator.resume] accepts any locally-present blob with no
/// server check; the secure [SessionRollbackValidator.resumeSafe] validates the
/// blob against the current server epoch and revocation list, rejecting
/// rolled-back state while accepting the current session.
///
/// real ARTIFACT: the session blob is PERSISTED to SharedPreferences
/// (`session_token` / `session_epoch`) and resume reads FROM that on-disk
/// state. On Android the backing file
/// `/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml` is adb-pullable
/// and adb-writable, so an old blob captured/restored on disk is the genuine
/// rollback surface: an attacker who restores an old `FlutterSharedPreferences.xml`
/// (or edits `session_epoch` back) revives a revoked session. A
/// MissingPluginException keeps `flutter test` deterministic on the const blobs.
library;

import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

/// A locally-persisted session: an opaque [token] and the [epoch] it was minted
/// at. A monotonically-increasing epoch lets the server detect stale state.
class SessionBlob {
  const SessionBlob({required this.token, required this.epoch});

  final String token;

  /// The session generation this blob belongs to (higher == fresher).
  final int epoch;
}

/// The outcome of attempting to resume from a persisted session blob.
class SessionResumeResult {
  const SessionResumeResult({
    required this.authenticated,
    required this.token,
    required this.epoch,
    required this.rolledBack,
    this.denyReason,
  });

  /// Whether the app considers the user authenticated after resume.
  final bool authenticated;

  /// The token the resume was attempted with.
  final String token;

  /// The epoch of the blob the resume was attempted with.
  final int epoch;

  /// True when a stale/revoked (rolled-back) session was accepted - the hit.
  final bool rolledBack;

  /// Why the secure resume refused (mentions 'rolled back' or 'revoked').
  final String? denyReason;
}

class SessionRollbackValidator {
  const SessionRollbackValidator();

  /// The server's current session generation. The authority has advanced past
  /// older epochs (e.g. after logout / password change / token rotation).
  static const int serverEpoch = 42;

  /// Tokens the server has explicitly revoked (logout, compromise, rotation).
  static const Set<String> revokedTokens = {'sess-old-7c1e'};

  /// The current, valid session as the server sees it.
  static const SessionBlob currentSession = SessionBlob(
    token: 'sess-new-9b4f',
    epoch: serverEpoch,
  );

  /// A STALE session restored from an old backup/snapshot: its epoch predates
  /// the server's current epoch AND its token was revoked at logout.
  static const SessionBlob staleSession = SessionBlob(
    token: 'sess-old-7c1e',
    epoch: 37,
  );

  /// VULN: trust any locally-present session blob as authoritative. There is
  /// no server-side freshness or revocation check, so a rolled-back blob from
  /// an old backup revives an ended/revoked session.
  SessionResumeResult resume(SessionBlob blob) {
    // The only "check" is that a token exists locally - always true here.
    final accepted = blob.token.isNotEmpty;
    final isStale =
        blob.epoch < serverEpoch || revokedTokens.contains(blob.token);
    return SessionResumeResult(
      authenticated: accepted,
      token: blob.token,
      epoch: blob.epoch,
      rolledBack: accepted && isStale, // stale session accepted anyway
    );
  }

  /// SECURE contrast: validate the blob against the server authority - reject
  /// revoked tokens and any epoch below the current (monotonic) server epoch.
  /// Rolled-back state is refused; the current session is accepted.
  SessionResumeResult resumeSafe(
    SessionBlob blob, {
    int currentServerEpoch = serverEpoch,
    Set<String> revocationList = revokedTokens,
  }) {
    if (revocationList.contains(blob.token)) {
      return SessionResumeResult(
        authenticated: false,
        token: blob.token,
        epoch: blob.epoch,
        rolledBack: false,
        denyReason: 'session token was revoked server-side; resume refused',
      );
    }
    if (blob.epoch < currentServerEpoch) {
      return SessionResumeResult(
        authenticated: false,
        token: blob.token,
        epoch: blob.epoch,
        rolledBack: false,
        denyReason:
            'session epoch ${blob.epoch} is behind server epoch '
            '$currentServerEpoch: state was rolled back, resume refused',
      );
    }
    return SessionResumeResult(
      authenticated: true,
      token: blob.token,
      epoch: blob.epoch,
      rolledBack: false, // only fresh, non-revoked sessions reach here
    );
  }

  /// SharedPreferences keys the persisted session blob lives under.
  static const String prefsTokenKey = 'session_token';
  static const String prefsEpochKey = 'session_epoch';

  /// real ARTIFACT: persist [blob] to SharedPreferences so the session lives
  /// on disk (the rollback surface). On device this writes the token + epoch to
  /// the adb-pullable/writable shared_prefs XML. Returns the `k=v` lines
  /// written. Degrades to returning the lines under `flutter test`.
  Future<String> persistSession(SessionBlob blob) async {
    final lines = '$prefsTokenKey=${blob.token}\n$prefsEpochKey=${blob.epoch}';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsTokenKey, blob.token);
      await prefs.setInt(prefsEpochKey, blob.epoch);
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`): lines still returned.
    } catch (_) {
      // Best effort: never perturb the demo.
    }
    return lines;
  }

  /// real ARTIFACT: load the persisted session blob from SharedPreferences -
  /// the on-disk state an attacker can roll back. Falls back to [fallback]
  /// (used under `flutter test` where the platform channel is unavailable).
  Future<SessionBlob> loadPersistedBlob({required SessionBlob fallback}) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final token = prefs.getString(prefsTokenKey);
      final epoch = prefs.getInt(prefsEpochKey);
      if (token != null && epoch != null) {
        return SessionBlob(token: token, epoch: epoch);
      }
    } on MissingPluginException {
      // Fall through to the fallback blob.
    } catch (_) {
      // Fall through to the fallback blob.
    }
    return fallback;
  }
}
