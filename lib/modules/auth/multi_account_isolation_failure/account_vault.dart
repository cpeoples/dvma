/// Multi-Account Isolation Failure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-459 / CWE-200 / CWE-613): when the user
/// switches accounts (or logs out of account A and into account B), the app
/// does not fully clear account A's cached credentials, tokens, and data. The
/// per-account isolation boundary on a single device fails, so account B can
/// read - or act with - account A's token and private data, and account A's
/// old session survives logout.
///
/// This is an offline + deterministic SIMULATION. [AccountVault] models a
/// process-wide cache that the vulnerable path shares across principals: it
/// keeps a single "current token"/"current note" plus a `sessions` map that is
/// never cleared, so after `switchTo(B)` a `readToken()` still returns A's
/// token. The secure path (`switchToSafe`/`logoutSafe`) scopes all per-account
/// state to the active principal and wipes/rotates it on switch and logout, so
/// A's data is gone the moment B becomes active.
///
/// real ARTIFACT: each account's token is ALSO persisted to SharedPreferences
/// under a per-account key (`account_token_<email>`) on login. The vulnerable
/// switch does not delete the previous account's prefs entry, so on Android the
/// backing file `/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml` -
/// adb-pullable/objection-readable in cleartext, holds account A's token after
/// switching to B. The secure switch removes the previous account's persisted
/// token. A MissingPluginException keeps the sync simulation working under
/// `flutter test`.
library;

import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

/// The result of reading the vault after a login/switch/logout operation.
class AccountAccessResult {
  const AccountAccessResult({
    required this.activeAccount,
    required this.readableToken,
    required this.readableNote,
    required this.ownerOfReadableData,
    required this.leakedAcrossAccounts,
    required this.previousAccountDataVisible,
    required this.liveSessions,
  });

  /// The account the app currently considers signed in.
  final String activeAccount;

  /// The token a caller can read from the vault right now.
  final String? readableToken;

  /// The private note a caller can read from the vault right now.
  final String? readableNote;

  /// Which account actually owns the currently-readable data.
  final String? ownerOfReadableData;

  /// True when the readable data belongs to an account other than the active
  /// one - the cross-account leak (the hit).
  final bool leakedAcrossAccounts;

  /// True when the previous account's data is still visible after switching.
  final bool previousAccountDataVisible;

  /// Accounts whose sessions are still live (survived logout/switch).
  final List<String> liveSessions;
}

class AccountVault {
  /// The first (victim) account.
  static const String accountA = 'alice@example.com';

  /// The second account that logs in on the same device.
  static const String accountB = 'bob@example.com';

  /// Account A's secret session token.
  static const String secretTokenA = 'A-token-8f3c1d94e2';

  /// Account A's private note.
  static const String privateNoteA = 'alice: recovery phrase drawer, top-left';

  /// Account B's own token (issued when B logs in).
  static const String secretTokenB = 'B-token-1a77b0c4d5';

  // --- Shared, process-wide cache (the isolation failure) -------------------
  String? _currentToken;
  String? _currentNote;
  String? _tokenOwner;
  String? _noteOwner;
  String _active = '';

  /// A "sessions" map the vulnerable path never clears on logout/switch.
  final Map<String, String> _sessions = <String, String>{};

  int _tokenCounter = 0;

  String _issueToken(String account) {
    if (account == accountA) return secretTokenA;
    if (account == accountB) return secretTokenB;
    _tokenCounter++;
    return '$account-token-gen$_tokenCounter';
  }

  // --- VULNERABLE flow ------------------------------------------------------

  /// Log in [account], caching its token/note in the shared slots.
  void login(String account) {
    _active = account;
    _currentToken = _issueToken(account);
    _tokenOwner = account;
    _currentNote = account == accountA ? privateNoteA : null;
    _noteOwner = account == accountA ? account : null;
    _sessions[account] = _currentToken!;
    // real ARTIFACT: persist this account's token to the shared_prefs XML.
    // Fire-and-forget so the sync simulation is unaffected.
    _persistToken(account, _currentToken!);
  }

  /// VULN: switch the active account WITHOUT clearing the cached token/note or
  /// tearing down the previous session. The shared slots still hold whatever
  /// the previous principal put there, so it stays readable to the new one.
  AccountAccessResult switchTo(String account) {
    _active = account;
    // No wipe: _currentToken/_currentNote/_sessions all retain account A's data.
    return _snapshot();
  }

  /// VULN: "log out" by only flipping a flag; the cached token/note and the
  /// session entry survive, so the old session is still usable.
  AccountAccessResult logout() {
    _active = '';
    // Intentionally does not clear _currentToken/_currentNote/_sessions.
    return _snapshot();
  }

  // --- SECURE flow ----------------------------------------------------------

  /// SECURE: switching principals wipes all cached per-account state and
  /// rotates to the new account's own data, so nothing from the previous
  /// account remains readable.
  AccountAccessResult switchToSafe(String account) {
    final previous = _active;
    _wipeAll();
    login(account);
    // Only the newly-active account's own session should remain live.
    _sessions
      ..clear()
      ..[account] = _currentToken!;
    // real ARTIFACT: also purge the previous account's persisted token so it
    // does not linger on disk after the switch.
    if (previous.isNotEmpty && previous != account) {
      _removePersisted(previous);
    }
    return _snapshot();
  }

  /// SECURE: logout fully wipes cached state and revokes the session so the old
  /// session cannot survive.
  AccountAccessResult logoutSafe() {
    final previous = _active;
    _wipeAll();
    if (previous.isNotEmpty) _removePersisted(previous);
    return _snapshot();
  }

  void _wipeAll() {
    _currentToken = null;
    _currentNote = null;
    _tokenOwner = null;
    _noteOwner = null;
    _active = '';
    _sessions.clear();
  }

  /// Read the token currently reachable from the vault (used by tests/UI).
  String? readToken() => _currentToken;

  /// Read the private note currently reachable from the vault.
  String? readCurrentData() => _currentNote;

  AccountAccessResult _snapshot() {
    // Data "belongs to" the recorded owner of whatever is cached.
    final owner = _tokenOwner ?? _noteOwner;
    final crossAccount =
        _active.isNotEmpty &&
        owner != null &&
        owner != _active &&
        (_currentToken != null || _currentNote != null);
    final previousVisible =
        owner != null &&
        owner != _active &&
        (_currentToken != null || _currentNote != null);
    return AccountAccessResult(
      activeAccount: _active.isEmpty ? '(logged out)' : _active,
      readableToken: _currentToken,
      readableNote: _currentNote,
      ownerOfReadableData: owner,
      leakedAcrossAccounts: crossAccount,
      previousAccountDataVisible: previousVisible,
      liveSessions: _sessions.keys.toList(growable: false),
    );
  }

  /// The SharedPreferences key an account's token is persisted under.
  static String prefsTokenKey(String account) => 'account_token_$account';

  /// real ARTIFACT: persist [account]'s token to the shared_prefs XML. On the
  /// vulnerable path this entry is never removed on switch, so the previous
  /// account's token lingers on disk (adb-pullable). Best effort / test-safe.
  Future<void> _persistToken(String account, String token) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsTokenKey(account), token);
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`): sim is unaffected.
    } catch (_) {
      // Best effort: never perturb the demo.
    }
  }

  /// SECURE helper: purge [account]'s persisted token from the shared_prefs XML.
  Future<void> _removePersisted(String account) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(prefsTokenKey(account));
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`).
    } catch (_) {
      // Best effort.
    }
  }

  /// Reads whatever per-account tokens are currently persisted on disk, as an
  /// attacker with `adb`/objection would recover them from the shared_prefs
  /// XML. Returns a map keyed by the known accounts that still have an entry.
  Future<Map<String, String>> dumpPersistedTokens() async {
    final out = <String, String>{};
    try {
      final prefs = await SharedPreferences.getInstance();
      for (final account in const [accountA, accountB]) {
        final token = prefs.getString(prefsTokenKey(account));
        if (token != null) out[account] = token;
      }
    } on MissingPluginException {
      // Fall through: return whatever was collected (possibly empty) under test.
    } catch (_) {
      // Best effort.
    }
    return out;
  }
}
