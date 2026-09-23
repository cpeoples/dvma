import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

/// Unsafe-deserialization helper.
///
/// INTENTIONALLY VULNERABLE (CWE-502): deserializes untrusted JSON into a
/// privileged typed object with no validation, it trusts attacker-controlled
/// fields like `isAdmin` and `role`, and blindly instantiates a "type" named in
/// the payload. A safe deserializer validates every field and never lets the
/// input choose a type or privilege level.
///
/// Pure Dart so a unit test can assert a hostile payload still yields an
/// admin/privileged object.
class UnsafeDeserializer {
  UnsafeDeserializer._();

  /// Parses [rawJson] straight into a [UserSession], trusting all fields.
  static UserSession fromUntrusted(String rawJson) {
    final map = jsonDecode(rawJson) as Map<String, Object?>;
    return UserSession(
      username: map['username'] as String? ?? 'guest',
      // VULN: privilege comes straight from attacker-controlled input.
      isAdmin: map['isAdmin'] as bool? ?? false,
      role: map['role'] as String? ?? 'user',
      // VULN: the payload can name the class to build ("gadget chain" idea).
      handlerType: map['__type'] as String? ?? 'Default',
    );
  }

  /// SharedPreferences key the built session is persisted under.
  static const String sessionKey = 'deserialized_session';

  /// VULN (real): deserialize the untrusted payload AND persist the resulting
  /// privileged object to SharedPreferences, so the injected `isAdmin`/`role`
  /// survives on disk and is recoverable across launches. This is the real
  /// effect, the attacker-chosen privilege is now durable state, not a
  /// transient in-memory object. Returns the built (and stored) session.
  static Future<UserSession> fromUntrustedAndPersist(String rawJson) async {
    final session = fromUntrusted(rawJson);
    final prefs = await SharedPreferences.getInstance();
    // Store the trusted-verbatim privileged object as JSON.
    await prefs.setString(sessionKey, session.toStorageJson());
    return session;
  }

  /// Read the persisted session back off disk (proves the injected privilege
  /// survived). Returns null when nothing was stored.
  static Future<UserSession?> loadPersisted() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(sessionKey);
    if (raw == null) return null;
    final map = jsonDecode(raw) as Map<String, Object?>;
    return UserSession(
      username: map['username'] as String? ?? 'guest',
      isAdmin: map['isAdmin'] as bool? ?? false,
      role: map['role'] as String? ?? 'user',
      handlerType: map['handlerType'] as String? ?? 'Default',
    );
  }

  /// The raw stored value on disk (the recoverable artifact), or null.
  static Future<String?> rawPersisted() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(sessionKey);
  }

  /// SECURE contrast: validate against a strict schema/allowlist and never let
  /// the input choose privilege or a type. Privilege is fixed to a safe default
  /// server-side; only a whitelisted role is honored; unknown `__type` is
  /// rejected. Nothing attacker-controlled is persisted with authority. Throws
  /// [FormatException] on a hostile payload.
  static UserSession fromTrustedSchema(String rawJson) {
    final decoded = jsonDecode(rawJson);
    if (decoded is! Map<String, Object?>) {
      throw const FormatException('payload is not a JSON object');
    }
    const allowedRoles = {'user', 'viewer'};
    final username = decoded['username'];
    if (username is! String || username.isEmpty || username.length > 64) {
      throw const FormatException('invalid username');
    }
    final role = decoded['role'] is String ? decoded['role'] as String : 'user';
    final safeRole = allowedRoles.contains(role) ? role : 'user';
    if (decoded.containsKey('__type')) {
      throw const FormatException('payload-named types are not permitted');
    }
    return UserSession(
      username: username,
      // SECURE: privilege is never taken from the input.
      isAdmin: false,
      role: safeRole,
      handlerType: 'Default',
    );
  }
}

/// A privileged session object populated directly from untrusted input.
class UserSession {
  UserSession({
    required this.username,
    required this.isAdmin,
    required this.role,
    required this.handlerType,
  });

  final String username;
  final bool isAdmin;
  final String role;
  final String handlerType;

  /// Serialize for persistence (the recoverable on-disk artifact).
  String toStorageJson() => jsonEncode({
    'username': username,
    'isAdmin': isAdmin,
    'role': role,
    'handlerType': handlerType,
  });

  @override
  String toString() =>
      'UserSession(username=$username, isAdmin=$isAdmin, role=$role, '
      'handlerType=$handlerType)';
}
