/// Biometric Authorization Not Bound to Operation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-304 / CWE-294 / CWE-287): the biometric prompt
/// returns a plain boolean "success" that is not cryptographically bound to the
/// operation being authorized (no CryptoObject-signed challenge). Because the
/// success token carries no operation identity, a success captured for
/// operation A can be REPLAYED to authorize a different sensitive operation B,
/// and an overlaid prompt lets the attacker capture/redirect the result
/// (Android BiometricPrompt CVE-2025-48528 class).
///
/// This is an offline + deterministic SIMULATION. [BiometricAuthorizer]'s
/// vulnerable [authorize] returns a reusable success token unrelated to the
/// operationId; the secure [authorizeSafe] binds the biometric result to a
/// per-operation signed challenge (CryptoObject-style) so the token only
/// authorizes the exact operation it was minted for.
library;

/// A biometric authorization token returned to the app.
class AuthToken {
  const AuthToken({
    required this.success,
    required this.boundOperationId,
    required this.signature,
  });

  /// Whether the biometric prompt reported success.
  final bool success;

  /// The operation this token is bound to (null on the vuln path - unbound).
  final String? boundOperationId;

  /// The CryptoObject signature over the operation challenge (secure path).
  final String? signature;
}

/// The outcome of using a token to authorize an operation.
class AuthorizationResult {
  const AuthorizationResult({
    required this.operationId,
    required this.authorized,
    required this.replayed,
    this.denyReason,
  });

  /// The operation the caller is trying to authorize.
  final String operationId;

  /// Whether the operation was authorized.
  final bool authorized;

  /// True when a token minted for a DIFFERENT operation authorized this one -
  /// the replay hit.
  final bool replayed;

  /// Why the secure authorizer refused.
  final String? denyReason;
}

class BiometricAuthorizer {
  BiometricAuthorizer();

  /// A low-value operation the user genuinely authorizes.
  static const String operationView = 'op:view-balance';

  /// A high-value operation the attacker replays the success onto.
  static const String operationTransfer = 'op:wire-transfer-9000usd';

  /// Per-operation server challenges (the thing a CryptoObject signs).
  static const Map<String, String> _challenges = {
    operationView: 'chal-view-11aa',
    operationTransfer: 'chal-transfer-77zz',
  };

  /// VULN: the prompt returns a bare boolean success with no operation binding.
  /// The token can be reused/replayed for any operation.
  AuthToken authorize(String operationId, {required bool promptSuccess}) {
    return AuthToken(
      success: promptSuccess,
      boundOperationId: null, // unbound: nothing ties this to operationId.
      signature: null,
    );
  }

  /// VULN: authorize [operationId] from any successful token, ignoring which
  /// operation it was produced for. A success captured for A authorizes B.
  AuthorizationResult useToken(String operationId, AuthToken token) {
    if (!token.success) {
      return AuthorizationResult(
        operationId: operationId,
        authorized: false,
        replayed: false,
        denyReason: 'biometric prompt did not succeed',
      );
    }
    // No check that the token was minted for THIS operation. An unbound token
    // (vuln path) carries no operation identity, so authorizing any operation
    // with it is a replay; a bound token used for a different operation is too.
    final replayed =
        token.boundOperationId == null || token.boundOperationId != operationId;
    return AuthorizationResult(
      operationId: operationId,
      authorized: true,
      replayed: replayed,
    );
  }

  /// SECURE contrast: bind the biometric result to a per-operation signed
  /// challenge (CryptoObject-style). The returned token carries the operation
  /// id + a signature over that operation's challenge.
  AuthToken authorizeSafe(String operationId, {required bool promptSuccess}) {
    if (!promptSuccess) {
      return const AuthToken(
        success: false,
        boundOperationId: null,
        signature: null,
      );
    }
    final challenge = _challenges[operationId];
    return AuthToken(
      success: true,
      boundOperationId: operationId,
      signature: challenge == null ? null : 'sig($operationId:$challenge)',
    );
  }

  /// SECURE contrast: authorize only when the token's signature matches the
  /// challenge for THIS operation. A token minted for another operation fails
  /// the signature check and is rejected (replay blocked).
  AuthorizationResult useTokenSafe(String operationId, AuthToken token) {
    if (!token.success || token.signature == null) {
      return AuthorizationResult(
        operationId: operationId,
        authorized: false,
        replayed: false,
        denyReason: 'no signed biometric assertion for this operation',
      );
    }
    final expected = _challenges[operationId] == null
        ? null
        : 'sig($operationId:${_challenges[operationId]})';
    if (token.signature != expected) {
      return AuthorizationResult(
        operationId: operationId,
        authorized: false,
        replayed: false,
        denyReason:
            'biometric assertion bound to '
            '${token.boundOperationId}, not $operationId',
      );
    }
    return AuthorizationResult(
      operationId: operationId,
      authorized: true,
      replayed: false,
    );
  }
}
