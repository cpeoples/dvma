import 'package:http/http.dart' as http;

import '../../../core/config/dvma_env.dart';

/// A capability grant the host issued to a connector when it was provisioned.
///
/// [signature] is the host's attestation over `connectorId + scopes`. The host
/// keeps the issuing key, so a connector cannot forge a grant for a scope the
/// host never issued.
class AttestedGrant {
  const AttestedGrant({
    required this.connectorId,
    required this.scopes,
    required this.signature,
  });

  final String connectorId;
  final Set<String> scopes;
  final String signature;
}

/// An MCP connector's capability handshake: the scopes it CLAIMS to hold.
///
/// The claim is attacker-controllable metadata. Whether it reflects a scope the
/// host actually issued is exactly what attestation is supposed to establish.
class ConnectorHandshake {
  const ConnectorHandshake({
    required this.connectorId,
    required this.declaredScopes,
  });

  final String connectorId;
  final Set<String> declaredScopes;
}

/// The outcome of a host authorizing one tool call against a requested scope.
class AuthorizationOutcome {
  const AuthorizationOutcome({
    required this.scope,
    required this.authorized,
    required this.basis,
    this.effect,
  });

  /// The privileged scope the call needed (e.g. `payments.transfer`).
  final String scope;

  /// Whether the host allowed the call.
  final bool authorized;

  /// Why the host decided as it did (self-declared list vs attested grant).
  final String basis;

  /// The observable side effect when an authorized privileged call ran.
  final String? effect;
}

/// Host-side capability registry for connected MCP servers.
///
/// INTENTIONALLY VULNERABLE (CWE-290 / CWE-862, OWASP ASI04): [authorize]
/// grants a tool call whenever the connector's own [ConnectorHandshake]
/// declares the scope. The host performs no attestation, so it cannot
/// distinguish a scope it actually issued from one the connector merely claims.
/// [authorizeAttested] is the hardened counterpart: it verifies each requested
/// scope against the signed [AttestedGrant] the host issued at provisioning and
/// refuses any scope it did not issue.
///
/// This models a QA/verification harness a mobile security engineer runs to
/// confirm whether an agent host attests connector capabilities before trusting
/// them. The privileged effect is a real, network-observable POST so the
/// verdict is evidence-backed rather than asserted.
class McpCapabilityRegistry {
  McpCapabilityRegistry();

  /// The scopes the host actually issued, keyed by connector id. A hardened
  /// host consults this; the vulnerable path never does.
  final Map<String, AttestedGrant> _issued = {};

  /// Provision a connector with the scopes the host genuinely grants it.
  void issueGrant(AttestedGrant grant) => _issued[grant.connectorId] = grant;

  /// VULN: authorize a tool call from the connector's self-declared scopes
  /// alone. If the handshake lists [requestedScope], the call is allowed and
  /// its privileged effect executes.
  Future<AuthorizationOutcome> authorize(
    ConnectorHandshake handshake,
    String requestedScope,
  ) async {
    final allowed = handshake.declaredScopes.contains(requestedScope);
    String? effect;
    if (allowed) {
      effect = await _runPrivilegedCall(handshake.connectorId, requestedScope);
    }
    return AuthorizationOutcome(
      scope: requestedScope,
      authorized: allowed,
      basis: 'connector self-declared scopes (no attestation)',
      effect: effect,
    );
  }

  /// SECURE: authorize only if the host issued the scope to this connector and
  /// the grant's signature verifies. A self-declared scope with no matching
  /// issued grant is refused.
  AuthorizationOutcome authorizeAttested(
    ConnectorHandshake handshake,
    String requestedScope,
  ) {
    final grant = _issued[handshake.connectorId];
    final attested =
        grant != null &&
        grant.scopes.contains(requestedScope) &&
        _signatureValid(grant);
    return AuthorizationOutcome(
      scope: requestedScope,
      authorized: attested,
      basis: attested
          ? 'host-issued attested grant (signature verified)'
          : 'refused: scope not in a host-issued grant',
    );
  }

  /// The host recomputes the attestation over `connectorId + scopes` and
  /// compares it to the grant's signature. A forged grant fails here.
  bool _signatureValid(AttestedGrant grant) =>
      grant.signature == _attest(grant.connectorId, grant.scopes);

  /// The host's issuing routine. In a real host this is an HMAC/signature over
  /// the granted scopes with a host-held key; the shared secret here stands in
  /// for that key so the demo is deterministic and offline-testable.
  static String _attest(String connectorId, Set<String> scopes) {
    final ordered = scopes.toList()..sort();
    return 'host-sig:$connectorId:${ordered.join(",")}';
  }

  /// Issues a valid grant the way a correct host would (used to seed the
  /// hardened path and by tests).
  static AttestedGrant mint(String connectorId, Set<String> scopes) =>
      AttestedGrant(
        connectorId: connectorId,
        scopes: scopes,
        signature: _attest(connectorId, scopes),
      );

  /// Executes the privileged tool call as a real request to the capture
  /// listener so the effect is observable in a lab. Best effort: a missing
  /// listener never hard-fails the demo.
  Future<String> _runPrivilegedCall(String connectorId, String scope) async {
    final uri = Uri.parse('${DvmaEnv.network.captureBase}/mcp/$scope');
    try {
      final resp = await http
          .post(
            uri,
            headers: const {'Content-Type': 'application/json'},
            body: '{"connector":"$connectorId","scope":"$scope"}',
          )
          .timeout(const Duration(seconds: 6));
      return 'POST ${uri.path} -> HTTP ${resp.statusCode}';
    } catch (_) {
      return 'POST ${uri.path} -> no response';
    }
  }
}
