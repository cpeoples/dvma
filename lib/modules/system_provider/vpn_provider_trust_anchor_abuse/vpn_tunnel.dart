/// VPN Provider Trust-Anchor Abuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-295 / CWE-297 / CWE-940): an app that provides
/// a device-wide VPN tunnel is the trust anchor for ALL tunneled traffic. If it
/// authenticates the tunnel ENDPOINT weakly - certificate validation disabled,
/// an accept-all trust manager, hostname verification bypassed, or a
/// user-installed CA honored - an adjacent attacker can present a rogue
/// certificate and MITM every flow routed through the tunnel (Prisma Access
/// VPN-agent cert-validation MITM CVE-2026-0248 class). This is the whole-device
/// VPN provider as trust anchor, distinct from per-app pinning.
///
/// This is an offline + deterministic SIMULATION. [VpnTunnel] establishes a
/// connection to an [Endpoint] presenting a [TunnelCertificate] with fields
/// like `hostnameMatches`, `chainTrusted`, and `caUserInstalled`. The
/// vulnerable [connect] accepts any certificate (validation disabled), so a
/// rogue endpoint is established and MITM is possible. The secure [connectSafe]
/// enforces chain trust + hostname match and rejects user-installed CAs, so a
/// rogue endpoint is refused.
library;

/// The certificate a VPN endpoint presents during the handshake.
class TunnelCertificate {
  const TunnelCertificate({
    required this.subject,
    required this.hostnameMatches,
    required this.chainTrusted,
    required this.caUserInstalled,
  });

  /// The certificate subject / advertised host.
  final String subject;

  /// Whether the certificate hostname matches the expected endpoint host.
  final bool hostnameMatches;

  /// Whether the certificate chains to a trusted system root.
  final bool chainTrusted;

  /// Whether the anchoring CA was installed by the user (attacker-controllable).
  final bool caUserInstalled;
}

/// A VPN tunnel endpoint the provider connects to.
class Endpoint {
  const Endpoint({required this.host, required this.cert});

  /// The expected endpoint host.
  final String host;

  /// The certificate this endpoint presents.
  final TunnelCertificate cert;
}

/// The outcome of establishing a tunnel to an endpoint.
class TunnelResult {
  const TunnelResult({
    required this.endpointHost,
    required this.established,
    required this.mitmPossible,
    this.denyReason,
  });

  /// The endpoint host the provider tried to reach.
  final String endpointHost;

  /// Whether the tunnel was established.
  final bool established;

  /// True when a tunnel was established to an unauthenticated endpoint - the
  /// hit (all tunneled traffic is now MITM-able).
  final bool mitmPossible;

  /// Why the secure flow refused.
  final String? denyReason;
}

class VpnTunnel {
  /// The legitimate corporate VPN endpoint.
  static const String expectedHost = 'vpn.corp.example';

  /// A rogue MITM endpoint presenting a mismatched, untrusted, user-CA cert.
  static const Endpoint rogueEndpoint = Endpoint(
    host: 'vpn.corp.example',
    cert: TunnelCertificate(
      subject: 'attacker-gateway.evil.example',
      hostnameMatches: false,
      chainTrusted: false,
      caUserInstalled: true,
    ),
  );

  /// The genuine endpoint with a properly validating certificate.
  static const Endpoint genuineEndpoint = Endpoint(
    host: 'vpn.corp.example',
    cert: TunnelCertificate(
      subject: 'vpn.corp.example',
      hostnameMatches: true,
      chainTrusted: true,
      caUserInstalled: false,
    ),
  );

  /// VULN: accept ANY certificate (validation disabled / accept-all trust
  /// manager). The tunnel is established even when the hostname mismatches and
  /// the chain is untrusted, so all tunneled traffic can be intercepted.
  TunnelResult connect(Endpoint endpoint) {
    // No chain / hostname / CA checks: an accept-all trust manager.
    final unauthenticated =
        !endpoint.cert.chainTrusted ||
        !endpoint.cert.hostnameMatches ||
        endpoint.cert.caUserInstalled;
    return TunnelResult(
      endpointHost: endpoint.host,
      established: true,
      mitmPossible: unauthenticated,
    );
  }

  /// SECURE contrast: enforce chain trust AND hostname match, and reject
  /// endpoints anchored to a user-installed CA. A rogue endpoint is refused, so
  /// no MITM tunnel is established.
  TunnelResult connectSafe(Endpoint endpoint) {
    final cert = endpoint.cert;
    if (cert.caUserInstalled) {
      return TunnelResult(
        endpointHost: endpoint.host,
        established: false,
        mitmPossible: false,
        denyReason:
            'endpoint certificate anchored to a user-installed CA - '
            'refusing tunnel',
      );
    }
    if (!cert.chainTrusted) {
      return TunnelResult(
        endpointHost: endpoint.host,
        established: false,
        mitmPossible: false,
        denyReason:
            'endpoint certificate chain is not trusted - '
            'refusing tunnel',
      );
    }
    if (!cert.hostnameMatches) {
      return TunnelResult(
        endpointHost: endpoint.host,
        established: false,
        mitmPossible: false,
        denyReason:
            'endpoint certificate hostname "${cert.subject}" does not '
            'match expected host "${endpoint.host}" - refusing tunnel',
      );
    }
    return TunnelResult(
      endpointHost: endpoint.host,
      established: true,
      mitmPossible: false,
    );
  }
}
