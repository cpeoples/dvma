import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'vpn_tunnel.dart';

/// VPN Provider Trust-Anchor Abuse.
///
/// An app providing a device-wide VPN tunnel authenticates the tunnel endpoint
/// weakly (disabled/loose cert validation, accept-all trust manager, hostname
/// bypass, user-controllable CA), so an adjacent attacker MITMs all tunneled
/// traffic (Prisma Access VPN-agent cert-validation MITM CVE-2026-0248 class).
class VpnProviderTrustAnchorAbuseScreen extends StatefulWidget {
  const VpnProviderTrustAnchorAbuseScreen({super.key});

  static const String vulnId = 'vpn_provider_trust_anchor_abuse';

  @override
  State<VpnProviderTrustAnchorAbuseScreen> createState() =>
      _VpnProviderTrustAnchorAbuseScreenState();
}

class _VpnProviderTrustAnchorAbuseScreenState
    extends State<VpnProviderTrustAnchorAbuseScreen> {
  static const Endpoint _rogue = VpnTunnel.rogueEndpoint;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(TunnelResult r) {
    final b = StringBuffer();
    b.writeln('expected host      : ${r.endpointHost}');
    b.writeln('cert subject       : ${_rogue.cert.subject}');
    b.writeln('hostname matches   : ${_rogue.cert.hostnameMatches}');
    b.writeln('chain trusted      : ${_rogue.cert.chainTrusted}');
    b.writeln('ca user-installed  : ${_rogue.cert.caUserInstalled}');
    b.writeln('tunnel established : ${r.established}');
    b.writeln('mitm possible      : ${r.mitmPossible}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: query VpnService.prepare() to learn whether a VPN
    // consent already exists for this app, plus report the trust-anchor gap.
    final native = await SystemProviderBridge.vpnConsentState();

    // VULN: an accept-all trust manager establishes a tunnel to a rogue MITM
    // endpoint despite a mismatched hostname and untrusted chain.
    final vulnTunnel = VpnTunnel();
    final vuln = vulnTunnel.connect(_rogue);

    // SECURE: the same rogue endpoint is refused (user-CA / untrusted chain /
    // hostname mismatch), so no MITM tunnel is established.
    final secureTunnel = VpnTunnel();
    final secure = secureTunnel.connectSafe(_rogue);

    await DvmaEvidence.record(
      VpnProviderTrustAnchorAbuseScreen.vulnId,
      'vpn-trust-anchor',
      'nativeConsentState=${native ?? 'unavailable (off-Android fallback)'} :: '
          'rogueTunnelEstablished=${vuln.established} :: '
          'mitmPossible=${vuln.mitmPossible} :: '
          'secureDenyReason=${secure.denyReason}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? 'native unavailable (off-Android fallback)';
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: VpnProviderTrustAnchorAbuseScreen.vulnId,
      title: 'VPN Provider Trust-Anchor Abuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An app that provides a device-wide VPN tunnel is the trust anchor '
          'for ALL tunneled traffic. Here it authenticates the tunnel endpoint '
          'with an accept-all trust manager - certificate validation is '
          'effectively disabled - so it establishes a tunnel to a rogue MITM '
          'endpoint whose certificate hostname does not match, whose chain is '
          'untrusted, and which is anchored to a user-installed CA. Every flow '
          'routed through the tunnel is now interceptable (Prisma Access '
          'VPN-agent cert-validation MITM CVE-2026-0248 class). The secure path '
          'enforces chain trust and hostname match and rejects user-installed '
          'CAs, so the rogue endpoint is refused. The "real state" panel shows '
          "this device's VpnService consent state (VpnService.prepare()); to "
          'fully arm a device-wide tunnel, implement a VpnService, confirm the '
          'system VPN consent dialog, and start it as a foreground service.',
      children: [
        DemoActionButton(
          label: 'Connect tunnel to rogue endpoint',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real VpnService consent state (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'accept-all trust manager -> MITM tunnel established',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'chain + hostname + CA checks reject rogue endpoint',
            value: _secureResult!,
          ),
      ],
    );
  }
}
