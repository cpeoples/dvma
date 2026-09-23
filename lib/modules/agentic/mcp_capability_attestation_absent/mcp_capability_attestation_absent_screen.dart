import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'mcp_capability_registry.dart';

/// MCP Connector Capability Attestation Absent.
///
/// A connector self-declares a privileged scope it was never issued; a host
/// that does not attest capabilities authorizes it anyway.
class McpCapabilityAttestationAbsentScreen extends StatefulWidget {
  const McpCapabilityAttestationAbsentScreen({super.key});

  static const String vulnId = 'mcp_capability_attestation_absent';

  @override
  State<McpCapabilityAttestationAbsentScreen> createState() =>
      _McpCapabilityAttestationAbsentScreenState();
}

class _McpCapabilityAttestationAbsentScreenState
    extends State<McpCapabilityAttestationAbsentScreen> {
  // The host issued this connector a read-only scope only. The privileged
  // transfer scope below was never granted to it.
  static const String _connector = 'notes-sync-connector';
  static const String _issuedScope = 'notes.read';
  static const String _privilegedScope = 'payments.transfer';

  // The connector's handshake CLAIMS a scope it was never issued.
  final _handshake = const ConnectorHandshake(
    connectorId: _connector,
    declaredScopes: {_issuedScope, _privilegedScope},
  );

  String? _result;

  Future<void> _verify() async {
    final registry = McpCapabilityRegistry()
      // Seed what the host actually issued: read-only, no transfer.
      ..issueGrant(McpCapabilityRegistry.mint(_connector, {_issuedScope}));

    final unattested = await registry.authorize(_handshake, _privilegedScope);
    final attested = registry.authorizeAttested(_handshake, _privilegedScope);

    if (!mounted) return;
    setState(
      () => _result =
          'requested scope   : $_privilegedScope\n'
          'host issued        : $_issuedScope (only)\n\n'
          'no-attestation host: '
          '${unattested.authorized ? "AUTHORIZED" : "refused"} '
          '(${unattested.basis})'
          '${unattested.effect != null ? "\n  effect          : ${unattested.effect}" : ""}\n\n'
          'attested host      : '
          '${attested.authorized ? "AUTHORIZED" : "refused"} '
          '(${attested.basis})',
    );

    // Evidence: fires when the no-attestation host authorized a scope the host
    // never issued to the connector, and the privileged call actually ran.
    if (unattested.authorized) {
      DvmaEvidence.record(
        McpCapabilityAttestationAbsentScreen.vulnId,
        'capability',
        'connector "$_connector" was issued only "$_issuedScope" but '
            'self-declared "$_privilegedScope"; no-attestation host authorized '
            'it (${unattested.effect ?? "no listener"}). Attested host verdict: '
            '${attested.authorized ? "authorized" : "refused"}.',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: McpCapabilityAttestationAbsentScreen.vulnId,
      title: 'MCP Capability Attestation Absent',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An MCP connector declares the capabilities (scopes) it holds during '
          'its handshake, and the agent host authorizes tool calls from that '
          'self-declared list alone. With no attestation, the host cannot tell '
          'a scope it actually issued from one the connector merely claims, so '
          'a connector that lists a privileged scope it was never granted is '
          'authorized to use it. This QA check provisions a connector with a '
          'read-only scope, has it declare a privileged transfer scope it was '
          'never issued, and compares two hosts: the no-attestation host '
          'authorizes the call (and the privileged call runs as a real, '
          'network-observable request), while the attested host verifies each '
          'scope against the signed grant it issued and refuses.',
      children: [
        DemoActionButton(
          label: 'Run capability-attestation check',
          onPressed: _verify,
        ),
        if (_result != null)
          EvidencePanel(label: 'authorization verdict', value: _result!),
      ],
    );
  }
}
