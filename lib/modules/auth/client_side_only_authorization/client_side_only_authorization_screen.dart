import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Client-Side-Only Authorization.
///
/// Admin-only actions gated purely by a client-side boolean flag.
class ClientSideOnlyAuthorizationScreen extends StatefulWidget {
  const ClientSideOnlyAuthorizationScreen({super.key});

  static const String vulnId = 'client_side_only_authorization';

  @override
  State<ClientSideOnlyAuthorizationScreen> createState() =>
      _ClientSideOnlyAuthorizationScreenState();
}

class _ClientSideOnlyAuthorizationScreenState
    extends State<ClientSideOnlyAuthorizationScreen> {
  // VULN: authorization is a mutable client-side boolean. The server never
  // re-checks the role, so flipping this (frida/objection, or just this toggle)
  // grants admin. Real authorization must be enforced server-side per request.
  bool _isAdmin = false;
  String? _result;

  void _deleteAllUsers() {
    if (_isAdmin) {
      const artifact =
          'ADMIN ACTION EXECUTED: deleteAllUsers() - server accepted it '
          'because the client sent the request.';
      // Real leak: a privileged action ran solely because a client-side flag
      // was flipped. Fire-and-forget mirror of the outcome the panel shows.
      DvmaEvidence.record(
        ClientSideOnlyAuthorizationScreen.vulnId,
        'authz-bypass',
        artifact,
      );
      setState(() => _result = artifact);
    } else {
      setState(() => _result = 'Button hidden/disabled for non-admins only.');
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ClientSideOnlyAuthorizationScreen.vulnId,
      title: 'Client-Side-Only Authorization',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Admin-only actions are gated solely by a client-side isAdmin flag. '
          'An attacker flips the boolean (frida/objection) or replays the '
          'request; since the server never re-authorizes, the privileged action '
          'succeeds. Toggle below to simulate the flip.',
      children: [
        SwitchListTile(
          value: _isAdmin,
          onChanged: (v) => setState(() => _isAdmin = v),
          title: const Text('isAdmin (client-side flag)'),
          activeColor: DvmaColors.accent,
        ),
        DemoActionButton(
          label: 'Delete all users (admin only)',
          onPressed: _deleteAllUsers,
        ),
        if (_result != null)
          EvidencePanel(label: 'authorization outcome', value: _result!),
      ],
    );
  }
}
