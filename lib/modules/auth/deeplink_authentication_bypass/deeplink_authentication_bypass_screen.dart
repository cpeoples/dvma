import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'deeplink_auth_router.dart';

/// Deep Link Authentication Bypass.
///
/// A deep link routes directly to an authenticated screen/function, skipping
/// the app-lock / login gate the normal navigation path enforces (Groww
/// CVE-2026-12065 class).
class DeeplinkAuthenticationBypassScreen extends StatefulWidget {
  const DeeplinkAuthenticationBypassScreen({super.key});

  static const String vulnId = 'deeplink_authentication_bypass';

  @override
  State<DeeplinkAuthenticationBypassScreen> createState() =>
      _DeeplinkAuthenticationBypassScreenState();
}

class _DeeplinkAuthenticationBypassScreenState
    extends State<DeeplinkAuthenticationBypassScreen> {
  final TextEditingController _controller = TextEditingController(
    text: 'dvma://wallet',
  );

  bool _loggedIn = false;
  String? _vulnResult;
  String? _secureResult;

  Future<void> _follow() async {
    final link = _controller.text.trim();
    final vulnRouter = DeeplinkAuthRouter(isAuthenticated: _loggedIn);
    final secureRouter = DeeplinkAuthRouter(isAuthenticated: _loggedIn);
    final vuln = DeeplinkAuthRouter.navigate(vulnRouter, link);
    final secure = DeeplinkAuthRouter.navigateSafe(secureRouter, link);
    // real artifact: record the protected screen + content the deep link
    // reached while the user was logged out (auth gate skipped).
    await DvmaEvidence.record(
      DeeplinkAuthenticationBypassScreen.vulnId,
      'auth-bypass',
      'loggedIn=$_loggedIn deep link=$link opened screen=${vuln.screen} '
          'content=${vuln.content} (${vuln.reason})',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult =
          'opened: ${vuln.screen ?? '(none)'}\n'
          'content: ${vuln.content ?? '(none)'}\n'
          '${vuln.reason}';
      _secureResult =
          'opened: ${secure.screen ?? '(none)'}\n'
          'content: ${secure.content ?? '(none)'}\n'
          '${secure.reason}';
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeeplinkAuthenticationBypassScreen.vulnId,
      title: 'Deep Link Authentication Bypass',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A deep link routes directly to an authenticated screen (dvma://wallet, '
          'dvma://transfer), skipping the app-lock / login gate the normal '
          'in-app navigation enforces. The vulnerable router honors the '
          'requested target WITHOUT checking whether the user is authenticated, '
          'so an attacker-triggered link opens the wallet and returns its '
          'balance while the user is logged OUT (the Groww CVE-2026-12065 '
          'class). This is an offline, deterministic simulation: routes and '
          'their requiresAuth flags are an in-memory table. The secure router '
          'enforces the auth gate and redirects protected routes to login.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'incoming deep link',
              hintText: 'dvma://wallet',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Logged in?'),
            value: _loggedIn,
            onChanged: (v) => setState(() => _loggedIn = v),
          ),
        ),
        DemoActionButton(label: 'Follow deep link', onPressed: _follow),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'deep-link router (no auth gate)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(label: 'auth-enforcing router', value: _secureResult!),
      ],
    );
  }
}
