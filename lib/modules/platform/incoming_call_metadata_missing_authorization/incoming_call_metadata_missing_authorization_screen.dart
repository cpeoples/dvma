import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'call_metadata_provider.dart';

/// Incoming-Call Metadata Read (Missing Authorization class).
///
/// Reproduces CVE-2026-0057: a provider returns an incoming call's number and
/// metadata with no permission check, so an unprivileged caller reads it.
class IncomingCallMetadataMissingAuthorizationScreen extends StatefulWidget {
  const IncomingCallMetadataMissingAuthorizationScreen({super.key});

  static const String vulnId = 'incoming_call_metadata_missing_authorization';

  @override
  State<IncomingCallMetadataMissingAuthorizationScreen> createState() =>
      _IncomingCallMetadataMissingAuthorizationScreenState();
}

class _IncomingCallMetadataMissingAuthorizationScreenState
    extends State<IncomingCallMetadataMissingAuthorizationScreen> {
  final _provider = CallMetadataProvider();
  String? _result;

  Future<void> _run() async {
    // On Android, read the real unguarded /calls path through the resolver;
    // off-Android fall back to the offline provider model.
    final native = await ProviderIpcBridge.callLog();
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        IncomingCallMetadataMissingAuthorizationScreen.vulnId,
        'missing-authorization',
        'read incoming-call metadata from the real exported provider with no '
            'permission check and no user interaction:\n$native',
      );
      if (!mounted) return;
      setState(
        () => _result =
            'unprivileged read of '
            'content://com.dvma.provider.vuln/calls (REAL provider, no '
            'permission check):\n$native',
      );
      return;
    }
    final leaked = _provider.readLatestIncoming(hasPermission: false);
    final denied = _provider.secureReadLatestIncoming(hasPermission: false);
    if (!mounted) return;
    setState(
      () => _result =
          'unprivileged read (offline model): '
          '${leaked ?? "(none)"}\n'
          'same read on hardened path (permission enforced): '
          '${denied ?? "(denied)"}',
    );
    if (leaked != null) {
      DvmaEvidence.record(
        IncomingCallMetadataMissingAuthorizationScreen.vulnId,
        'missing-authorization',
        'read incoming-call metadata with no permission check and no user '
            'interaction: $leaked',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: IncomingCallMetadataMissingAuthorizationScreen.vulnId,
      title: 'Incoming-Call Metadata Read',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A provider path returns an incoming call\'s phone number and '
          'associated metadata without checking the caller\'s permission, so a '
          'local app reads it with zero grants and no user interaction. This '
          'reproduces the Android 17 Contacts-Provider missing-authorization '
          'read (CVE-2026-0057); the hardened path enforces the permission the '
          'vulnerable path omits.',
      children: [
        DemoActionButton(label: 'Read as unprivileged app', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'call-metadata read', value: _result!),
      ],
    );
  }
}
