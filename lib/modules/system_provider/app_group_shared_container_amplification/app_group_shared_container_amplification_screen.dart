import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_group_bridge.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'app_group_container.dart';

/// App Group Shared-Container Privilege Amplification.
///
/// Secrets stored in an App Group shared container are readable/writable by
/// every group member with no per-item access control, so a low-trust
/// extension reads or tampers with the main app's auth token.
class AppGroupSharedContainerAmplificationScreen extends StatefulWidget {
  const AppGroupSharedContainerAmplificationScreen({super.key});

  static const String vulnId = 'app_group_shared_container_amplification';

  @override
  State<AppGroupSharedContainerAmplificationScreen> createState() =>
      _AppGroupSharedContainerAmplificationScreenState();
}

class _AppGroupSharedContainerAmplificationScreenState
    extends State<AppGroupSharedContainerAmplificationScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(ContainerAccessResult r) {
    final b = StringBuffer();
    b.writeln('app group        : ${AppGroupContainer.appGroupId}');
    b.writeln('reader           : ${r.reader.id} (${r.reader.trust.name})');
    b.writeln('key              : ${r.key}');
    b.writeln('read granted     : ${r.read}');
    b.writeln('value returned   : ${r.value.isEmpty ? '(none)' : r.value}');
    b.writeln('sensitive exposed: ${r.sensitiveExposed}');
    if (r.denyReason != null) {
      b.writeln('deny reason      : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // Prefer a real native shared-container probe. On iOS this is the App Group
    // container path (dvma/app_group), which is a genuine cross-member file
    // write→read on an App-Group-entitled build and an honest
    // `entitlement-missing` report otherwise. On Android it is the real
    // external-files shared-dir path. Off-native it is null and the module runs
    // the deterministic in-app simulation below.
    final native =
        await AppGroupBridge.sharedContainerLeak(
          AppGroupContainer.authTokenKey,
          AppGroupContainer.authTokenValue,
        ) ??
        await SystemProviderBridge.sharedContainerLeak(
          AppGroupContainer.authTokenKey,
          AppGroupContainer.authTokenValue,
        );

    // VULN: the low-trust keyboard extension reads the main app's auth token
    // because group membership is treated as sufficient authorization.
    final vulnStore = AppGroupContainer()..seedAsMainApp();
    final vuln = vulnStore.read(
      AppGroupContainer.keyboardExtension,
      AppGroupContainer.authTokenKey,
    );

    // SECURE: per-item scoping denies the non-entitled reader.
    final secureStore = AppGroupContainer()..seedAsMainApp();
    final secure = secureStore.readSafe(
      AppGroupContainer.keyboardExtension,
      AppGroupContainer.authTokenKey,
    );

    const nativeUnavailable =
        'native shared-container probe unavailable on this host; showing the '
        'deterministic App Group over-read simulation below';

    await DvmaEvidence.record(
      AppGroupSharedContainerAmplificationScreen.vulnId,
      'app-group',
      'nativeSharedContainer=${native ?? nativeUnavailable} :: '
          'crossMemberRead=${vuln.value} :: '
          'sensitiveExposed=${vuln.sensitiveExposed}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? nativeUnavailable;
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AppGroupSharedContainerAmplificationScreen.vulnId,
      title: 'App Group Shared-Container Privilege Amplification',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The main app persists secrets - here an auth/session token - in an '
          'Apple App Group shared container (shared UserDefaults / a container '
          'obtained via containerURL(forSecurityApplicationGroupIdentifier:)) '
          'keyed by an app-group id. Every member of that group, including a '
          'low-trust custom keyboard extension, can read and write every item '
          'with no per-item access control. Membership amplifies privilege: the '
          'keyboard extension reads a token it should never see. "App Group '
          'used" is not the finding - over-sharing is. On an App-Group-entitled '
          'iOS build (or on Android) this runs a real cross-member file '
          'write/read through the shared container; otherwise it falls back to '
          'this deterministic simulation. The secure path enforces per-item '
          'access scoping so sensitive items are served only to the entitled '
          'main app.',
      children: [
        DemoActionButton(
          label: 'Read auth token as keyboard extension',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label:
                'shared-container probe (real native path: '
                'App Group on iOS / external-files on Android)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'shared-container over-read (no per-item ACL)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure: per-item scoping denies low-trust reader',
            value: _secureResult!,
          ),
      ],
    );
  }
}
