import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Over-Privileged Permissions.
///
/// Requests broad permissions unrelated to app functionality.
class OverPrivilegedPermissionsScreen extends StatefulWidget {
  const OverPrivilegedPermissionsScreen({super.key});

  static const String vulnId = 'over_privileged_permissions';

  @override
  State<OverPrivilegedPermissionsScreen> createState() =>
      _OverPrivilegedPermissionsScreenState();
}

class _OverPrivilegedPermissionsScreenState
    extends State<OverPrivilegedPermissionsScreen> {
  final PlatformLingo _lingo = PlatformLingo.current();

  // The over-declared permissions this app requests but no feature uses. These
  // are the REAL entries in AndroidManifest.xml (<uses-permission>, recoverable
  // via aapt/jadx/dumpsys). CAMERA is deliberately excluded: it is declared
  // android:required="false" and genuinely used by the QR-scanning demos, so it
  // is justified, not over-privilege. iOS declares no unused usage-description
  // keys (its NSCamera/NSUserTracking/NSFaceID keys each back a demo), so the
  // over-privilege finding is Android-specific and reported as such.
  static const List<String> _unusedAndroidPermissions = [
    'READ_CONTACTS',
    'ACCESS_FINE_LOCATION',
    'READ_SMS',
    'RECEIVE_SMS',
    'RECORD_AUDIO',
    'READ_EXTERNAL_STORAGE',
    'WRITE_EXTERNAL_STORAGE',
    'READ_CALL_LOG',
    'READ_PHONE_STATE',
    'GET_ACCOUNTS',
  ];

  /// Command a trainee runs to confirm these are really declared.
  String get _verifyCmd => _lingo.pick(
    ios:
        'plutil -p Runner.app/Info.plist | grep UsageDescription   '
        '# iOS declares no unused keys; this finding is Android-specific',
    android:
        'adb shell dumpsys package $_appId | grep permission   # or: '
        'aapt dump permissions <app.apk>',
  );

  String get _appId => 'com.dvma';

  String? _audit;

  void _audit2() {
    final unused = _unusedAndroidPermissions;

    // Mirror the real declared permissions + the verification command to the
    // evidence sink (fire-and-forget). The manifest is the real artifact.
    DvmaEvidence.record(
      OverPrivilegedPermissionsScreen.vulnId,
      'permissions',
      'over-declared, unused permissions (AndroidManifest.xml): '
          '${unused.join(', ')}'
          '\nverify: $_verifyCmd',
    );

    setState(
      () => _audit =
          '${unused.length} declared permissions have no functional '
          'justification. They are really in AndroidManifest.xml; confirm '
          'with:\n$_verifyCmd',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: OverPrivilegedPermissionsScreen.vulnId,
      title: 'Over-Privileged Permissions',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app declares dangerous Android permissions (contacts, precise '
          'location, SMS, call log, phone state, microphone, external storage, '
          'accounts) that none of its features use. They are really declared in '
          'AndroidManifest.xml and are recoverable from the built APK; '
          'over-privilege widens attack surface and privacy exposure. CAMERA is '
          'excluded because it is declared not-required and genuinely used by '
          'the QR-scanning demos. iOS declares no unused usage-description keys '
          '(its camera, tracking, and Face ID keys each back a demo), so this '
          'finding is Android-specific. Verify with `$_verifyCmd`.',
      children: [
        EvidencePanel(
          label: 'over-declared, unused permissions (AndroidManifest.xml)',
          value: _unusedAndroidPermissions.join('\n'),
        ),
        DemoActionButton(label: 'Audit permissions', onPressed: _audit2),
        if (_audit != null)
          EvidencePanel(label: 'audit result', value: _audit!),
      ],
    );
  }
}
