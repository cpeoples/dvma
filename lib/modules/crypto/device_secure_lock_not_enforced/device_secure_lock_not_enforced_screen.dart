import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'secure_lock_store.dart';

/// Device Secure Lock Not Enforced for Sensitive Storage.
///
/// Persists a session secret without requiring a device secure lock or binding
/// the key to one, so it is recoverable at rest on an unlocked/lock-less device.
class DeviceSecureLockNotEnforcedScreen extends StatefulWidget {
  const DeviceSecureLockNotEnforcedScreen({super.key});

  static const String vulnId = 'device_secure_lock_not_enforced';

  @override
  State<DeviceSecureLockNotEnforcedScreen> createState() =>
      _DeviceSecureLockNotEnforcedScreenState();
}

class _DeviceSecureLockNotEnforcedScreenState
    extends State<DeviceSecureLockNotEnforcedScreen> {
  String? _result;

  Future<void> _store() async {
    final r = await SecureLockStore.storeWithoutLock();
    if (!mounted) return;
    setState(
      () => _result =
          'stored: ${r.stored}\n'
          'required device lock: ${r.requiredDeviceLock}'
          '${r.path == null ? "" : "\nartifact: ${r.path}"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeviceSecureLockNotEnforcedScreen.vulnId,
      title: 'Device Secure Lock Not Enforced',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A session secret is persisted without requiring a device secure '
          'lock (PIN/passcode/biometric) or binding the key to one. On a '
          'device with no lock screen the secret is recoverable at rest with '
          'no user presence - the value a hardened app would keep only in '
          'lock-gated Keystore/Keychain.',
      children: [
        DemoActionButton(label: 'Store secret without lock', onPressed: _store),
        if (_result != null)
          EvidencePanel(label: 'stored secret', value: _result!),
      ],
    );
  }
}
