import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'companion_device_manager.dart';

/// Companion Device Pairing / Capability Confusion.
///
/// An app pairs with a nearby companion device (watch / peripheral / car / IoT)
/// via CompanionDeviceManager and then treats "paired" as "authorized for every
/// capability", so a spoofed or lower-trust device is granted actions it should
/// not have (Android CompanionDeviceManager trusted-device boundary class).
class CompanionDevicePairingConfusionScreen extends StatefulWidget {
  const CompanionDevicePairingConfusionScreen({super.key});

  static const String vulnId = 'companion_device_pairing_confusion';

  @override
  State<CompanionDevicePairingConfusionScreen> createState() =>
      _CompanionDevicePairingConfusionScreenState();
}

class _CompanionDevicePairingConfusionScreenState
    extends State<CompanionDevicePairingConfusionScreen> {
  static const CompanionCapability _cap = CompanionCapability.unlockDoor;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(CapabilityResult r) {
    final b = StringBuffer();
    b.writeln('device             : ${r.device.id}');
    b.writeln('device trust       : ${r.device.trustLevel.name}');
    b.writeln('capability         : ${r.capability.label}');
    b.writeln('required trust     : ${r.capability.requiredTrust.name}');
    b.writeln('granted            : ${r.granted}');
    b.writeln('over-privileged    : ${r.overPrivileged}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: query CompanionDeviceManager.getAssociations() for this
    // app's actual paired companion devices + report the over-broad-capability
    // gap.
    final native = await SystemProviderBridge.companionAssociations();

    // VULN: a spoofed low-trust device is granted a high-privilege capability
    // (unlock the door) purely because it completed pairing.
    final vulnMgr = CompanionDeviceManager();
    final vuln = vulnMgr.requestCapability(
      CompanionDeviceManager.spoofedWatch,
      _cap,
    );

    // SECURE: the same spoofed device is denied for lacking the per-capability
    // trust binding required to unlock the door.
    final secureMgr = CompanionDeviceManager();
    final secure = secureMgr.requestCapabilitySafe(
      CompanionDeviceManager.spoofedWatch,
      _cap,
    );

    await DvmaEvidence.record(
      CompanionDevicePairingConfusionScreen.vulnId,
      'companion-pairing',
      'nativeAssociations=${native ?? 'unavailable (off-Android fallback)'} :: '
          'spoofedDeviceGranted=${vuln.granted} :: '
          'overPrivileged=${vuln.overPrivileged} :: '
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
      vulnId: CompanionDevicePairingConfusionScreen.vulnId,
      title: 'Companion Device Pairing / Capability Confusion',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Pairing with a companion device (watch / peripheral / car / IoT) '
          'via CompanionDeviceManager only establishes proximity and identity '
          '- it is NOT a grant for every privileged action. Here the app '
          'equates "paired" with "authorized for every capability", so a '
          'spoofed, low-trust advertiser that completed pairing is granted a '
          'high-privilege capability (unlock the door) it should never hold '
          '(Android CompanionDeviceManager trusted-device boundary class). The '
          'secure path binds each capability to the device\'s verified trust '
          'level, so a spoofed / low-trust device is denied high-privilege '
          'capabilities. The "real state" panel lists this app\'s actual '
          'CompanionDeviceManager associations (getAssociations); to fully arm '
          'the capability, create an association via CompanionDeviceManager '
          '.associate() and pick a device in the system dialog.',
      children: [
        DemoActionButton(
          label: 'Spoofed device requests unlock-door',
          onPressed: _run,
        ),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real companion associations (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'paired == authorized -> over-privileged grant',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'per-capability trust binding denies spoofed device',
            value: _secureResult!,
          ),
      ],
    );
  }
}
