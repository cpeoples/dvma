import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/keychain_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'keychain_service.dart';

/// Keychain Access-Group Authorization Confusion.
///
/// Over-broad `kSecAttrAccessGroup` / shared-group / synchronizable flags let a
/// different app or extension read items that should be isolated to the owning
/// app, an authorization confusion at the access-group boundary.
class KeychainAccessGroupAuthorizationConfusionScreen extends StatefulWidget {
  const KeychainAccessGroupAuthorizationConfusionScreen({super.key});

  static const String vulnId = 'keychain_access_group_authorization_confusion';

  @override
  State<KeychainAccessGroupAuthorizationConfusionScreen> createState() =>
      _KeychainAccessGroupAuthorizationConfusionScreenState();
}

class _KeychainAccessGroupAuthorizationConfusionScreenState
    extends State<KeychainAccessGroupAuthorizationConfusionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(KeychainReadResult r) {
    final b = StringBuffer();
    b.writeln('caller group     : ${r.callerAccessGroup}');
    b.writeln('item group       : ${r.itemAccessGroup}');
    b.writeln('granted          : ${r.granted}');
    b.writeln('cross-group leak : ${r.crossGroupLeak}');
    b.writeln('value            : ${r.value ?? '<refused>'}');
    if (r.denyReason != null) {
      b.writeln('reason           : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // A DIFFERENT app / extension presents its own access group.
    final vuln = KeychainService.seeded().read(
      KeychainService.attackerGroup,
      KeychainService.secretKey,
    );
    final secure = KeychainService.seeded().readScoped(
      KeychainService.attackerGroup,
      KeychainService.secretKey,
    );
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real ARTIFACT: persist the isolated secret via the local key-value store
    // (NSUserDefaults on iOS) under a key embedding the WILDCARD access group,
    // then mirror the stored line + the backup-recoverable backing file to the
    // evidence sink (fire-and-forget).
    _persistAndRecord();
  }

  Future<void> _persistAndRecord() async {
    final storedLine = await KeychainService.persistSeeded();
    // On iOS, drive a real Security.framework Keychain item: store a
    // synchronizable secret not scoped to an app-private access group and read
    // it back across the group boundary (SecItemAdd / SecItemCopyMatching).
    final native = await KeychainBridge.accessGroupConfusion();
    if (native != null && native.isNotEmpty && mounted) {
      setState(() => _nativeResult = native);
    }
    // On iOS the Flutter key-value store is backed by an NSUserDefaults plist
    // in the app's Library/Preferences, recoverable from an unencrypted device
    // backup or a jailbroken device.
    const backingFile =
        'Library/Preferences/<bundle-id>.plist (NSUserDefaults)';
    final artifact =
        '$storedLine'
        '\n\naccess group (over-broad) : ${KeychainService.wildcardGroup}'
        '\nsynchronizable            : true'
        '\nattacker caller group     : ${KeychainService.attackerGroup}'
        '\n\nbacking file (readable from an unencrypted backup or over SSH/SCP / '
        'Filza on a jailbroken device): $backingFile';
    DvmaEvidence.record(
      KeychainAccessGroupAuthorizationConfusionScreen.vulnId,
      'keychain',
      native != null && native.isNotEmpty
          ? '$artifact\n\nreal iOS Keychain (SecItem) result:\n$native'
          : artifact,
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: KeychainAccessGroupAuthorizationConfusionScreen.vulnId,
      title: 'Keychain Access-Group Authorization Confusion',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A sensitive keychain item is scoped to an access group that is too '
          'broad to isolate it, and marked synchronizable, so a DIFFERENT app '
          'or extension can still read an item that should be private to the '
          'owning app. This is an authorization confusion at the access-group '
          'boundary, distinct from weak item-accessibility misuse. The in-app '
          'model shows the extreme case (a shared/wildcard group served to any '
          'caller); on a real iOS device the same confusion is reproduced with '
          'Security.framework by storing the secret synchronizable and NOT '
          'scoped to an app-private access group (so it lands in the default '
          'app+extensions group), then reading it back across the boundary via '
          'SecItemAdd / SecItemCopyMatching. On device the secret is also '
          'persisted to a Keychain/NSUserDefaults item, recoverable in cleartext '
          'from an unencrypted device backup or a jailbroken device (SSH/SCP or '
          'Filza; keychain-dumper). The secure path rejects the over-broad '
          'stored group and requires an exact app-private access-group match, '
          'refusing cross-group reads.',
      children: [
        DemoActionButton(
          label: 'Read isolated item from attacker access group',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'wildcard group served cross-app (leak)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'exact app-private group required (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label:
                'real iOS Keychain item read across group boundary (SecItem)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
