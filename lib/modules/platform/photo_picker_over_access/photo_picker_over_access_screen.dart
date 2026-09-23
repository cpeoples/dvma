import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'photo_access.dart';

/// Over-Broad Media Access (no scoped photo picker).
///
/// Contrasts requesting full media/library permission (vulnerable) with the
/// modern scoped photo picker (secure).
class PhotoPickerOverAccessScreen extends StatefulWidget {
  const PhotoPickerOverAccessScreen({super.key});

  static const String vulnId = 'photo_picker_over_access';

  @override
  State<PhotoPickerOverAccessScreen> createState() =>
      _PhotoPickerOverAccessScreenState();
}

class _PhotoPickerOverAccessScreenState
    extends State<PhotoPickerOverAccessScreen> {
  PhotoGrant? _full;
  PhotoGrant? _scoped;
  String? _nativeFull;

  Future<void> _requestFull() async {
    final grant = PhotoAccess.requestFullLibraryAccess();
    // real artifact: the over-broad grant (full-library scope + standing
    // permission + the enumerated photos it can now read) is written to the
    // adb-pullable evidence file.
    await DvmaEvidence.record(
      PhotoPickerOverAccessScreen.vulnId,
      'photo-grant',
      'over-broad media grant: scope=${grant.scope} '
          'standingPermission=${grant.standingPermission} '
          'accessiblePhotos=${grant.grantedItems.join(",")}',
    );

    // On Android, run a real MediaStore query enumerating on-device images -
    // the full-library over-collection contrasted with the scoped picker.
    final native = await SystemProviderBridge.mediaStoreQuery();
    if (native != null) {
      await DvmaEvidence.record(
        PhotoPickerOverAccessScreen.vulnId,
        'photo-grant-native',
        'real MediaStore enumeration: $native',
      );
    }
    if (!mounted) return;
    setState(() {
      _full = grant;
      _nativeFull = native;
    });
  }

  void _requestScoped() {
    // The user only picked one photo to attach.
    setState(() => _scoped = PhotoAccess.scopedPicker(const ['IMG_0002.jpg']));
  }

  String _describe(PhotoGrant g) =>
      'scope: ${g.scope}\n'
      'standing permission: ${g.standingPermission}\n'
      'accessible photos (${g.grantedItems.length}):\n'
      '${g.grantedItems.join("\n")}';

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PhotoPickerOverAccessScreen.vulnId,
      title: 'Photo Picker Over-Access',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'To let the user attach one photo, the app requests full '
          'media-library permission and receives every photo on the device '
          '(including sensitive scans), plus standing access to future photos. '
          'The modern scoped photo picker returns only the item the user '
          'selected and grants no standing permission - collecting exactly '
          'what is needed.',
      children: [
        DemoActionButton(
          label: 'Request full library permission (vulnerable)',
          onPressed: _requestFull,
        ),
        if (_full != null)
          EvidencePanel(
            label: 'full-access grant (over-collects!)',
            value: _describe(_full!),
          ),
        if (_nativeFull != null)
          EvidencePanel(
            label: 'real MediaStore query (full-library enumeration)',
            value: _nativeFull!,
          ),
        DemoActionButton(
          label: 'Use scoped photo picker (secure)',
          onPressed: _requestScoped,
        ),
        if (_scoped != null)
          EvidencePanel(
            label: 'scoped picker grant',
            value: _describe(_scoped!),
          ),
      ],
    );
  }
}
