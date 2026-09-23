/// Pure-Dart simulation of over-broad media access vs the scoped photo picker.
///
/// INTENTIONALLY VULNERABLE (CWE-250 / CWE-359): the app requests full
/// media-library permission (Android `READ_MEDIA_IMAGES` / iOS full Photos
/// access) and therefore receives every photo on the device, over-collecting
/// far more than it needs. The modern, privacy-preserving approach is the
/// scoped photo picker (Android Photo Picker / iOS `PHPickerViewController`),
/// which returns only the specific items the user chose and grants no standing
/// permission.
///
/// Deterministic + offline so a test can assert the vulnerable path yields the
/// entire library while the scoped picker yields only the user's selection.
class PhotoAccess {
  PhotoAccess._();

  /// A stand-in device photo library.
  static const List<String> deviceLibrary = [
    'IMG_0001.jpg',
    'IMG_0002.jpg',
    'passport_scan.jpg',
    'medical_report.png',
    'IMG_0777.jpg',
  ];

  /// VULN: requesting full library permission grants access to ALL photos,
  /// regardless of what the user actually intended to share.
  static PhotoGrant requestFullLibraryAccess() {
    return PhotoGrant(
      scope: 'ALL_PHOTOS',
      grantedItems: List<String>.from(deviceLibrary),
      standingPermission: true,
    );
  }

  /// The scoped photo picker: returns only [userSelection] and grants no
  /// standing permission to the rest of the library.
  static PhotoGrant scopedPicker(List<String> userSelection) {
    final selected = userSelection
        .where(deviceLibrary.contains)
        .toList(growable: false);
    return PhotoGrant(
      scope: 'USER_SELECTED',
      grantedItems: selected,
      standingPermission: false,
    );
  }
}

/// The result of a media-access request.
class PhotoGrant {
  PhotoGrant({
    required this.scope,
    required this.grantedItems,
    required this.standingPermission,
  });

  /// 'ALL_PHOTOS' (vulnerable) or 'USER_SELECTED' (scoped).
  final String scope;

  /// The photos the app can now read.
  final List<String> grantedItems;

  /// Whether the app retains standing access to future/other photos.
  final bool standingPermission;

  bool get overCollects => scope == 'ALL_PHOTOS';
}
