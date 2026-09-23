/// Pure-Dart simulation of Android 14+ predictive-back / recents snapshot
/// leakage.
///
/// INTENTIONALLY VULNERABLE (CWE-200): when a sensitive screen is not marked
/// secure, the OS captures a snapshot of its current content for the recents
/// (task-switcher) UI and the predictive-back preview. That snapshot - which
/// includes whatever secret is on screen - is retained by the system and
/// visible to anyone with the device or with screencap access.
///
/// The fix is native: FLAG_SECURE and/or
/// `setRecentsScreenshotEnabled(false)` on the Activity. This class models the
/// snapshot decision so a test can assert the secret is captured when the
/// screen is not marked secure.
class RecentsSnapshotSimulator {
  RecentsSnapshotSimulator._();

  /// Produces the snapshot the OS would retain for [sensitiveContent].
  ///
  /// VULN: because [recentsScreenshotEnabled] is left at its default (true) and
  /// FLAG_SECURE is not set, the snapshot captures the raw sensitive content.
  static String captureSnapshot(
    String sensitiveContent, {
    bool flagSecure = false,
    bool recentsScreenshotEnabled = true,
  }) {
    if (flagSecure || !recentsScreenshotEnabled) {
      // A secure screen: the OS stores a blank/obscured placeholder instead.
      return '[obscured by FLAG_SECURE]';
    }
    // VULN: the recents/predictive-back snapshot contains the secret verbatim.
    return sensitiveContent;
  }

  /// True if the retained snapshot would leak [sensitiveContent].
  static bool snapshotLeaks(
    String sensitiveContent, {
    bool flagSecure = false,
    bool recentsScreenshotEnabled = true,
  }) => captureSnapshot(
    sensitiveContent,
    flagSecure: flagSecure,
    recentsScreenshotEnabled: recentsScreenshotEnabled,
  ).contains(sensitiveContent);
}
