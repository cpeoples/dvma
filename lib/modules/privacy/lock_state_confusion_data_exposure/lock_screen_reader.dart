/// Lock-State Confusion Data Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-284 / CWE-668): sensitive data or a
/// privileged action is reachable while the device is LOCKED through an
/// alternate path - an accessibility / notification / widget / VoiceOver
/// surface - that never re-checks the keyguard. The lock-screen boundary is
/// bypassed and protected content is exposed on a locked device (the iOS
/// CVE-2026-20645 / CVE-2026-20661 lock-screen VoiceOver disclosure class).
///
/// This is an offline + deterministic simulation. A [LockScreenSurface] holds
/// protected content plus a `locked` flag. The vulnerable [read] returns the
/// FULL protected content even when `locked == true` (the alternate path skips
/// the keyguard check); the secure [readSafe] re-checks the lock state and
/// returns only non-sensitive / redacted content while locked.
library;

/// The alternate surface a read arrives through.
enum AccessPath {
  /// The normal, keyguard-gated app UI.
  primaryUi,

  /// A VoiceOver / accessibility surface that historically skipped the
  /// keyguard re-check.
  voiceOver,

  /// A home-screen widget surface.
  widget,
}

/// A lock-screen surface exposing protected content.
class LockScreenSurface {
  const LockScreenSurface({
    required this.locked,
    required this.protectedContent,
    required this.redactedContent,
  });

  /// Whether the device is currently locked (keyguard engaged).
  final bool locked;

  /// The full, sensitive content behind the keyguard.
  final String protectedContent;

  /// The non-sensitive form safe to show on a locked device.
  final String redactedContent;

  static const LockScreenSurface sample = LockScreenSurface(
    locked: true,
    protectedContent:
        'Wallet: Visa •1234 balance \$4,182.55 - recent: pharmacy \$63.20, '
        'clinic \$220.00',
    redactedContent: 'Wallet • unlock to view',
  );
}

/// The outcome of a read through some access path.
class LockReadResult {
  const LockReadResult({
    required this.path,
    required this.locked,
    required this.displayed,
    required this.leakedWhileLocked,
    this.reason,
  });

  /// The access path the read arrived through.
  final AccessPath path;

  /// Whether the device was locked at read time.
  final bool locked;

  /// The content actually returned to the surface.
  final String displayed;

  /// True when full protected content was returned on a LOCKED device - the
  /// lock-state-confusion hit.
  final bool leakedWhileLocked;

  /// Why the secure reader redacted / allowed.
  final String? reason;
}

class LockScreenReader {
  const LockScreenReader();

  /// VULN: the alternate (e.g. VoiceOver) path returns the FULL protected
  /// content regardless of the keyguard. It never re-checks `locked`, so a
  /// locked device still discloses the sensitive content.
  LockReadResult read(
    LockScreenSurface surface, {
    AccessPath path = AccessPath.voiceOver,
  }) {
    // BUG: no keyguard re-check on the alternate path.
    return LockReadResult(
      path: path,
      locked: surface.locked,
      displayed: surface.protectedContent,
      leakedWhileLocked: surface.locked,
      reason: 'alternate path skipped the keyguard re-check',
    );
  }

  /// SECURE contrast: re-check the lock state on every path. While locked, only
  /// the non-sensitive / redacted content is returned; the full content
  /// requires the device to be unlocked.
  LockReadResult readSafe(
    LockScreenSurface surface, {
    AccessPath path = AccessPath.voiceOver,
  }) {
    if (surface.locked) {
      return LockReadResult(
        path: path,
        locked: true,
        displayed: surface.redactedContent,
        leakedWhileLocked: false,
        reason: 'keyguard re-checked on ${path.name}: redacted while locked',
      );
    }
    return LockReadResult(
      path: path,
      locked: false,
      displayed: surface.protectedContent,
      leakedWhileLocked: false,
      reason: 'device unlocked - full content permitted',
    );
  }
}
