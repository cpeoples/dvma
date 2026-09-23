/// Notification Content Disclosure via Alternate Surface helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-359 / CWE-284): sensitive
/// notification content that is REDACTED on the lock screen is rendered IN FULL
/// on a secondary presentation surface - desktop / DeX mode, a home-screen
/// widget, a companion display - that skips the redaction / access-control
/// boundary. Anyone with access to that surface reads the hidden notification
/// contents (the Samsung DeX CVE-2026-21006 class).
///
/// This is an offline + deterministic simulation. A [SensitiveNotification]
/// carries both a PUBLIC (redacted) form and a PRIVATE (full) form plus a
/// visibility policy. [NotificationRenderer] renders it per surface: the
/// vulnerable path emits the full private content on an alternate surface
/// ignoring the policy; the secure path applies the SAME redaction policy on
/// every surface (or requires the surface to be authenticated), so the alternate
/// surface only ever shows the redacted form.
library;

/// A presentation surface a notification can be rendered on.
enum Surface {
  /// The locked primary device screen (redaction expected).
  lockScreen,

  /// A secondary desktop/DeX/widget/companion surface.
  alternateSurface,
}

/// A notification with redacted (public) and full (private) content.
class SensitiveNotification {
  const SensitiveNotification({
    required this.publicContent,
    required this.privateContent,
    this.visibilityPrivate = true,
  });

  /// The redacted content shown when the device is locked.
  final String publicContent;

  /// The full content, meant to be shown only after authentication.
  final String privateContent;

  /// Whether the notification's visibility is marked PRIVATE (redact on
  /// unauthenticated surfaces).
  final bool visibilityPrivate;

  static const SensitiveNotification sample = SensitiveNotification(
    publicContent: 'Messages • 1 new notification',
    privateContent:
        'Dr. Reyes: Your HIV test result is positive. Call the clinic at '
        '555-0142.',
  );
}

/// What a surface ended up displaying.
class RenderResult {
  const RenderResult({
    required this.surface,
    required this.displayed,
    required this.leakedPrivate,
    this.reason,
  });

  /// The surface this render targeted.
  final Surface surface;

  /// The text actually shown on the surface.
  final String displayed;

  /// True when the FULL private content was exposed on an unauthenticated
  /// alternate surface - the disclosure hit.
  final bool leakedPrivate;

  /// Why the secure renderer redacted (secure path).
  final String? reason;
}

class NotificationRenderer {
  const NotificationRenderer();

  /// VULN: render the notification on [surface]. The lock screen honors
  /// redaction, but the alternate surface is treated as "already trusted" and
  /// emits the FULL private content, ignoring the visibility policy.
  RenderResult render(SensitiveNotification n, Surface surface) {
    switch (surface) {
      case Surface.lockScreen:
        // The primary lock screen redacts as configured.
        final text = n.visibilityPrivate ? n.publicContent : n.privateContent;
        return RenderResult(
          surface: surface,
          displayed: text,
          leakedPrivate: false,
        );
      case Surface.alternateSurface:
        // BUG: the alternate surface skips the redaction boundary entirely.
        return RenderResult(
          surface: surface,
          displayed: n.privateContent,
          leakedPrivate: n.visibilityPrivate,
          reason: 'alternate surface bypassed the redaction policy',
        );
    }
  }

  /// SECURE contrast: apply the SAME visibility policy on every surface. An
  /// unauthenticated surface - lock screen OR alternate surface - only ever
  /// receives the redacted public form. Full content requires [authenticated].
  RenderResult renderSafe(
    SensitiveNotification n,
    Surface surface, {
    bool authenticated = false,
  }) {
    final redact = n.visibilityPrivate && !authenticated;
    final text = redact ? n.publicContent : n.privateContent;
    return RenderResult(
      surface: surface,
      displayed: text,
      leakedPrivate: false,
      reason: redact
          ? 'redaction policy enforced on ${surface.name}'
          : 'authenticated surface - full content permitted',
    );
  }
}
