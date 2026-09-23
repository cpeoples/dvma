import 'dart:io' show Platform;

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/notification_bridge.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'notification_surface_renderer.dart';

/// Notification Content Disclosure via Alternate Surface.
///
/// Content redacted on the lock screen is rendered in full on a secondary
/// surface (DeX / widget / companion display) that skips the redaction boundary
/// (Samsung DeX CVE-2026-21006 class).
class NotificationAlternateSurfaceDisclosureScreen extends StatefulWidget {
  const NotificationAlternateSurfaceDisclosureScreen({super.key});

  static const String vulnId = 'notification_alternate_surface_disclosure';

  @override
  State<NotificationAlternateSurfaceDisclosureScreen> createState() =>
      _NotificationAlternateSurfaceDisclosureScreenState();
}

class _NotificationAlternateSurfaceDisclosureScreenState
    extends State<NotificationAlternateSurfaceDisclosureScreen> {
  static const _renderer = NotificationRenderer();
  static const _notification = SensitiveNotification.sample;

  String? _vulnResult;
  String? _secureResult;
  String? _nativeReport;
  bool _running = false;

  String _render(RenderResult lock, RenderResult alt) {
    final b = StringBuffer();
    b.writeln('lock screen shows  : ${lock.displayed}');
    b.writeln('alt surface shows  : ${alt.displayed}');
    b.writeln('leaked private     : ${alt.leakedPrivate}');
    if (alt.reason != null) {
      b.writeln('note               : ${alt.reason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);
    // VULN: the DeX / widget surface renders the full private content.
    final vulnLock = _renderer.render(_notification, Surface.lockScreen);
    final vulnAlt = _renderer.render(_notification, Surface.alternateSurface);
    // SECURE: the same redaction policy applies on every unauthenticated
    // surface.
    final secureLock = _renderer.renderSafe(_notification, Surface.lockScreen);
    final secureAlt = _renderer.renderSafe(
      _notification,
      Surface.alternateSurface,
    );

    // real SINK: post an actual OS notification whose full private body lands on
    // real secondary surfaces (status bar / lock screen / DeX / companion),
    // observable off-device via `adb shell dumpsys notification --noredact`
    // (Android) or the iOS lock screen. The native handler posts the sensitive
    // OTP/balance with no per-surface visibility restriction and reads the
    // delivered content back.
    final native = Platform.isIOS
        ? await NotificationBridge.postSensitiveNotification()
        : await PlatformIpcBridge.postSensitiveNotification();

    // Mirror the sensitive notification body disclosed on the alternate surface
    // to the pullable evidence sink (fire-and-forget; never blocks the demo).
    DvmaEvidence.record(
      NotificationAlternateSurfaceDisclosureScreen.vulnId,
      'notif-disclosure',
      'lock screen showed : ${vulnLock.displayed}\n'
          'alternate surface disclosed (full private body): ${vulnAlt.displayed}\n'
          'leaked private = ${vulnAlt.leakedPrivate}\n'
          'real OS notification: ${native ?? "(native surface unavailable on host)"}',
    );

    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vulnLock, vulnAlt);
      _secureResult = _render(secureLock, secureAlt);
      _nativeReport = native;
      _running = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: NotificationAlternateSurfaceDisclosureScreen.vulnId,
      title: 'Notification Content Disclosure via Alternate Surface',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Sensitive notification content that is REDACTED on the lock screen '
          'is rendered IN FULL on a secondary presentation surface (desktop / '
          'DeX mode, a home-screen widget, a companion display) that skips the '
          'redaction / access-control boundary, so anyone with access to that '
          'surface reads the hidden contents (the Samsung DeX CVE-2026-21006 '
          'class). This is an offline, deterministic simulation: a notification '
          'carries a public (redacted) and a private (full) form; the vulnerable '
          'alternate-surface renderer emits the full private content, ignoring '
          'the visibility policy the lock screen honors. The secure path applies '
          'the SAME redaction policy on every unauthenticated surface, so the '
          'alternate surface shows only the redacted form until authenticated.',
      children: [
        DemoActionButton(
          label: _running ? 'Rendering...' : 'Render on DeX / widget surface',
          onPressed: _running ? () {} : _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'alternate surface bypasses redaction (leaked)',
            value: _vulnResult!,
          ),
        if (_nativeReport != null)
          EvidencePanel(
            label: 'real OS notification posted (dumpsys/lock screen)',
            value: _nativeReport!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'same redaction policy every surface',
            value: _secureResult!,
          ),
      ],
    );
  }
}
