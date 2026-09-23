import 'package:flutter/material.dart';

import '../vulnerability_registry.dart';
import 'platform_lingo.dart';
import 'test_ids.dart';
import 'theme/dvma_colors.dart';
import 'theme/dvma_theme.dart';
import 'widgets.dart';

/// Shared scaffold for a vulnerability demo screen.
///
/// Gives every module a consistent, intentionally-designed layout: a short
/// explanation of the insecure behavior, an interactive area that triggers the
/// vulnerable code path, and an "evidence" area rendering the leaked/insecure
/// artifact in monospace (the "raw technical data" signal). Keeping this
/// consistent both looks designed and makes the vulnerable path obvious to a
/// trainee.
class VulnDemoScaffold extends StatelessWidget {
  const VulnDemoScaffold({
    super.key,
    required this.title,
    required this.difficulty,
    required this.explanation,
    required this.children,
    this.vulnId,
  });

  final String title;
  final DvmaDifficulty difficulty;

  /// The registry id for this module, used to tag the screen root with a
  /// stable automation identifier (`demo_screen_<vulnId>`) and to resolve the
  /// module's framework-mapping badges from the registry.
  final String? vulnId;

  /// One or two sentences describing what is insecure here.
  final String explanation;

  /// The interactive demo body.
  final List<Widget> children;

  /// The full registry entry for this module, when resolvable, so the header
  /// can render the complete framework mapping (every CWE/MASVS/MASWE/MASTG/
  /// OWASP ref) grouped like the Hugo detail pages.
  VulnerabilityEntry? _resolveEntry() =>
      vulnId == null ? null : VulnerabilityRegistry.byId(vulnId!);

  @override
  Widget build(BuildContext context) {
    final scaffold = Scaffold(
      appBar: AppBar(title: Text(title)),
      body: ListView(
        padding: const EdgeInsets.all(DvmaSpacing.lg),
        children: [
          DvmaFrameworkChips(difficulty: difficulty, entry: _resolveEntry()),
          const SizedBox(height: DvmaSpacing.md),
          Text(
            explanation,
            style: TextStyle(
              color: DvmaColors.of(context).textSecondary,
              height: 1.5,
            ),
          ),
          const SizedBox(height: DvmaSpacing.lg),
          const Divider(),
          const SizedBox(height: DvmaSpacing.lg),
          ...children,
        ],
      ),
    );
    if (vulnId == null) return scaffold;
    return testId(DvmaTestIds.demoScreen(vulnId!), scaffold);
  }
}

/// A labeled monospace panel for rendering the insecure artifact (stored value,
/// token, ciphertext, leaked prompt, etc.) that a trainee should inspect.
class EvidencePanel extends StatelessWidget {
  const EvidencePanel({super.key, required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final c = DvmaColors.of(context);
    return testId(
      DvmaTestIds.evidence(label),
      Container(
        width: double.infinity,
        margin: const EdgeInsets.only(top: DvmaSpacing.md),
        padding: const EdgeInsets.all(DvmaSpacing.md),
        decoration: BoxDecoration(
          color: c.base,
          border: Border.all(color: c.border),
          borderRadius: DvmaRadii.cardRadius,
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: DvmaTheme.mono(
                fontSize: 10,
                color: c.textFaint,
                letterSpacing: 1,
              ),
            ),
            const SizedBox(height: DvmaSpacing.xs),
            SelectableText(
              value,
              style: DvmaTheme.mono(fontSize: 12, color: DvmaColors.accent),
            ),
          ],
        ),
      ),
    );
  }
}

/// A primary action button that triggers the vulnerable code path.
class DemoActionButton extends StatelessWidget {
  const DemoActionButton({
    super.key,
    required this.label,
    required this.onPressed,
  });

  final String label;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return testTapId(
      DvmaTestIds.demoAction(label),
      Padding(
        padding: const EdgeInsets.only(top: DvmaSpacing.md),
        child: SizedBox(
          width: double.infinity,
          child: ElevatedButton(onPressed: onPressed, child: Text(label)),
        ),
      ),
    );
  }
}

/// A platform-aware panel describing a real on-device artifact a module just
/// persisted to the local key-value store.
///
/// Modules used to hand-build an [EvidencePanel] with a hard-coded Android
/// label (`device artifact (adb/objection)`) and value (`SharedPreferences key
/// "..." holds ...`). That reads wrong on iOS and drifts across ~30 call sites.
/// This widget owns the entire phrasing so a module only declares *what* the
/// artifact is:
///
/// ```dart
/// DeviceArtifactPanel(
///   storeKey: _artifactKey!,
///   describes: 'the downgraded password-fallback login success',
/// )
/// ```
///
/// which renders, per running platform (see [PlatformLingo]):
/// - Android: label `device artifact (adb/objection)`,
///   value `SharedPreferences key "<key>" holds <describes>.`
/// - iOS:     label `device artifact (backup / jailbreak SSH)`,
///   value `UserDefaults key "<key>" holds <describes>.`
///
/// The Android output is byte-for-byte the previous hard-coded text, so no
/// existing Android behavior changes.
class DeviceArtifactPanel extends StatelessWidget {
  const DeviceArtifactPanel({
    super.key,
    required this.storeKey,
    required this.describes,
    this.verb = 'holds',
  });

  /// The key under which the artifact was persisted in the local key-value
  /// store (e.g. the value returned by `PasskeyEvidenceStore.persist`).
  final String storeKey;

  /// A plain-English clause naming what the stored value contains, phrased to
  /// follow [verb], e.g. `'the accepted cross-origin assertion'`.
  final String describes;

  /// The verb linking the key to [describes]; defaults to `holds`. Pass e.g.
  /// `'now holds'` to preserve a specific phrasing.
  final String verb;

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return EvidencePanel(
      label: 'device artifact ${lingo.extractionParenthetical}',
      value: '${lingo.keyValueStore} key "$storeKey" $verb $describes.',
    );
  }
}
