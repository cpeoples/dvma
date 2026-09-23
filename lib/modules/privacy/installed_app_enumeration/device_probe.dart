/// Installed-app enumeration (privacy fingerprint) helper.
///
/// INTENTIONALLY VULNERABLE (CWE-359 / CWE-200): the app probes which OTHER
/// apps are installed - iOS `canOpenURL` over a scheme list, Android
/// `queryIntentActivities` / `getInstalledPackages` - with no functional need.
/// The set of detected apps is a stable device fingerprint and reveals
/// sensitive traits (dating, health, finance, political apps) across a privacy
/// boundary (iOS CVE-2026-20641 installed-apps disclosure class).
///
/// This is an offline, deterministic model: [DeviceProbe] holds an installed-app set
/// and a probe list in pure Dart. The vuln [enumerate] returns the full
/// detected set (the fingerprint). The secure path only checks the single
/// scheme the app legitimately needs, with a declared reason, so no broad
/// fingerprint is built.
library;

/// A candidate app the probe checks for (a URL scheme / package name + a
/// privacy-sensitive category the mere presence discloses).
class AppCandidate {
  const AppCandidate({
    required this.scheme,
    required this.label,
    required this.category,
  });

  final String scheme;
  final String label;
  final String category;
}

/// The outcome of a probe.
class ProbeResult {
  const ProbeResult({
    required this.detected,
    required this.probedCount,
    this.reason,
  });

  /// The apps the probe detected as installed.
  final List<AppCandidate> detected;

  /// How many candidates were probed.
  final int probedCount;

  /// Why the probe ran / was constrained (secure path).
  final String? reason;

  /// A stable fingerprint string built from the detected set.
  String get fingerprint =>
      detected.map((c) => c.scheme).toList(growable: false).join(',');

  /// True when the probe disclosed MORE than a single legitimately-needed app,
  /// i.e. built a broad cross-app fingerprint.
  bool get isFingerprint => detected.length > 1;
}

class DeviceProbe {
  DeviceProbe();

  /// The one scheme the app actually needs (to hand off a payment).
  static const String neededScheme = 'dvmapay';

  /// Candidate apps the greedy probe checks for. Presence of any is sensitive.
  static const List<AppCandidate> candidates = [
    AppCandidate(scheme: 'dvmapay', label: 'DVMA Pay', category: 'finance'),
    AppCandidate(scheme: 'grindr', label: 'Grindr', category: 'dating/LGBTQ'),
    AppCandidate(scheme: 'tinder', label: 'Tinder', category: 'dating'),
    AppCandidate(
      scheme: 'telegram',
      label: 'Telegram',
      category: 'private-messaging',
    ),
    AppCandidate(
      scheme: 'signal',
      label: 'Signal',
      category: 'private-messaging',
    ),
    AppCandidate(
      scheme: 'robinhood',
      label: 'Robinhood',
      category: 'investing',
    ),
    AppCandidate(scheme: 'mychart', label: 'MyChart', category: 'health'),
    AppCandidate(scheme: 'wickr', label: 'Wickr', category: 'secure-messaging'),
  ];

  /// The apps actually installed on this (simulated) device.
  final Set<String> installedSchemes = const {
    'dvmapay',
    'grindr',
    'telegram',
    'robinhood',
    'mychart',
  };

  bool _isInstalled(String scheme) => installedSchemes.contains(scheme);

  /// VULN: probe every candidate via canOpenURL and return the full detected
  /// set. No functional need for most of these; the result is a fingerprint.
  ProbeResult enumerate(List<AppCandidate> probeList) {
    final detected = probeList.where((c) => _isInstalled(c.scheme)).toList();
    return ProbeResult(
      detected: detected,
      probedCount: probeList.length,
      reason:
          'canOpenURL over ${probeList.length} schemes (no functional need)',
    );
  }

  /// SECURE contrast: only check the single scheme the app declared it needs,
  /// with a stated purpose. No broad set is collected, so no fingerprint.
  ProbeResult enumerateSafe() {
    final detected = candidates
        .where((c) => c.scheme == neededScheme && _isInstalled(c.scheme))
        .toList();
    return ProbeResult(
      detected: detected,
      probedCount: 1,
      reason:
          'checked only "$neededScheme" (declared purpose: payment handoff)',
    );
  }
}
