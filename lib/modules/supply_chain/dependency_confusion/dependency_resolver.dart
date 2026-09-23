/// Dependency Confusion / Substitution helper.
///
/// INTENTIONALLY VULNERABLE (CWE-427 / CWE-1357): an internal/private package
/// name is resolved from a PUBLIC registry alongside the private one, and the
/// resolver picks the highest version across BOTH sources. An attacker who
/// publishes the internal name (`acme-internal-auth`) to the public index at a
/// higher version (9.9.9) therefore gets their impostor pulled into the build
/// instead of the trusted private 1.2.0 (the classic dependency-confusion /
/// substitution class; also seen in iOS dependency-management research).
///
/// This is an offline + deterministic simulation of pubspec / CocoaPods / SPM
/// resolution: the private and public registries are in-memory maps and
/// "resolving" returns which source/version wins. A test can assert [resolve]
/// selects the impostor while [resolveScoped] pins the internal name to the
/// private registry and returns the trusted package.
class DependencyResolver {
  DependencyResolver._();

  /// Private/internal registry: trusted source of internal packages.
  static const Map<String, _Pkg> _privateRegistry = {
    'acme-internal-auth': _Pkg(version: '1.2.0', source: 'private-registry'),
    'acme-internal-crypto': _Pkg(version: '0.9.1', source: 'private-registry'),
  };

  /// Public registry (e.g. pub.dev / CocoaPods trunk / npm). An attacker has
  /// squatted the internal name here at a higher version.
  static const Map<String, _Pkg> _publicRegistry = {
    'acme-internal-auth': _Pkg(version: '9.9.9', source: 'public-registry'),
    'left-pad': _Pkg(version: '1.3.0', source: 'public-registry'),
  };

  /// Package names the org considers internal (private) by scope/prefix.
  static bool _isInternal(String pkg) => pkg.startsWith('acme-internal-');

  static int _cmpVersion(String a, String b) {
    final pa = a.split('.').map(int.parse).toList();
    final pb = b.split('.').map(int.parse).toList();
    for (var i = 0; i < 3; i++) {
      if (pa[i] != pb[i]) return pa[i].compareTo(pb[i]);
    }
    return 0;
  }

  /// VULN: resolve by picking the HIGHEST version across BOTH registries, with
  /// no scope pinning. For an internal name the attacker's higher public
  /// version wins, so the impostor is selected.
  static Resolution resolve(String pkg) {
    final priv = _privateRegistry[pkg];
    final pub = _publicRegistry[pkg];
    if (priv == null && pub == null) {
      return Resolution(
        package: pkg,
        version: null,
        source: null,
        isImpostor: false,
        reason: 'not found in any registry',
      );
    }
    _Pkg winner;
    if (priv == null) {
      winner = pub!;
    } else if (pub == null) {
      winner = priv;
    } else {
      // Highest version wins regardless of source (the flaw).
      winner = _cmpVersion(pub.version, priv.version) >= 0 ? pub : priv;
    }
    final isImpostor = _isInternal(pkg) && winner.source == 'public-registry';
    return Resolution(
      package: pkg,
      version: winner.version,
      source: winner.source,
      isImpostor: isImpostor,
      reason: isImpostor
          ? 'internal name resolved from PUBLIC registry (impostor)'
          : 'resolved highest version across registries',
    );
  }

  /// SECURE contrast: pin internal names to the private registry / scope and
  /// never resolve them from the public index. Returns the trusted private
  /// package (1.2.0) for internal names.
  static Resolution resolveScoped(String pkg) {
    if (_isInternal(pkg)) {
      final priv = _privateRegistry[pkg];
      if (priv == null) {
        return Resolution(
          package: pkg,
          version: null,
          source: null,
          isImpostor: false,
          reason: 'internal name not present in private registry',
        );
      }
      return Resolution(
        package: pkg,
        version: priv.version,
        source: priv.source,
        isImpostor: false,
        reason: 'internal name pinned to private registry',
      );
    }
    // Public packages resolve from the public registry as normal.
    final pub = _publicRegistry[pkg];
    if (pub == null) {
      return Resolution(
        package: pkg,
        version: null,
        source: null,
        isImpostor: false,
        reason: 'not found in public registry',
      );
    }
    return Resolution(
      package: pkg,
      version: pub.version,
      source: pub.source,
      isImpostor: false,
      reason: 'public package resolved from public registry',
    );
  }
}

class _Pkg {
  const _Pkg({required this.version, required this.source});
  final String version;
  final String source;
}

/// Outcome of a simulated dependency resolution.
class Resolution {
  const Resolution({
    required this.package,
    required this.version,
    required this.source,
    required this.isImpostor,
    required this.reason,
  });

  /// The package name that was resolved.
  final String package;

  /// The selected version, or null when unresolved.
  final String? version;

  /// The registry the winning package came from, or null.
  final String? source;

  /// Whether the resolved package is an attacker's public impostor of an
  /// internal name.
  final bool isImpostor;

  /// Human-readable explanation of the resolution.
  final String reason;
}
