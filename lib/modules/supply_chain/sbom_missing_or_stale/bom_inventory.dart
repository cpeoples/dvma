/// Missing / Stale SBOM helper (No Component Inventory).
///
/// INTENTIONALLY VULNERABLE (CWE-1104 / CWE-1035 / MASVS-CODE-3): the app ships
/// WITHOUT a Software Bill of Materials. Several third-party SDKs are bundled
/// into the binary, and some are pinned to versions with publicly-known
/// vulnerabilities - but because no SBOM is produced or maintained, defenders
/// are blind to them. You cannot audit what you never inventoried.
///
/// This is offline + deterministic so a test can assert the two paths:
///
///  * VULN ("no SBOM" / blind path): [knownVulnerableComponents] relies only on
///    "what the app declares" about its own risk. The app declares nothing, so
///    it returns [] - the vulnerable components are invisible.
///  * SECURE contrast: [generateSbom] emits a full CycloneDX-ish component
///    inventory and [auditAgainstAdvisories] cross-references it against a known
///    advisory feed, does surface the vulnerable components.
///
/// The teaching point: without the SBOM step the vulnerable components are
/// invisible; with it, they are caught.
library;

import 'dart:convert';
import 'dart:io';

import '../../../core/evidence_sink.dart';

class BomInventory {
  BomInventory._();

  /// The components actually bundled into the app binary (the ground truth).
  /// Some are pinned to versions with publicly-known CVEs.
  static const List<BundledComponent> bundledComponents = [
    BundledComponent(name: 'image_loader', version: '2.1.0'),
    BundledComponent(name: 'analytics_sdk', version: '1.0.3'),
    BundledComponent(name: 'crash_reporter', version: '4.2.1'),
    BundledComponent(name: 'net_http', version: '0.9.7'),
    BundledComponent(name: 'json_codec', version: '3.4.0'),
  ];

  /// A (fake) public vulnerability advisory feed. Keyed by component name, each
  /// entry lists the exact versions with a known-vulnerable advisory.
  static const Map<String, List<Advisory>> advisoryFeed = {
    'image_loader': [
      Advisory(
        cveId: 'CVE-2023-40001',
        affectedVersion: '2.1.0',
        summary: 'Heap overflow decoding malformed WebP frames.',
        severity: 'critical',
      ),
    ],
    'analytics_sdk': [
      Advisory(
        cveId: 'CVE-2023-40002',
        affectedVersion: '1.0.3',
        summary: 'Silently exfiltrates the device advertising ID and contacts.',
        severity: 'high',
      ),
    ],
    'net_http': [
      Advisory(
        cveId: 'CVE-2022-40003',
        affectedVersion: '0.9.7',
        summary: 'TLS certificate validation can be bypassed via redirect.',
        severity: 'high',
      ),
    ],
    // crash_reporter 4.2.1 and json_codec 3.4.0 have no known advisories.
  };

  /// VULN ("no SBOM" / blind path): the app maintains no component inventory,
  /// so the only thing it can report about its own supply-chain risk is what it
  /// explicitly declares. It declares nothing, so this returns [] - the bundled
  /// vulnerable SDKs above are completely invisible to a defender.
  ///
  /// This mirrors reality: with no SBOM, a `flutter pub deps` / manifest scan of
  /// "declared" risk finds nothing, even though vulnerable code ships anyway.
  static List<AuditedComponent> knownVulnerableComponents() {
    // No SBOM => nothing declared => nothing to cross-reference. Blind.
    const List<BundledComponent> declaredInventory = [];
    return _audit(declaredInventory);
  }

  /// SECURE contrast, step 1: generate a full SBOM (CycloneDX-ish map) from the
  /// actually-bundled components. This is the step that is missing in the wild.
  static Map<String, Object> generateSbom() {
    return {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.5',
      'version': 1,
      'components': [
        for (final c in bundledComponents)
          {
            'type': 'library',
            'name': c.name,
            'version': c.version,
            'purl': 'pkg:dart/${c.name}@${c.version}',
          },
      ],
    };
  }

  /// SECURE contrast, step 2: cross-reference the generated SBOM against the
  /// advisory feed and surface every bundled component with a known-vulnerable
  /// version. With the SBOM present, the blind spot disappears.
  static List<AuditedComponent> auditAgainstAdvisories(
    Map<String, Object> sbom,
  ) {
    final components = (sbom['components'] as List)
        .cast<Map<String, Object>>()
        .map(
          (c) => BundledComponent(
            name: c['name'] as String,
            version: c['version'] as String,
          ),
        )
        .toList();
    return _audit(components);
  }

  /// The on-disk name the generated SBOM is written to.
  static const String sbomFileName = 'dvma_sbom.cdx.json';

  /// SECURE contrast (real I/O): generate the SBOM and write it to a real file
  /// on disk (adb/root-pullable), producing the component inventory artifact
  /// that is missing in the wild. `pubspec.lock` is not bundled as an asset in
  /// this build, so the inventory is generated from the in-code component list;
  /// in a real build you would generate it from the resolved lockfile, e.g.
  /// `dart pub deps --json` / a CycloneDX generator. Returns the file path (or
  /// a fallback marker). Never throws.
  static Future<String> writeSbomToFile() async {
    final sbom = generateSbom();
    final json = const JsonEncoder.withIndent('  ').convert(sbom);
    final baseDir = await DvmaEvidence.writableBaseDir();
    if (baseDir == null) return '(no writable dir on this host)';
    try {
      final file = File('${baseDir.path}/$sbomFileName');
      await file.parent.create(recursive: true);
      await file.writeAsString(json, flush: true);
      return file.path;
    } catch (_) {
      return '(write failed on this host)';
    }
  }

  static List<AuditedComponent> _audit(List<BundledComponent> inventory) {
    final findings = <AuditedComponent>[];
    for (final component in inventory) {
      final advisories = advisoryFeed[component.name] ?? const [];
      for (final advisory in advisories) {
        if (advisory.affectedVersion == component.version) {
          findings.add(
            AuditedComponent(component: component, advisory: advisory),
          );
        }
      }
    }
    return findings;
  }
}

/// A third-party component bundled into the app (name + version).
class BundledComponent {
  const BundledComponent({required this.name, required this.version});

  final String name;
  final String version;

  @override
  String toString() => '$name $version';
}

/// A public vulnerability advisory for a specific component version.
class Advisory {
  const Advisory({
    required this.cveId,
    required this.affectedVersion,
    required this.summary,
    required this.severity,
  });

  final String cveId;
  final String affectedVersion;
  final String summary;
  final String severity;
}

/// A bundled component matched against a known advisory.
class AuditedComponent {
  const AuditedComponent({required this.component, required this.advisory});

  final BundledComponent component;
  final Advisory advisory;

  @override
  String toString() =>
      '${component.name} ${component.version}  ->  '
      '${advisory.cveId} (${advisory.severity}): ${advisory.summary}';
}
