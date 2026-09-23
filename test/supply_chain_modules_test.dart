import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/supply_chain/sbom_missing_or_stale/bom_inventory.dart';
import 'package:dvma/modules/supply_chain/silent_sdk_auto_update/updatable_sdk.dart';

/// Regression suite for the supply-chain training modules. Every test asserts
/// the *insecure* behavior is still present, so an accidental "fix" fails CI,
/// and also checks the secure contrast behaves correctly.
void main() {
  group('sbom_missing_or_stale', () {
    test('no-SBOM blind path is blind; SBOM audit surfaces the vulns', () {
      // VULN: without an SBOM there is nothing declared to cross-reference,
      // so the bundled known-vulnerable SDKs are invisible.
      final blind = BomInventory.knownVulnerableComponents();
      expect(blind, isEmpty, reason: 'no SBOM => defenders are blind');

      // SECURE contrast: generate an SBOM and audit it against advisories.
      final sbom = BomInventory.generateSbom();
      expect(sbom['bomFormat'], 'CycloneDX');
      expect((sbom['components'] as List), isNotEmpty);

      final findings = BomInventory.auditAgainstAdvisories(sbom);
      expect(
        findings.length,
        greaterThanOrEqualTo(1),
        reason: 'the SBOM audit must surface known-vulnerable components',
      );

      final cves = findings.map((f) => f.advisory.cveId).toList();
      expect(cves, contains('CVE-2023-40001')); // image_loader 2.1.0

      // The vulnerable components exist in the actual bundle either way.
      expect(
        BomInventory.bundledComponents.any(
          (c) => c.name == 'image_loader' && c.version == '2.1.0',
        ),
        isTrue,
      );
    });
  });

  group('silent_sdk_auto_update', () {
    test('unsigned update flips behavior to exfiltrate', () {
      final sdk = UpdatableSdk();
      // Starts benign.
      expect(sdk.run().exfiltrated, isFalse);
      expect(sdk.run().output, contains('ad'));

      // VULN: an unsigned malicious payload is applied with no verification.
      const malicious = RemotePayload(behavior: 'exfiltrate', signature: null);
      sdk.checkForUpdate(malicious);

      final after = sdk.run();
      expect(
        after.exfiltrated,
        isTrue,
        reason: 'silent auto-update turned the SDK malicious post-install',
      );
      expect(after.output, contains(DeviceData.authToken));
    });

    test(
      'signed updater rejects the unsigned payload; behavior stays benign',
      () {
        final sdk = UpdatableSdk();
        final updater = SignedSdkUpdater(sdk);

        const malicious = RemotePayload(
          behavior: 'exfiltrate',
          signature: null,
        );
        final applied = updater.applyIfVerified(malicious);

        expect(applied, isFalse, reason: 'unsigned update must be rejected');
        expect(sdk.run().exfiltrated, isFalse);

        // A forged signature is also rejected.
        const forged = RemotePayload(
          behavior: 'exfiltrate',
          signature: 'sig_deadbeef',
        );
        expect(updater.applyIfVerified(forged), isFalse);
        expect(sdk.run().exfiltrated, isFalse);

        // A correctly-signed (benign) update is accepted.
        final validSig = SignedSdkUpdater.expectedSignature('ads');
        final signed = RemotePayload(behavior: 'ads', signature: validSig);
        expect(updater.applyIfVerified(signed), isTrue);
        expect(sdk.run().exfiltrated, isFalse);
      },
    );
  });
}
