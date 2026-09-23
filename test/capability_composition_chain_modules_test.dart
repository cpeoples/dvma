import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/android_capability_composition_chain/capability_composition_chain.dart';
import 'package:dvma/modules/platform/ios_capability_composition_chain/capability_composition_chain.dart';

/// Regression suite for the capability-composition chain modules. The point of
/// these labs is that no single hop is the vulnerability - the COMPOSITION is -
/// so the tests assert the untrusted trigger reaches the privileged sink with
/// no re-authorization of the ORIGINAL caller, and that the secure contrast
/// breaks the chain by re-authorizing at the sink.
void main() {
  group('android_capability_composition_chain', () {
    test('untrusted notification trigger laundered to the transfer sink', () {
      final r = CapabilityCompositionChain().run(
        CapabilityCompositionChain.attackerCaller,
      );
      expect(r.transferPerformed, isTrue);
      expect(r.originalCallerReauthorized, isFalse);
      expect(r.chainExploited, isTrue);
      expect(r.hops, hasLength(4));
    });

    test(
      'secure path re-authorizes the original caller and breaks the chain',
      () {
        final blocked = CapabilityCompositionChain().runSafe(
          CapabilityCompositionChain.attackerCaller,
        );
        expect(blocked.transferPerformed, isFalse);
        expect(blocked.originalCallerReauthorized, isTrue);
        expect(blocked.chainExploited, isFalse);
        expect(blocked.denyReason, isNotNull);

        final trusted = CapabilityCompositionChain().runSafe('com.dvma.app');
        expect(trusted.transferPerformed, isTrue);
      },
    );
  });

  group('ios_capability_composition_chain', () {
    test(
      'crafted Universal Link exports contacts with no user authorization',
      () {
        final r = IosCapabilityCompositionChain().run(
          IosCapabilityCompositionChain.craftedLink,
        );
        expect(r.contactsExported, isTrue);
        expect(r.userAuthorized, isFalse);
        expect(r.chainExploited, isTrue);
        expect(r.exportedCount, IosCapabilityCompositionChain.contactCount);
      },
    );

    test(
      'secure path gates the protected-data action on fresh authorization',
      () {
        final chain = IosCapabilityCompositionChain();
        final blocked = chain.runSafe(
          IosCapabilityCompositionChain.craftedLink,
        );
        expect(blocked.contactsExported, isFalse);
        expect(blocked.userAuthorized, isTrue);
        expect(blocked.chainExploited, isFalse);
        expect(blocked.denyReason, isNotNull);

        final approved = chain.runSafe(
          IosCapabilityCompositionChain.craftedLink,
          userApproved: true,
        );
        expect(approved.contactsExported, isTrue);
      },
    );
  });
}
