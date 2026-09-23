import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'rsa_padding_crypto.dart';

/// RSA Without OAEP Padding.
///
/// Encrypts a payload with legacy PKCS#1 v1.5 padding (Bleichenbacher-oracle
/// exposed) instead of OAEP.
class RsaNoOaepPaddingScreen extends StatefulWidget {
  const RsaNoOaepPaddingScreen({super.key});

  static const String vulnId = 'rsa_no_oaep_padding';

  @override
  State<RsaNoOaepPaddingScreen> createState() => _RsaNoOaepPaddingScreenState();
}

class _RsaNoOaepPaddingScreenState extends State<RsaNoOaepPaddingScreen> {
  RsaPaddingCrypto? _crypto;
  bool _generating = false;
  String? _vulnResult;
  String? _secureResult;

  Future<RsaPaddingCrypto> _keys() async {
    if (_crypto != null) return _crypto!;
    setState(() => _generating = true);
    // 2048-bit keygen is CPU-bound; yield first so the spinner paints.
    await Future<void>.delayed(Duration.zero);
    final c = RsaPaddingCrypto.generate();
    setState(() {
      _crypto = c;
      _generating = false;
    });
    return c;
  }

  Future<void> _runVulnerable() async {
    final r = (await _keys()).pkcs1v15();
    setState(
      () => _vulnResult =
          'ciphertext        : ${r.hex}\n'
          'round-trip        : ${r.roundTrip}\n'
          'tampered decrypt  : ${r.tamperedBehavior}',
    );

    DvmaEvidence.record(
      RsaNoOaepPaddingScreen.vulnId,
      'pkcs1v15',
      'RSA/PKCS#1 v1.5: round-trip="${r.roundTrip}"; tampered ciphertext -> '
          '${r.tamperedBehavior}',
    );
  }

  Future<void> _runSecure() async {
    final r = (await _keys()).oaep();
    setState(
      () => _secureResult =
          'ciphertext        : ${r.hex}\n'
          'round-trip        : ${r.roundTrip}\n'
          'tampered decrypt  : ${r.tamperedBehavior}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: RsaNoOaepPaddingScreen.vulnId,
      title: 'RSA Without OAEP Padding',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The payload is RSA-encrypted with legacy PKCS#1 v1.5 padding instead '
          'of OAEP. v1.5 is malleable and its padding-validity behavior is the '
          'classic Bleichenbacher chosen-ciphertext oracle: an attacker who '
          'submits modified ciphertexts and observes whether the padding was '
          'well-formed recovers the plaintext without the private key. Both '
          'paths use one real 2048-bit RSA keypair generated on-device. The '
          'secure path uses RSA-OAEP (SHA-256); its randomized, '
          'integrity-checked padding rejects the tampered ciphertext uniformly '
          'and closes the oracle.',
      children: [
        if (_generating) const LinearProgressIndicator(),
        DemoActionButton(
          label: 'Vulnerable: RSA/PKCS#1 v1.5',
          onPressed: _runVulnerable,
        ),
        if (_vulnResult != null)
          EvidencePanel(label: 'PKCS#1 v1.5 result', value: _vulnResult!),
        DemoActionButton(
          label: 'Secure: RSA-OAEP (SHA-256)',
          onPressed: _runSecure,
        ),
        if (_secureResult != null)
          EvidencePanel(label: 'OAEP result', value: _secureResult!),
      ],
    );
  }
}
