import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/native_proximity_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'proximity_parser.dart';

/// Proximity Transfer Unsafe Parsing (AirDrop / Quick Share).
///
/// The app parses an untrusted, pre-authentication proximity-transfer payload
/// with a naive, unbounded parser, so a deeply-nested "billion laughs" entity
/// bomb expands to a colossal node count and exhausts memory with no prior
/// pairing. The secure contrast enforces depth / entity-expansion / size caps
/// and rejects the bomb before it can expand.
class ProximityTransferUnsafeParsingScreen extends StatefulWidget {
  const ProximityTransferUnsafeParsingScreen({super.key});

  static const String vulnId = 'proximity_transfer_unsafe_parsing';

  @override
  State<ProximityTransferUnsafeParsingScreen> createState() =>
      _ProximityTransferUnsafeParsingScreenState();
}

class _ProximityTransferUnsafeParsingScreenState
    extends State<ProximityTransferUnsafeParsingScreen> {
  String? _vuln;
  String? _secure;
  String? _native;
  String? _realXml;

  // An over-read TLV record: the length field lies far past the bytes actually
  // received on the wire (the AirDrop / Quick Share length-over-read primitive
  // that complements the entity-expansion bomb below).
  static const int _tlvDeclaredLen = 200;
  static const int _tlvPayloadLen = 16;

  Future<void> _run() async {
    final parser = ProximityParser();
    const bomb = TransferPayload.billionLaughs;

    // Prefer the real native TLV parser (compiled C in libdvma_native.so): it
    // trusts the declared length field and reads past the received payload into
    // adjacent heap. Off Android it returns null and only the offline entity-
    // expansion model below is shown.
    final native = await NativeProximityBridge.parseTlv(
      declaredLen: _tlvDeclaredLen,
      payloadLen: _tlvPayloadLen,
    );

    // VULN: the unbounded parser expands the entity bomb with no pairing check
    // and no limits. We compute the node count it WOULD materialize.
    final vuln = parser.parse(bomb);
    // real: actually parse the internal-DTD entity definitions and recursively
    // materialize the expansion of a genuine billion-laughs XML in memory,
    // observing the real byte blowup (bounded by a safety valve).
    final realXml = ProximityParser.expandXmlEntities(
      ProximityParser.billionLaughsXml,
    );
    final vulnBuf = StringBuffer()
      ..writeln('payload        : ${bomb.name}')
      ..writeln('wire size      : ${bomb.declaredBytes} bytes (tiny)')
      ..writeln('nesting depth  : ${bomb.depth}')
      ..writeln('parser         : parse() - no depth/entity/size limit')
      ..writeln('paired first?  : no (pre-auth proximity payload)')
      ..writeln('expanded nodes : ${vuln.expandedNodes}')
      ..writeln('threshold      : ${ProximityParser.exhaustionThreshold}')
      ..writeln(
        'memory exhausted: ${vuln.exhausted(ProximityParser.exhaustionThreshold)}',
      )
      ..writeln('reason         : ${vuln.reason}');

    // SECURE: the same bomb hits the bounded parser and is rejected.
    final secure = parser.parseSafe(bomb);
    final secureBuf = StringBuffer()
      ..writeln('payload        : ${bomb.name}')
      ..writeln('parser         : parseSafe() - depth/entity/size caps')
      ..writeln('max depth      : ${ProximityParser.maxDepth}')
      ..writeln('max expansion  : ${ProximityParser.maxEntityExpansion}')
      ..writeln('max bytes      : ${ProximityParser.maxBytes}')
      ..writeln('parsed         : ${secure.parsed}')
      ..writeln('blocked        : ${secure.blocked}')
      ..writeln('nodes at abort : ${secure.expandedNodes}')
      ..writeln('reason         : ${secure.reason}');

    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
      _native = native == null
          ? null
          : 'source: REAL native (libdvma_native.so)\n'
                'declaredLen=$_tlvDeclaredLen payloadLen=$_tlvPayloadLen\n$native';
      _realXml =
          'real recursive entity expansion of billion-laughs XML\n'
          'wire size      : ${realXml.wireBytes} bytes\n'
          'entities        : ${realXml.entityCount}\n'
          'expanded to     : ${realXml.expandedBytes} bytes '
          '(${realXml.aborted ? 'hit safety valve - unbounded' : 'fully expanded'})\n'
          'amplification   : ${realXml.amplification}x';
    });

    // real artifact: record the pre-auth entity-bomb expansion (tiny wire size
    // -> colossal materialized node count) that exhausts memory.
    await DvmaEvidence.record(
      ProximityTransferUnsafeParsingScreen.vulnId,
      'entity-bomb',
      'payload=${bomb.name} wireBytes=${bomb.declaredBytes} depth=${bomb.depth} '
          'expandedNodes=${vuln.expandedNodes} '
          'threshold=${ProximityParser.exhaustionThreshold} '
          'exhausted=${vuln.exhausted(ProximityParser.exhaustionThreshold)}',
    );

    // real artifact: the genuinely-materialized entity expansion byte blowup.
    await DvmaEvidence.record(
      ProximityTransferUnsafeParsingScreen.vulnId,
      'entity-bomb-real',
      'real XML entity expansion: wireBytes=${realXml.wireBytes} '
          'expandedBytes=${realXml.expandedBytes} '
          'amplification=${realXml.amplification}x aborted=${realXml.aborted}',
    );

    // real native artifact: the compiled-C TLV over-read, when on Android.
    if (native != null) {
      await DvmaEvidence.record(
        ProximityTransferUnsafeParsingScreen.vulnId,
        'tlv-overread',
        'REAL native TLV parse over libdvma_native.so '
            '(declaredLen=$_tlvDeclaredLen payloadLen=$_tlvPayloadLen): $native',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ProximityTransferUnsafeParsingScreen.vulnId,
      title: 'Proximity Transfer Unsafe Parsing (AirDrop / Quick Share)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app parses an untrusted, PRE-AUTHENTICATION proximity-transfer '
          'payload (AirDrop / Quick Share plist / XML / archive) with a naive, '
          'UNBOUNDED parser: no pairing, no size cap, no recursion-depth cap, '
          'no entity-expansion cap. A tiny deeply-nested "billion laughs" '
          'entity bomb therefore expands to a colossal node count and exhausts '
          'memory with no prior interaction. On Android a compiled-C TLV parser '
          'over-reads on a lying length field; on every host a REAL recursive '
          'entity expander materializes a genuine billion-laughs XML in memory '
          'and reports the observed byte blowup. The secure path enforces max '
          'depth + max entity-expansion + max size and rejects the bomb before '
          'it can expand.',
      children: [
        DemoActionButton(
          label: 'Receive AirDrop payload (unbounded parse)',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'parse() - unbounded, memory exhausted',
            value: _vuln!,
          ),
        if (_native != null)
          EvidencePanel(
            label: 'native TLV parse - length-field over-read',
            value: _native!,
          ),
        if (_realXml != null)
          EvidencePanel(
            label: 'real XML entity expansion - materialized blowup',
            value: _realXml!,
          ),
        if (_secure != null)
          EvidencePanel(label: 'parseSafe() - bomb rejected', value: _secure!),
      ],
    );
  }
}
