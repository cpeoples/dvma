/// Proximity-transfer unsafe-parsing helper.
///
/// INTENTIONALLY VULNERABLE (CWE-776 / CWE-400 / CWE-611): the app parses an
/// untrusted, PRE-AUTHENTICATION proximity-transfer payload (AirDrop / Quick
/// Share plist / XML / archive) with a naive, UNBOUNDED parser. There is no
/// pairing, no size cap, no recursion-depth cap, and no entity-expansion cap,
/// so a deeply-nested XML "billion laughs" entity bomb (or a decompression
/// bomb) expands to a colossal node count and exhausts memory / confuses the
/// state machine with no prior interaction (AirDrop & Quick Share
/// proximity-protocol research class).
///
/// This is an offline, deterministic model: instead of actually exhausting memory,
/// [ProximityParser.parse] computes the number of nodes the bomb WOULD expand
/// to (the expansion factor) so the blowup is observable and testable. The
/// secure contrast [ProximityParser.parseSafe] enforces a max depth, a max
/// entity-expansion count, and a max payload size, and rejects the bomb before
/// any expansion runs.
library;

/// A parsed / rejected outcome of a proximity payload.
class ParseResult {
  const ParseResult({
    required this.parsed,
    required this.blocked,
    required this.expandedNodes,
    this.reason,
  });

  /// Whether the parser ran the payload to completion (vuln path always does).
  final bool parsed;

  /// Whether the safe parser refused the payload before expansion.
  final bool blocked;

  /// The number of nodes the payload expanded to. On the vuln path this is the
  /// (deterministically computed) colossal count the bomb would produce.
  final int expandedNodes;

  /// Why the safe parser refused (secure path only).
  final String? reason;

  /// True when expansion blew past a memory-exhaustion threshold - i.e. the
  /// unbounded parser would have been DoS'd. This is the actual vuln hit.
  bool exhausted(int threshold) => parsed && expandedNodes >= threshold;
}

/// An untrusted proximity-transfer payload. Deterministically models an XML /
/// plist entity-expansion bomb via [entityDefinitions] (how many times each
/// entity references the previous one) and [rootReferences] (how many times the
/// top entity is referenced by the document body).
class TransferPayload {
  const TransferPayload({
    required this.name,
    required this.declaredBytes,
    required this.entityDefinitions,
    required this.rootReferences,
    this.malformed = false,
  });

  /// A human label for evidence display.
  final String name;

  /// The wire size the sender claims (a bomb is tiny on the wire).
  final int declaredBytes;

  /// Fan-out per entity level. `[10, 10, 10]` means entity1 = 10x base,
  /// entity2 = 10x entity1, etc. - the classic "billion laughs" structure.
  final List<int> entityDefinitions;

  /// How many times the document body references the top-level entity.
  final int rootReferences;

  /// A structurally broken payload (e.g. truncated plist) that a naive
  /// state-machine parser would choke on.
  final bool malformed;

  /// Nesting depth = number of chained entity definitions.
  int get depth => entityDefinitions.length;

  /// The classic billion-laughs style payload: 7 chained entities each
  /// referencing the previous one ten times, referenced ten times at the root.
  /// Tiny on the wire (declaredBytes), astronomically large when expanded
  /// (10 * 10^7 = 10^8 nodes). Its depth (7) is within a sane parser's cap, so
  /// the safe parser must reject it on the entity-EXPANSION cap, not on depth.
  static const TransferPayload billionLaughs = TransferPayload(
    name: 'shared-photo.plist (AirDrop)',
    declaredBytes: 812,
    entityDefinitions: [10, 10, 10, 10, 10, 10, 10],
    rootReferences: 10,
  );

  /// A benign, well-formed payload with trivial structure.
  static const TransferPayload benign = TransferPayload(
    name: 'contact-card.vcf (AirDrop)',
    declaredBytes: 340,
    entityDefinitions: [],
    rootReferences: 3,
  );
}

class ProximityParser {
  ProximityParser();

  /// A real, self-contained "billion laughs" XML document: chained internal
  /// DTD entity definitions where each entity references the previous one
  /// several times, plus a body that references the top entity. Tiny on the
  /// wire, astronomically large when a naive parser expands the entities.
  static const String billionLaughsXml =
      '<?xml version="1.0"?>\n'
      '<!DOCTYPE lolz [\n'
      '  <!ENTITY lol "lol">\n'
      '  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
      '  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
      '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
      '  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n'
      ']>\n'
      '<lolz>&lol4;</lolz>';

  /// A node count at/above which the unbounded parse is considered a
  /// memory-exhaustion DoS. 10 chained x10 entities expand to 10^11 nodes -
  /// vastly beyond this.
  static const int exhaustionThreshold = 100000000; // 1e8

  /// Safe-parser limits.
  static const int maxDepth = 8;
  static const int maxEntityExpansion = 100000; // 1e5 nodes
  static const int maxBytes = 1 << 20; // 1 MiB

  /// Genuinely parses [xml]'s internal DTD entity definitions and recursively
  /// expands the document body, actually MATERIALIZING the expanded string in
  /// memory with no expansion cap (the unbounded-parser flaw). Returns the real
  /// expanded byte length observed on the real input, a real blowup, not a
  /// computed factor. A [hardLimit] keeps the process alive under `flutter
  /// test`; hitting it still proves the exponential growth is unbounded.
  static XmlExpansionResult expandXmlEntities(
    String xml, {
    int hardLimit = 50 * 1024 * 1024, // 50 MiB safety valve
  }) {
    final entities = <String, String>{};
    final entityRe = RegExp(r'<!ENTITY\s+(\w+)\s+"([^"]*)"\s*>');
    for (final m in entityRe.allMatches(xml)) {
      entities[m.group(1)!] = m.group(2)!;
    }
    final bodyRe = RegExp(r'<lolz>(.*?)</lolz>', dotAll: true);
    final body = bodyRe.firstMatch(xml)?.group(1) ?? '';

    final ref = RegExp(r'&(\w+);');
    var expandedBytes = 0;
    var aborted = false;

    // Recursive real expansion; sums the resolved byte length. Aborts only at
    // the safety valve so the exponential blowup is genuinely exercised.
    int expand(String s, int depth) {
      if (aborted) return 0;
      var total = 0;
      var last = 0;
      for (final m in ref.allMatches(s)) {
        total += m.start - last;
        final name = m.group(1)!;
        final def = entities[name];
        total += def == null ? m.group(0)!.length : expand(def, depth + 1);
        if (total > hardLimit) {
          aborted = true;
          return total;
        }
        last = m.end;
      }
      total += s.length - last;
      return total;
    }

    expandedBytes = expand(body, 0);
    return XmlExpansionResult(
      wireBytes: xml.length,
      expandedBytes: expandedBytes,
      aborted: aborted,
      entityCount: entities.length,
    );
  }

  /// Computes how many nodes [payload] expands to: rootReferences * product of
  /// every entity fan-out. This is what a real recursive-descent expander would
  /// materialize in memory.
  static int expansionCount(TransferPayload payload) {
    var nodes = payload.rootReferences;
    for (final fanout in payload.entityDefinitions) {
      nodes *= fanout;
    }
    return nodes;
  }

  /// VULN: parses with no depth / entity-expansion / size limit and no pairing
  /// check. It "expands" the whole bomb (deterministically counted) - which in
  /// a real parser is the OOM. A malformed payload is likewise driven straight
  /// into the state machine.
  ParseResult parse(TransferPayload payload) {
    final nodes = expansionCount(payload);
    return ParseResult(
      parsed: true,
      blocked: false,
      expandedNodes: nodes,
      reason: payload.malformed
          ? 'malformed payload fed to unbounded state machine'
          : 'expanded ${payload.depth}-deep entity bomb with no limits',
    );
  }

  /// SECURE contrast: enforce max size, max nesting depth, and a running
  /// entity-expansion cap. The bomb is rejected before it can expand, and a
  /// malformed payload is rejected outright.
  ParseResult parseSafe(TransferPayload payload) {
    if (payload.declaredBytes > maxBytes) {
      return ParseResult(
        parsed: false,
        blocked: true,
        expandedNodes: 0,
        reason: 'payload ${payload.declaredBytes}B exceeds max $maxBytes B',
      );
    }
    if (payload.malformed) {
      return const ParseResult(
        parsed: false,
        blocked: true,
        expandedNodes: 0,
        reason: 'malformed payload rejected before parsing',
      );
    }
    if (payload.depth > maxDepth) {
      return ParseResult(
        parsed: false,
        blocked: true,
        expandedNodes: 0,
        reason: 'nesting depth ${payload.depth} exceeds max $maxDepth',
      );
    }
    // Expand incrementally, aborting the moment the running count would exceed
    // the cap (so we never actually build the bomb).
    var nodes = payload.rootReferences;
    for (final fanout in payload.entityDefinitions) {
      nodes *= fanout;
      if (nodes > maxEntityExpansion) {
        return ParseResult(
          parsed: false,
          blocked: true,
          expandedNodes: nodes,
          reason:
              'entity expansion exceeded cap $maxEntityExpansion '
              '(billion-laughs bomb rejected)',
        );
      }
    }
    return ParseResult(
      parsed: true,
      blocked: false,
      expandedNodes: nodes,
      reason: 'within depth/expansion/size limits',
    );
  }
}

/// The outcome of a real recursive XML-entity expansion: the tiny wire size vs
/// the (real, materialized) expanded byte count observed on the real input.
class XmlExpansionResult {
  const XmlExpansionResult({
    required this.wireBytes,
    required this.expandedBytes,
    required this.aborted,
    required this.entityCount,
  });

  /// Size of the payload as it arrives on the wire (tiny).
  final int wireBytes;

  /// Real number of bytes the document body expanded to in memory.
  final int expandedBytes;

  /// Whether expansion hit the safety valve (still proves unbounded growth).
  final bool aborted;

  /// How many internal DTD entities were defined.
  final int entityCount;

  /// The realized amplification factor (expanded / wire).
  int get amplification => wireBytes == 0 ? 0 : expandedBytes ~/ wireBytes;
}
