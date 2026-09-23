import 'dart:math';

/// A deliberately-insecure, in-app RAG (retrieval-augmented generation) store.
///
/// INTENTIONALLY VULNERABLE (CWE-349 / CWE-345, OWASP LLM08): documents are
/// [ingest]ed with no provenance, trust, or integrity check, and [retrieve]
/// ranks them purely by a naive similarity score. A single poisoned document
/// containing an embedded instruction is therefore retrieved for a later,
/// unrelated query and fed straight into the prompt as trusted context.
///
/// Everything is deterministic and offline so a regression test can ingest a
/// poisoned doc and assert it is later retrieved and obeyed.
class RagStore {
  final List<RagDoc> _docs = [];

  /// All ingested documents (attacker + benign), in insertion order.
  List<RagDoc> get documents => List.unmodifiable(_docs);

  /// Ingests [text] with no provenance/trust check whatsoever. Any caller -
  /// including untrusted "shared" content - can add authoritative context.
  void ingest(String text, {String source = 'user'}) {
    // VULN: no source allow-list, no signing, no content sanitization. The
    // embedding is a bag-of-words vector derived from the text itself.
    _docs.add(RagDoc(text: text, source: source, embedding: _embed(text)));
  }

  /// Retrieves the top-[k] documents most "similar" to [query] by cosine
  /// similarity over the naive embeddings. No trust weighting is applied, so a
  /// poisoned doc that merely shares a few tokens with the query ranks highly.
  List<RagDoc> retrieve(String query, {int k = 2}) {
    final q = _embed(query);
    final scored =
        _docs.map((d) => _Scored(d, _cosine(q, d.embedding))).toList()
          ..sort((a, b) => b.score.compareTo(a.score));
    return scored.take(k).map((s) => s.doc).toList();
  }

  /// Builds the context block that gets concatenated into the LLM prompt.
  /// Retrieved text is trusted verbatim - embedded instructions survive.
  String buildContext(String query, {int k = 2}) =>
      retrieve(query, k: k).map((d) => '- ${d.text}').join('\n');

  /// A toy bag-of-words embedding over a fixed vocabulary hash space. Not a
  /// real model - just enough to make cosine ranking deterministic offline.
  static List<double> _embed(String text) {
    final vec = List<double>.filled(32, 0);
    for (final tok in _tokens(text)) {
      vec[tok.hashCode.abs() % 32] += 1;
    }
    return vec;
  }

  static Iterable<String> _tokens(String text) => text
      .toLowerCase()
      .split(RegExp(r'[^a-z0-9]+'))
      .where((t) => t.isNotEmpty);

  static double _cosine(List<double> a, List<double> b) {
    var dot = 0.0, na = 0.0, nb = 0.0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    if (na == 0 || nb == 0) return 0;
    return dot / (sqrt(na) * sqrt(nb));
  }
}

/// A single stored document plus its (untrusted) embedding.
class RagDoc {
  RagDoc({required this.text, required this.source, required this.embedding});

  final String text;
  final String source;
  final List<double> embedding;
}

class _Scored {
  _Scored(this.doc, this.score);
  final RagDoc doc;
  final double score;
}
