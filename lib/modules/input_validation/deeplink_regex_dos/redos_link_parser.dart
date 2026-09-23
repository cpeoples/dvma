/// Deep Link Regex DoS (ReDoS) helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1333 / CWE-400): a catastrophically-
/// backtracking regex parses incoming deep-link URLs. A crafted link (many
/// repeats of a character that ultimately fails to match) forces the regex
/// engine into exponential backtracking, freezing/hanging the app on the main
/// isolate (the Mattermost CVE-2024-3872 class).
///
/// The step-count model ([measureBacktracking]/[parse]) never executes
/// the hanging regex, so it is safe for tests/UI. The real demo ([parseReal])
/// does execute `^(a+)+$`, but clamps the ambiguous 'a' run to [realRunCap] so
/// the exponential blow-up is observable (hundreds of ms to a few seconds) yet
/// bounded, it returns instead of hanging. [parseSafe]/[parseSafeReal] use a
/// linear, anchored, non-backtracking pattern whose cost grows linearly.
class RedosLinkParser {
  RedosLinkParser._();

  /// The KNOWN catastrophic-backtracking pattern (nested quantifiers). Kept for
  /// reference/inspection; it is not executed against untrusted input here.
  static final RegExp pattern = RegExp(r'^(a+)+$');

  /// A linear, anchored, non-backtracking pattern used by the safe parser.
  static final RegExp safePattern = RegExp(r'^a+$');

  /// Step cap so the simulated exponential count never overflows / never
  /// pretends to run forever. Any input at/above this is "definitely hangs".
  static const int stepCap = 1 << 40; // ~1.1e12

  /// Inspects a crafted input for the catastrophic shape driving `^(a+)+$`:
  /// the LONGEST consecutive run of 'a' (the ambiguous repetition the nested
  /// quantifier backtracks over) and whether the overall string ultimately
  /// FAILS to match (a trailing/embedded non-'a' char). A failing match with a
  /// long 'a' run is the exponential case.
  static ({int aRun, bool fails}) _shape(String input) {
    var longest = 0;
    var current = 0;
    for (var i = 0; i < input.length; i++) {
      if (input.codeUnitAt(i) == 0x61 /* 'a' */ ) {
        current++;
        if (current > longest) longest = current;
      } else {
        current = 0;
      }
    }
    final fails = longest != input.length; // not entirely 'a' -> match fails
    return (aRun: longest, fails: fails);
  }

  /// VULN cost model: simulated number of regex steps for `^(a+)+$` on [input].
  /// When the input is a run of `n` 'a's followed by a non-matching char, the
  /// engine explores ~2^(n-1) partitions before failing -> exponential. When it
  /// matches cleanly the cost is linear. The result is capped at [stepCap] so
  /// we never actually loop exponentially.
  static int measureBacktracking(String input) {
    final shape = _shape(input);
    if (!shape.fails) {
      // Clean match: roughly linear in length.
      return input.length;
    }
    final n = shape.aRun;
    if (n <= 1) return 1;
    if (n - 1 >= 40) return stepCap; // 2^39+ already exceeds the cap
    final steps = 1 << (n - 1); // 2^(n-1)
    return steps > stepCap ? stepCap : steps;
  }

  /// Whether the vulnerable parser would effectively hang on [input] given a
  /// step [threshold] (default: 1,000,000 steps ~ perceptible freeze).
  static bool wouldHang(String input, {int threshold = 1000000}) {
    return measureBacktracking(input) >= threshold;
  }

  /// VULN: "parses" the link by consulting the exponential cost model. Returns
  /// a result describing the (simulated) step count and whether it hangs. The
  /// evil regex is not run against the raw input.
  static ParseResult parse(String link) {
    final path = _pathPart(link);
    final steps = measureBacktracking(path);
    final hang = steps >= 1000000;
    return ParseResult(
      matched: !hang && !_shape(path).fails,
      steps: steps,
      hangs: hang,
      reason: hang
          ? 'catastrophic backtracking: ~$steps steps (would hang)'
          : 'parsed in ~$steps steps',
    );
  }

  /// SECURE contrast: a linear, anchored, non-backtracking parse whose cost is
  /// O(n). Never hangs regardless of input.
  static ParseResult parseSafe(String link) {
    final path = _pathPart(link);
    // Linear scan cost == input length; no nested quantifier backtracking.
    final steps = path.length;
    final matched = safePattern.hasMatch(path);
    return ParseResult(
      matched: matched,
      steps: steps,
      hangs: false,
      reason: 'linear parse: $steps steps (no backtracking)',
    );
  }

  /// Extract the path/host portion the regex is applied to. For a link like
  /// `dvma://open/aaaa...!` we take everything after the scheme separator.
  static String _pathPart(String link) {
    final idx = link.indexOf('://');
    return idx >= 0 ? link.substring(idx + 3) : link;
  }

  /// Hard cap on the ambiguous run length actually fed to the evil regex, so
  /// the real backtracking demo stays within a few seconds instead of hanging
  /// forever. ~26 'a's + a failing char is clearly slow (hundreds of ms to a
  /// few seconds on a phone/CI) but returns.
  static const int realRunCap = 26;

  /// VULN (real): actually execute the catastrophic-backtracking regex
  /// `^(a+)+$` against the crafted path and MEASURE real elapsed wall-clock
  /// time with a [Stopwatch]. Unlike [parse] (a step-count model), this runs
  /// the engine for real. The ambiguous 'a' run is clamped to [realRunCap] so
  /// the exponential blow-up is observable but bounded (returns within a few
  /// seconds). Returns the clamped input length and measured milliseconds.
  static RealRedosResult parseReal(String link) {
    final rawPath = _pathPart(link);
    final input = _clampAmbiguousRun(rawPath, realRunCap);

    final sw = Stopwatch()..start();
    // real catastrophic backtracking: this genuinely spins the regex engine.
    final matched = pattern.hasMatch(input);
    sw.stop();

    final micros = sw.elapsedMicroseconds;
    final ms = micros / 1000.0;
    return RealRedosResult(
      inputLength: input.length,
      elapsedMs: ms,
      matched: matched,
      reason:
          'ran ^(a+)+\$ on ${input.length} chars in '
          '${ms.toStringAsFixed(1)} ms (real backtracking)',
    );
  }

  /// SECURE contrast (real): run the anchored, linear pattern on the SAME
  /// (clamped) input and measure real time, orders of magnitude faster.
  static RealRedosResult parseSafeReal(String link) {
    final rawPath = _pathPart(link);
    final input = _clampAmbiguousRun(rawPath, realRunCap);

    final sw = Stopwatch()..start();
    final matched = safePattern.hasMatch(input);
    sw.stop();

    final ms = sw.elapsedMicroseconds / 1000.0;
    return RealRedosResult(
      inputLength: input.length,
      elapsedMs: ms,
      matched: matched,
      reason:
          'ran ^a+\$ on ${input.length} chars in '
          '${ms.toStringAsFixed(3)} ms (linear, no backtracking)',
    );
  }

  /// Clamp the LONGEST consecutive run of 'a' in [input] to at most [cap]
  /// characters (leaving any trailing non-'a' char intact so the match still
  /// fails and backtracking is triggered). Prevents an attacker-pasted 10k-'a'
  /// string from hanging the demo indefinitely.
  static String _clampAmbiguousRun(String input, int cap) {
    final b = StringBuffer();
    var run = 0;
    for (var i = 0; i < input.length; i++) {
      final isA = input.codeUnitAt(i) == 0x61; // 'a'
      if (isA) {
        run++;
        if (run <= cap) b.write('a');
      } else {
        run = 0;
        b.write(input[i]);
      }
    }
    return b.toString();
  }
}

/// Outcome of a real (timed) regex execution.
class RealRedosResult {
  const RealRedosResult({
    required this.inputLength,
    required this.elapsedMs,
    required this.matched,
    required this.reason,
  });

  /// Length of the (clamped) string the regex was actually run against.
  final int inputLength;

  /// Real measured wall-clock time in milliseconds.
  final double elapsedMs;

  /// Whether the pattern matched.
  final bool matched;

  /// Human-readable explanation.
  final String reason;
}

/// Outcome of a (simulated) parse.
class ParseResult {
  const ParseResult({
    required this.matched,
    required this.steps,
    required this.hangs,
    required this.reason,
  });

  /// Whether the pattern matched the input.
  final bool matched;

  /// Simulated regex-engine step count.
  final int steps;

  /// Whether the vulnerable parser would effectively hang.
  final bool hangs;

  /// Human-readable explanation.
  final String reason;
}
