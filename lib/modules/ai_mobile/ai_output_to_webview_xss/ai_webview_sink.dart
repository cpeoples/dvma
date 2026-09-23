import '../../ai_ml/mock_llm.dart';

/// AI Output Rendered in WebView helper.
///
/// INTENTIONALLY VULNERABLE (CWE-79 / CWE-73, OWASP LLM05, MASVS-PLATFORM-2):
/// the assistant's (attacker-influenced) output is injected into a WebView via
/// `loadHtmlString` with no output encoding. Because the model text can carry
/// a `<script>` tag - the model was steered to reflect an attacker payload -
/// that markup executes in the app's WebView origin, where it can call
/// `evaluateJavascript`-exposed bridges or read local files. This is the
/// AI-output->XSS class (FAQ-Bot CVE-2025-63639 / ZOLL ePCR CVE-2025-12699).
///
/// The secure contrast HTML-escapes the model output before it is placed in the
/// document, so any markup is rendered as inert text and no script executes.
///
/// Offline + deterministic: [InMemoryWebView] is a tiny fake WebView that
/// "parses" a loaded HTML string and records any `<script>` bodies it would
/// have executed. A test can assert the vulnerable load executes the injected
/// script while the escaped load executes nothing.
class AiWebViewSink {
  AiWebViewSink({MockLlm? llm}) : _llm = llm ?? MockLlm();

  final MockLlm _llm;

  /// VULN: take the model output and drop it into the page body verbatim, then
  /// load it. Any `<script>` the model emitted runs in the app origin.
  WebViewLoad renderInsecure(String userRequest) {
    final modelOutput = _llm.run(userRequest).text;
    final html = '<html><body><div>$modelOutput</div></body></html>';
    final webView = InMemoryWebView();
    webView.loadHtmlString(html);
    return WebViewLoad(
      modelOutput: modelOutput,
      html: html,
      executedScripts: webView.executedScripts,
      escaped: false,
    );
  }

  /// LIVE VULN: the model output comes from a real model via [MockLlm.complete]
  /// (falls back to the offline mock when no backend answers). The returned
  /// [WebViewLoad] carries the unescaped [WebViewLoad.html] the caller then
  /// loads into a genuine `WebViewController.loadHtmlString`, so any `<script>`
  /// the model reflected executes in the app's real WebView origin. The
  /// in-memory scan still records what would run (for tests / no-device hosts).
  Future<WebViewLoad> renderInsecureLive(String userRequest) async {
    final modelOutput = (await _llm.complete(userRequest)).text;
    final html = '<html><body><div>$modelOutput</div></body></html>';
    final webView = InMemoryWebView();
    webView.loadHtmlString(html);
    return WebViewLoad(
      modelOutput: modelOutput,
      html: html,
      executedScripts: webView.executedScripts,
      escaped: false,
    );
  }

  /// SECURE contrast: HTML-escape the model output before it goes into the
  /// document. Markup becomes inert text, so the fake WebView executes nothing.
  WebViewLoad renderSecure(String userRequest) {
    final modelOutput = _llm.run(userRequest).text;
    final html =
        '<html><body><div>${htmlEscape(modelOutput)}</div></body></html>';
    final webView = InMemoryWebView();
    webView.loadHtmlString(html);
    return WebViewLoad(
      modelOutput: modelOutput,
      html: html,
      executedScripts: webView.executedScripts,
      escaped: true,
    );
  }

  /// Minimal, dependency-free HTML entity encoding for the five significant
  /// characters. Enough to neutralize injected `<script>` markup.
  static String htmlEscape(String input) {
    return input
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
  }
}

/// A tiny in-memory stand-in for a platform WebView. It does not render, but it
/// "executes" any `<script>...</script>` block found in a loaded HTML string,
/// recording the script bodies so a demo/test can observe what ran.
class InMemoryWebView {
  final List<String> executedScripts = [];

  static final RegExp _scriptTag = RegExp(
    r'<script[^>]*>(.*?)</script>',
    dotAll: true,
    caseSensitive: false,
  );

  /// Loads [html] the way `WebViewController.loadHtmlString` would: unescaped
  /// `<script>` blocks are parsed and executed in the page origin.
  void loadHtmlString(String html) {
    for (final m in _scriptTag.allMatches(html)) {
      executedScripts.add(m.group(1)?.trim() ?? '');
    }
  }

  /// Directly evaluates JS the way `evaluateJavascript` would (also unsafe when
  /// fed model output).
  void evaluateJavascript(String script) => executedScripts.add(script.trim());
}

/// Result of loading model output into the fake WebView.
class WebViewLoad {
  WebViewLoad({
    required this.modelOutput,
    required this.html,
    required this.executedScripts,
    required this.escaped,
  });

  /// The raw model output that was placed into the page.
  final String modelOutput;

  /// The HTML string that was loaded.
  final String html;

  /// Script bodies the WebView executed (empty when properly escaped).
  final List<String> executedScripts;

  /// Whether the output was HTML-escaped before loading.
  final bool escaped;

  /// Whether any script executed (i.e. the XSS fired).
  bool get scriptExecuted => executedScripts.isNotEmpty;
}
