/// WKWebView Untrusted URL -> Local File Read helper (iOS).
///
/// INTENTIONALLY VULNERABLE (CWE-79 / CWE-73 / CWE-200): unsanitized
/// user-controlled fields are reflected into HTML that is rendered in a
/// WKWebView, AND the WebView is created with local file access enabled
/// (`allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs`, and the
/// content is loaded from a `file://` base). Injected JavaScript can therefore
/// `fetch()`/XHR the app's own local files (tokens, patient records) and
/// exfiltrate them (ZOLL ePCR iOS CVE-2025-12699 class).
///
/// This is an offline + deterministic simulation. [LocalFileWebView] models the
/// WKWebView: it holds a tiny in-memory local filesystem, reflects a field into
/// an HTML template, "executes" any injected `<script>` that reads a local
/// file, and records what was exfiltrated. No real WebView or filesystem is
/// touched. Tests can assert the payload reads a local file on the vuln path
/// and cannot on the secure path (HTML-escaped reflection + file access off).
library;

/// The outcome of reflecting a user field into the WebView.
class ReflectionResult {
  const ReflectionResult({
    required this.renderedHtml,
    required this.scriptExecuted,
    required this.exfiltratedFiles,
    required this.fileAccessEnabled,
  });

  /// The HTML that was rendered (after reflecting the user field).
  final String renderedHtml;

  /// Whether an injected inline script ran.
  final bool scriptExecuted;

  /// path -> contents of any local files the injected script read.
  final Map<String, String> exfiltratedFiles;

  /// Whether the WebView had local file access enabled.
  final bool fileAccessEnabled;

  /// True if injected JS actually read one or more local files.
  bool get leakedLocalFiles => exfiltratedFiles.isNotEmpty;
}

class LocalFileWebView {
  LocalFileWebView({
    required this.fileAccessEnabled,
    Map<String, String>? localFiles,
  }) : _localFiles =
           localFiles ??
           const {
             'file:///var/app/Documents/session.json':
                 '{"token":"tok-8b21-secret"}',
             'file:///var/app/Documents/patient.json':
                 '{"name":"Jane Roe","mrn":"MRN-4471"}',
           };

  /// Whether allowFileAccessFromFileURLs-style access is on.
  final bool fileAccessEnabled;

  final Map<String, String> _localFiles;

  /// VULN: reflect [userField] into the page with no escaping and render it
  /// from a file:// origin with file access enabled. Any `<script>` in the
  /// field runs and, using the enabled file access, can read local files.
  ReflectionResult reflect(String userField) {
    final html = '<html><body><h1>Report for $userField</h1></body></html>';
    return _render(html, userField, escaped: false);
  }

  /// SECURE contrast: HTML-escape the reflected field AND disable local file
  /// access. Injected markup becomes inert text and even a script could not
  /// reach the filesystem.
  ReflectionResult reflectSafe(String userField) {
    final escaped = _escape(userField);
    final html = '<html><body><h1>Report for $escaped</h1></body></html>';
    // Force file access off on the secure path.
    return LocalFileWebView(
      fileAccessEnabled: false,
      localFiles: _localFiles,
    )._render(html, escaped, escaped: true);
  }

  ReflectionResult _render(
    String html,
    String reflected, {
    required bool escaped,
  }) {
    final exfil = <String, String>{};
    var scriptRan = false;

    // Only unescaped reflection can inject live markup/script.
    if (!escaped && _containsScript(reflected)) {
      scriptRan = true;
      if (fileAccessEnabled) {
        // The injected script reads every local file it can reach and
        // "exfiltrates" it (models fetch('file://...') back to attacker).
        exfil.addAll(_localFiles);
      }
    }
    return ReflectionResult(
      renderedHtml: html,
      scriptExecuted: scriptRan,
      exfiltratedFiles: exfil,
      fileAccessEnabled: fileAccessEnabled,
    );
  }

  static bool _containsScript(String s) => s.toLowerCase().contains('<script');

  static String _escape(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
}
