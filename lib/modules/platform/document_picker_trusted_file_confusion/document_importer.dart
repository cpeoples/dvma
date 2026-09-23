/// Document-Picker Trusted-File Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-646 / CWE-73): the app ASSUMES a
/// file returned by the system document/file picker (or a security-scoped URL)
/// is trustworthy just because the OS handed it over. It feeds the file's
/// DECLARED type/name/path/contents into a sensitive sink with no
/// re-validation, so a hostile document whose real content disagrees with its
/// claimed type - or whose declared path points into a privileged location -
/// is imported and acted on.
///
/// This is the opposite direction to the over-broad FileProvider module: there
/// the app EXPORTS too much; here the app IMPORTS and over-trusts.
///
/// This now runs on a real `dart:io` filesystem when available: [DocumentImporter]
/// WRITES the picked bytes to a real temp file (`getTemporaryDirectory`), then
/// re-reads the leading MAGIC BYTES back OFF DISK to sniff the real type, and
/// canonicalizes the declared path with real `File(...).absolute` + `..`
/// normalization. The vulnerable [import] trusts the declared type/path; the
/// secure [importSafe] re-validates the real on-disk content and confines the
/// canonical path under the import sandbox. Under `flutter test` (or a host with
/// no temp dir) it falls back to sniffing the in-memory bytes so the demo stays
/// offline and deterministic.
library;

import 'dart:io';

import 'package:path_provider/path_provider.dart';

import '../../../core/evidence_sink.dart';

/// A document handed back by the (untrusted) system picker.
class PickedDocument {
  const PickedDocument({
    required this.declaredName,
    required this.declaredMimeType,
    required this.declaredPath,
    required this.bytes,
  });

  /// The display name the picker claims (e.g. "invoice.txt").
  final String declaredName;

  /// The MIME type the picker claims (e.g. "text/plain").
  final String declaredMimeType;

  /// The path/URL the picker claims to point at.
  final String declaredPath;

  /// The actual file bytes (leading bytes reveal the real type).
  final String bytes;

  /// The real type sniffed from the in-memory content (deterministic model /
  /// offline fallback). The real on-disk sniff is done by [DocumentImporter]
  /// re-reading the magic bytes back off a temp file.
  String get sniffedType => DocumentImporter._sniff(bytes);
}

/// The outcome of importing a picked document.
class ImportOutcome {
  const ImportOutcome({
    required this.imported,
    required this.blocked,
    required this.trustedType,
    required this.sniffedType,
    required this.realPath,
    required this.executedAsCode,
    required this.escapedSandbox,
    this.artifactPath,
    this.reason,
  });

  /// Whether the document was accepted into the sensitive sink.
  final bool imported;

  /// Whether the safe importer refused.
  final bool blocked;

  /// The type the importer treated the file as.
  final String? trustedType;

  /// The type sniffed from the real on-disk magic bytes.
  final String sniffedType;

  /// The canonical absolute path the declared path resolved to.
  final String realPath;

  /// True when the file was parsed/executed as code because its DECLARED type
  /// said it was safe while its real content was hostile - the confusion hit.
  final bool executedAsCode;

  /// True when the canonical path escaped the app's import sandbox.
  final bool escapedSandbox;

  /// The real temp file the picked bytes were written to (when on-disk).
  final String? artifactPath;

  /// Why the safe importer refused.
  final String? reason;
}

class DocumentImporter {
  const DocumentImporter();

  /// The sandbox the importer is confined to (lexical, for the fallback path).
  static const String importSandbox = '/data/data/com.dvma/files/inbox';

  /// A hostile document: named/claimed as harmless ".txt" but the real bytes
  /// are an executable shell script, AND it declares a path that traverses
  /// into a privileged location.
  static const PickedDocument hostile = PickedDocument(
    declaredName: 'notes.txt',
    declaredMimeType: 'text/plain',
    declaredPath: '/data/data/com.dvma/files/inbox/../../shared_prefs/auth.xml',
    bytes: '#!/bin/sh\nrm -rf /sdcard/DCIM\n',
  );

  /// A benign, self-consistent document.
  static const PickedDocument benign = PickedDocument(
    declaredName: 'invoice.pdf',
    declaredMimeType: 'application/pdf',
    declaredPath: '/data/data/com.dvma/files/inbox/invoice.pdf',
    bytes: '%PDF-1.7\n...',
  );

  /// Sniffs a MIME type from leading magic bytes (independent of any claim).
  static String _sniff(String head) {
    if (head.startsWith('#!')) return 'application/x-executable-script';
    if (head.startsWith('MZ')) return 'application/x-dosexec';
    if (head.startsWith('%PDF')) return 'application/pdf';
    if (head.startsWith('<?xml') || head.startsWith('<')) return 'text/xml';
    return 'text/plain';
  }

  /// Writes [doc] bytes to a real temp file and reads the leading magic bytes
  /// back OFF DISK, returning `(sniffedType, tempPath)`. Falls back to sniffing
  /// the in-memory bytes (path null) when no temp dir is available.
  static Future<({String type, String? path})> _sniffOffDisk(
    PickedDocument doc,
  ) async {
    try {
      final dir = await getTemporaryDirectory();
      final tmp = File('${dir.path}/dvma_import_${doc.declaredName}');
      await tmp.parent.create(recursive: true);
      await tmp.writeAsBytes(doc.bytes.codeUnits, flush: true);
      // Re-read the real content off disk; sniff from the actual leading bytes.
      final raf = await tmp.open();
      try {
        final take = doc.bytes.length < 8 ? doc.bytes.length : 8;
        final head = await raf.read(take);
        return (type: _sniff(String.fromCharCodes(head)), path: tmp.path);
      } finally {
        await raf.close();
      }
    } catch (_) {
      // Offline fallback (flutter test / no temp dir): sniff in-memory bytes.
      return (type: _sniff(doc.bytes), path: null);
    }
  }

  /// Canonicalizes [declaredPath] using real `File(...).absolute` semantics and
  /// collapses `.`/`..`. On a real filesystem `absolute` anchors relative paths
  /// against the CWD; declared absolute paths are normalized lexically.
  static String _canonicalize(String declaredPath) {
    final abs = File(declaredPath).absolute.path;
    final rooted = abs.startsWith('/');
    final segments = <String>[];
    for (final seg in abs.split('/')) {
      if (seg.isEmpty || seg == '.') continue;
      if (seg == '..') {
        if (segments.isNotEmpty) segments.removeLast();
      } else {
        segments.add(seg);
      }
    }
    return '${rooted ? '/' : ''}${segments.join('/')}';
  }

  static bool _within(String canonical, String root) =>
      canonical == root || canonical.startsWith('$root/');

  /// VULN (synchronous deterministic model, used by tests): trust the DECLARED
  /// type/path handed over by the picker. Handling is decided purely from the
  /// declared mime; the declared path is followed even into a privileged
  /// location, so a file lying about its type is parsed/executed per its real
  /// (hostile) content.
  ImportOutcome import(PickedDocument doc) {
    final canonical = _canonicalize(doc.declaredPath);
    final sniffed = _sniff(doc.bytes);
    return ImportOutcome(
      imported: true,
      blocked: false,
      trustedType: doc.declaredMimeType,
      sniffedType: sniffed,
      realPath: canonical,
      executedAsCode: sniffed == 'application/x-executable-script',
      escapedSandbox: !_within(canonical, importSandbox),
    );
  }

  /// SECURE contrast (synchronous): re-validate the real content/type and
  /// confine the canonical path under the import sandbox.
  ImportOutcome importSafe(PickedDocument doc) {
    final canonical = _canonicalize(doc.declaredPath);
    final sniffed = _sniff(doc.bytes);
    if (!_within(canonical, importSandbox)) {
      return ImportOutcome(
        imported: false,
        blocked: true,
        trustedType: null,
        sniffedType: sniffed,
        realPath: canonical,
        executedAsCode: false,
        escapedSandbox: false,
        reason: 'canonical path escapes the import sandbox',
      );
    }
    if (sniffed != doc.declaredMimeType) {
      return ImportOutcome(
        imported: false,
        blocked: true,
        trustedType: sniffed,
        sniffedType: sniffed,
        realPath: canonical,
        executedAsCode: false,
        escapedSandbox: false,
        reason:
            'content type "$sniffed" does not match declared '
            '"${doc.declaredMimeType}"',
      );
    }
    return ImportOutcome(
      imported: true,
      blocked: false,
      trustedType: sniffed,
      sniffedType: sniffed,
      realPath: canonical,
      executedAsCode: false,
      escapedSandbox: false,
      reason: 'content re-validated and confined',
    );
  }

  /// VULN (real): write the picked bytes to a real temp file, re-read the magic
  /// bytes OFF DISK, canonicalize the declared path, then handle the file per
  /// its DECLARED mime and follow the declared path - so a type-confused file
  /// is parsed/executed and a traversal path escapes the sandbox on disk.
  Future<ImportOutcome> importReal(PickedDocument doc) async {
    final sniff = await _sniffOffDisk(doc);
    final canonical = _canonicalize(doc.declaredPath);
    final treatedAsExecutable = sniff.type == 'application/x-executable-script';

    if (sniff.path != null) {
      await DvmaEvidence.record(
        'document_picker_trusted_file_confusion',
        'file',
        'wrote picked bytes to real temp file: ${sniff.path}\n'
            'declaredMime=${doc.declaredMimeType} sniffedOffDisk=${sniff.type} '
            'canonicalPath=$canonical',
      );
    }

    return ImportOutcome(
      imported: true,
      blocked: false,
      trustedType: doc.declaredMimeType,
      sniffedType: sniff.type,
      realPath: canonical,
      executedAsCode: treatedAsExecutable,
      escapedSandbox: !_within(canonical, importSandbox),
      artifactPath: sniff.path,
    );
  }

  /// SECURE contrast (real): re-validate the real on-disk content/type (magic
  /// bytes read back off the temp file) and confine the canonical path under
  /// the import sandbox. Mismatched or escaping documents are refused.
  Future<ImportOutcome> importSafeReal(PickedDocument doc) async {
    final sniff = await _sniffOffDisk(doc);
    final canonical = _canonicalize(doc.declaredPath);

    if (!_within(canonical, importSandbox)) {
      return ImportOutcome(
        imported: false,
        blocked: true,
        trustedType: null,
        sniffedType: sniff.type,
        realPath: canonical,
        executedAsCode: false,
        escapedSandbox: false,
        artifactPath: sniff.path,
        reason: 'canonical path escapes the import sandbox',
      );
    }
    if (sniff.type != doc.declaredMimeType) {
      return ImportOutcome(
        imported: false,
        blocked: true,
        trustedType: sniff.type,
        sniffedType: sniff.type,
        realPath: canonical,
        executedAsCode: false,
        escapedSandbox: false,
        artifactPath: sniff.path,
        reason:
            'on-disk content type "${sniff.type}" does not match declared '
            '"${doc.declaredMimeType}"',
      );
    }
    return ImportOutcome(
      imported: true,
      blocked: false,
      trustedType: sniff.type,
      sniffedType: sniff.type,
      realPath: canonical,
      executedAsCode: false,
      escapedSandbox: false,
      artifactPath: sniff.path,
      reason: 'content re-validated off disk and confined',
    );
  }
}
