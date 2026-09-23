import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'fd_capability_broker.dart';

/// File-Descriptor Capability Leakage.
///
/// The app hands an untrusted caller a live read/write ParcelFileDescriptor for
/// a sensitive DB with no caller check, transferring an already-open capability
/// that bypasses path-based permission checks. The secure path verifies the
/// caller, refuses sensitive resources, and returns only a read-only FD.
class FileDescriptorCapabilityLeakageScreen extends StatefulWidget {
  const FileDescriptorCapabilityLeakageScreen({super.key});

  static const String vulnId = 'file_descriptor_capability_leakage';

  @override
  State<FileDescriptorCapabilityLeakageScreen> createState() =>
      _FileDescriptorCapabilityLeakageScreenState();
}

class _FileDescriptorCapabilityLeakageScreenState
    extends State<FileDescriptorCapabilityLeakageScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _renderVuln(FdBrokerResult r) {
    final b = StringBuffer();
    b.writeln('caller package     : ${r.callerPackage}');
    b.writeln('resource requested : ${r.resourcePath}');
    b.writeln('caller checked     : ${r.callerChecked}');
    b.writeln('fd returned        : ${r.fdReturned}');
    b.writeln('read-only          : ${r.readOnly}');
    b.writeln('sensitive access   : ${r.sensitiveAccessGranted}');
    b.writeln('bytes read via fd  : ${r.bytesRead ?? '(none)'}');
    b.writeln(
      'fd-leak hit        : '
      '${r.fdReturned && !r.callerChecked && r.sensitiveAccessGranted}',
    );
    return b.toString().trimRight();
  }

  String _renderSecure(FdBrokerResult sensitive, FdBrokerResult benign) {
    final b = StringBuffer();
    b.writeln('caller package     : ${sensitive.callerPackage}');
    b.writeln('--- request sensitive DB ---');
    b.writeln('caller checked     : ${sensitive.callerChecked}');
    b.writeln('fd returned        : ${sensitive.fdReturned}');
    if (sensitive.denyReason != null) {
      b.writeln('deny reason        : ${sensitive.denyReason}');
    }
    b.writeln('--- request benign resource (trusted caller) ---');
    b.writeln('caller checked     : ${benign.callerChecked}');
    b.writeln('fd returned        : ${benign.fdReturned}');
    b.writeln('read-only          : ${benign.readOnly}');
    b.writeln('sensitive access   : ${benign.sensitiveAccessGranted}');
    b.writeln('bytes read via fd  : ${benign.bytesRead ?? '(none)'}');
    b.writeln(
      'fd-leak hit        : '
      '${sensitive.fdReturned && sensitive.sensitiveAccessGranted}',
    );
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: an untrusted caller asks for the sensitive DB and gets a live rw FD
    // with no identity check, then reads the secret bytes through it.
    final vulnBroker = FdCapabilityBroker();
    final vuln = vulnBroker.openForCaller(
      FdCapabilityBroker.attackerCallerPackage,
      FdCapabilityBroker.sensitiveDbPath,
    );

    // SECURE: the same untrusted caller is refused the sensitive DB entirely;
    // a trusted caller only ever gets a read-only FD to a benign resource.
    final secureBroker = FdCapabilityBroker();
    final secureSensitive = secureBroker.openForCallerSafe(
      FdCapabilityBroker.attackerCallerPackage,
      FdCapabilityBroker.sensitiveDbPath,
    );
    final secureBenign = secureBroker.openForCallerSafe(
      FdCapabilityBroker.trustedCallerPackage,
      FdCapabilityBroker.benignPath,
    );

    setState(() {
      _vulnResult = _renderVuln(vuln);
      _secureResult = _renderSecure(secureSensitive, secureBenign);
    });
    // On Android, the real exported provider's openFile() hands back a live
    // ParcelFileDescriptor for a resolved app-private file (an FD is a
    // capability that bypasses path-based permission checks). Reading it back
    // through the resolver proves the FD leaked real bytes.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await ProviderIpcBridge.openTraversal('../session.token');
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      FileDescriptorCapabilityLeakageScreen.vulnId,
      'fd-capability',
      'exported provider openFile() returned a live FD to an app-private '
          'file; bytes read through it:\n$native',
    );
    if (!mounted) return;
    setState(() {
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: FileDescriptorCapabilityLeakageScreen.vulnId,
      title: 'File-Descriptor Capability Leakage',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app opens a resource and passes the live ParcelFileDescriptor '
          '(via a Binder transaction, openFile(), or detachFd()) to an '
          'untrusted caller for a file/socket the caller could not otherwise '
          'open. An open FD is a CAPABILITY: once handed over it bypasses '
          'path-based permission checks and the recipient inherits access to '
          'whatever it points at - here a sensitive DB (CWE-402 / CWE-668 / '
          'CWE-200). This is conceptually different from path traversal: an '
          'already-open capability is transferred wholesale. This is an '
          'offline, deterministic simulation. The secure path verifies the '
          'caller, refuses sensitive resources, and returns only a read-only '
          'FD to a narrowly-scoped non-sensitive resource.',
      children: [
        DemoActionButton(
          label: 'Open FD for untrusted caller',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unchecked FD pass: sensitive DB capability leaked',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'caller-checked + read-only: sensitive FD refused',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real openFile() FD to app-private file (bytes read back)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
