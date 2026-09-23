import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'share_extension_handler.dart';

/// App Extension Activation != Input Authorization.
///
/// An extension acts on a crafted NSItemProvider payload simply because the
/// system activated it, driving a privileged import/open. The secure path
/// validates type + content before acting.
class ExtensionActivationInputConfusionScreen extends StatefulWidget {
  const ExtensionActivationInputConfusionScreen({super.key});

  static const String vulnId = 'extension_activation_input_confusion';

  @override
  State<ExtensionActivationInputConfusionScreen> createState() =>
      _ExtensionActivationInputConfusionScreenState();
}

class _ExtensionActivationInputConfusionScreenState
    extends State<ExtensionActivationInputConfusionScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(ExtensionActionResult r) {
    final b = StringBuffer();
    b.writeln('payload type   : ${r.payload.type.name}');
    b.writeln('payload value  : ${r.payload.value}');
    b.writeln('performed      : ${r.performed}');
    b.writeln('action         : ${r.action}');
    b.writeln('input validated: ${r.inputValidated}');
    b.writeln('unsafe op       : ${r.unsafe}');
    if (r.importedPath != null) {
      b.writeln('imported path  : ${r.importedPath}');
    }
    if (r.denyReason != null) {
      b.writeln('deny reason    : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final handler = ShareExtensionHandler();

    // VULN: a crafted file:// traversal payload is imported on activation
    // alone, writing outside the import root on the real filesystem.
    final vuln = await handler.handle(
      ShareExtensionHandler.maliciousFilePayload,
    );

    // SECURE: the same crafted payload is canonicalized and refused.
    final secure = await handler.handleSafe(
      ShareExtensionHandler.maliciousFilePayload,
    );

    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ExtensionActivationInputConfusionScreen.vulnId,
      title: 'App Extension Activation != Input Authorization',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An iOS app extension (Share / Action / File Provider) is handed an '
          'NSItemProvider item when the system activates it. Activation rules '
          'decide WHEN the extension is offered - not WHETHER the file/URL/text '
          'it received is safe. Here a crafted file:// URL using ../ traversal '
          '(or a javascript: URL) drives a privileged import/open because the '
          'extension mistakes "we were activated" for "the input is '
          'authorized". On device the vulnerable import writes the payload '
          'outside its import root on the real filesystem. The secure path '
          'validates type and content (canonicalize path, allowlist schemes, '
          'reject traversal) before acting, refusing the crafted payload.',
      children: [
        DemoActionButton(
          label: 'Handle crafted share payload',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'acted on payload from activation alone',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure: validated + refused crafted payload',
            value: _secureResult!,
          ),
      ],
    );
  }
}
