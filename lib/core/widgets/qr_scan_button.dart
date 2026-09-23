import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../theme/dvma_colors.dart';

/// Optional live-camera QR scan button for the QR/NFC demo modules.
///
/// DVMA is a white-box harness: the tested, deterministic attack path feeds a
/// crafted payload directly into the vulnerable handler (see each module's
/// text field / "process" button). This button is an *optional* convenience
/// for physical workshops, point the camera at a hostile QR and the decoded
/// string is delivered to [onScanned], which then flows through the exact same
/// vulnerable path. It degrades gracefully on platforms without a camera
/// (web/desktop/CI), where it simply renders nothing.
class QrScanButton extends StatelessWidget {
  const QrScanButton({super.key, required this.onScanned});

  /// Called with the decoded QR content once, when a code is first detected.
  final ValueChanged<String> onScanned;

  /// Camera scanning is only wired up for mobile; elsewhere the paste-decoded
  /// path is the intended (and only) way to drive the demo.
  static bool get _cameraSupported =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  Future<void> _openScanner(BuildContext context) async {
    final decoded = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      builder: (_) => const _QrScanSheet(),
    );
    if (decoded != null && decoded.isNotEmpty) {
      onScanned(decoded);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_cameraSupported) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(top: DvmaSpacing.sm),
      child: SizedBox(
        width: double.infinity,
        child: OutlinedButton.icon(
          icon: const Icon(Icons.qr_code_scanner),
          label: const Text('Scan with camera (optional)'),
          onPressed: () => _openScanner(context),
        ),
      ),
    );
  }
}

/// Modal camera sheet that pops with the first decoded barcode value.
class _QrScanSheet extends StatefulWidget {
  const _QrScanSheet();

  @override
  State<_QrScanSheet> createState() => _QrScanSheetState();
}

class _QrScanSheetState extends State<_QrScanSheet> {
  final _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );
  bool _handled = false;

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    final value = capture.barcodes.firstOrNull?.rawValue;
    if (value == null || value.isEmpty) return;
    _handled = true;
    Navigator.of(context).pop(value);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: SizedBox(
        height: MediaQuery.sizeOf(context).height * 0.6,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(DvmaSpacing.md),
              child: Row(
                children: [
                  const Expanded(
                    child: Text('Point at a QR code to feed the demo'),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
            ),
            Expanded(
              child: MobileScanner(
                controller: _controller,
                onDetect: _onDetect,
                errorBuilder: (context, error) => Center(
                  child: Padding(
                    padding: const EdgeInsets.all(DvmaSpacing.lg),
                    child: Text(
                      'Camera unavailable: ${error.errorCode.name}.\n'
                      'Use the decoded-content field instead.',
                      textAlign: TextAlign.center,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
