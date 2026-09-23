/// JS Bridge Callback-ID Injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-441 / CWE-20): a Cordova-style
/// native bridge lets each JS plugin register a native callback keyed by a
/// caller-supplied `callbackId`. When a plugin later resolves, the native side
/// dispatches the result to whatever `callbackId` the web message names, WITHOUT
/// verifying that the id actually belongs to the requesting plugin/origin. So
/// web content (or a low-privilege plugin) forges the id of another, PRIVILEGED
/// plugin's callback - Camera/Contacts/Files/Geolocation - and receives that
/// plugin's native result (photos, contacts, location) into its own JS handler.
/// This is the Cordova InAppBrowser iOS CVE-2026-47430 class.
///
/// The screen drives this over a real WebView `NativeBridge` JavaScript channel:
/// the page (running as the unprivileged Console plugin) posts a forged Camera
/// `callbackId` across the JS↔native boundary, the native side runs [dispatch]
/// with no ownership check and delivers the Camera result back into the page via
/// `runJavaScript`, and the page beacons it back over a `Received` channel -
/// genuine cross-plugin injection executing in a real WebView. [CallbackBridge]
/// models the per-plugin Cordova dispatch table and is also kept as a
/// deterministic in-memory fallback so `flutter test` (and platforms without a
/// WebView) stay offline. Tests assert that on the vuln path a forged id
/// belonging to the privileged Camera plugin is honored (the sensitive result
/// is delivered to the attacker's handler), and that on the secure path the
/// bridge validates the callbackId's shape AND ownership so the forged id is
/// rejected.
library;

/// A native callback the bridge is holding for a plugin, keyed by [callbackId].
class RegisteredCallback {
  const RegisteredCallback({
    required this.callbackId,
    required this.pluginId,
    required this.privileged,
  });

  /// The caller-supplied id the plugin used when it invoked the bridge.
  final String callbackId;

  /// The plugin that owns this callback (e.g. `Camera`, `Console`).
  final String pluginId;

  /// Whether resolving this callback exposes a privileged native capability.
  final bool privileged;
}

/// The outcome of a native dispatch to a (possibly forged) callbackId.
class DispatchResult {
  const DispatchResult({
    required this.delivered,
    required this.blocked,
    this.deliveredToPlugin,
    this.payload,
    this.blockReason,
  });

  /// Whether the native result was handed to a JS callback.
  final bool delivered;

  /// Whether the bridge refused the dispatch (secure path).
  final bool blocked;

  /// The plugin whose handler actually received the payload.
  final String? deliveredToPlugin;

  /// The sensitive native result that was delivered.
  final String? payload;

  /// Why the dispatch was refused (secure path only).
  final String? blockReason;

  /// True when a privileged plugin's result was delivered to a DIFFERENT
  /// (attacker-controlled) plugin than the one that owns the callback id -
  /// i.e. the actual callback-id injection hit.
  bool crossPluginLeak(RegisteredCallback owner, String requestingPlugin) =>
      delivered && owner.privileged && requestingPlugin != owner.pluginId;
}

/// A minimal, in-memory model of a Cordova-style bridge callback registry.
class CallbackBridge {
  CallbackBridge(this._callbacks);

  final Map<String, RegisteredCallback> _callbacks;

  /// The privileged Camera plugin's outstanding callback id.
  static const String cameraCallbackId = 'Camera1234567890';

  /// The unprivileged Console plugin's outstanding callback id.
  static const String consoleCallbackId = 'Console987654321';

  /// The sensitive native result the privileged plugin would return.
  static const String cameraResult =
      '{"uri":"file:///var/mobile/DCIM/IMG_0042.jpg","bytes":"<base64...>"}';

  /// A realistic registry: a privileged Camera plugin and an unprivileged
  /// Console plugin each hold an outstanding native callback.
  factory CallbackBridge.withPlugins() {
    return CallbackBridge({
      cameraCallbackId: const RegisteredCallback(
        callbackId: cameraCallbackId,
        pluginId: 'Camera',
        privileged: true,
      ),
      consoleCallbackId: const RegisteredCallback(
        callbackId: consoleCallbackId,
        pluginId: 'Console',
        privileged: false,
      ),
    });
  }

  RegisteredCallback? callback(String id) => _callbacks[id];

  /// VULN: the native side is told "resolve callbackId X with result Y" by a
  /// web message and dispatches to whatever id is named - no check that the
  /// [requestingPlugin] actually owns [callbackId]. The unprivileged Console
  /// plugin (attacker-controlled JS) forges the Camera plugin's id and receives
  /// the Camera result into its own handler.
  DispatchResult dispatch({
    required String callbackId,
    required String requestingPlugin,
    required String payload,
  }) {
    final cb = _callbacks[callbackId];
    if (cb == null) {
      return const DispatchResult(
        delivered: false,
        blocked: false,
        blockReason: 'no such callbackId',
      );
    }
    // The result is delivered to the REQUESTING plugin's handler, regardless of
    // which plugin owns the callback.
    return DispatchResult(
      delivered: true,
      blocked: false,
      deliveredToPlugin: requestingPlugin,
      payload: payload,
    );
  }

  /// SECURE contrast: before dispatching, validate the callbackId's SHAPE with
  /// a strict regex (Cordova InAppBrowser 6.0.1 fix) AND verify the id is one
  /// this plugin registered. A forged id owned by another plugin is refused, so
  /// the privileged result never crosses into the attacker's handler.
  DispatchResult dispatchSafe({
    required String callbackId,
    required String requestingPlugin,
    required String payload,
  }) {
    if (!_validCallbackId(callbackId)) {
      return const DispatchResult(
        delivered: false,
        blocked: true,
        blockReason: 'callbackId failed format validation',
      );
    }
    final cb = _callbacks[callbackId];
    if (cb == null) {
      return const DispatchResult(
        delivered: false,
        blocked: true,
        blockReason: 'no such callbackId',
      );
    }
    if (cb.pluginId != requestingPlugin) {
      return DispatchResult(
        delivered: false,
        blocked: true,
        blockReason:
            'callbackId owned by ${cb.pluginId}, not requesting plugin '
            '$requestingPlugin',
      );
    }
    return DispatchResult(
      delivered: true,
      blocked: false,
      deliveredToPlugin: requestingPlugin,
      payload: payload,
    );
  }

  /// The strict callback-id format the fixed bridge enforces: an alphanumeric
  /// token of a bounded length. (Cordova's fix rejects anything else before it
  /// ever reaches the dispatch table.)
  static final RegExp _callbackIdPattern = RegExp(r'^[A-Za-z0-9]{8,32}$');

  static bool _validCallbackId(String id) => _callbackIdPattern.hasMatch(id);
}
