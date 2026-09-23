import 'package:flutter/services.dart';

/// Prefix used when a native call raises a [PlatformException]; the error text
/// is surfaced through the same String channel as a real finding so a module
/// can display it. Callers that need to distinguish an error from a legitimate
/// finding can test for this prefix.
const String nativeErrorPrefix = 'native error: ';

/// Shared body for every DVMA native bridge's `invokeMethod<String>` call.
///
/// Each bridge (see the sibling `*_bridge.dart` files) wraps a single
/// [MethodChannel] and exposes typed methods that all funnel through here, so
/// the availability guard and error handling stay identical across bridges:
/// returns null when [available] is false or the plugin is missing (off-Android
/// / iOS / under `flutter test`), and a `${nativeErrorPrefix}…` string when the
/// native side throws.
Future<String?> invokeNativeString(
  MethodChannel channel,
  bool available,
  String method, [
  Map<String, Object?>? args,
]) async {
  if (!available) return null;
  try {
    return await channel.invokeMethod<String>(method, args);
  } on MissingPluginException {
    return null;
  } on PlatformException catch (e) {
    return '$nativeErrorPrefix${e.message}';
  }
}
