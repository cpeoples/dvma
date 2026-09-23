The Flutter and Kotlin halves ship in the **same APK** and communicate over
Flutter [`MethodChannel`](https://docs.flutter.dev/platform-integration/platform-channels)s.
Every native cluster follows the same symmetric pattern.

## 1. Registration

`MainActivity.configureFlutterEngine` registers each native bridge on the shared
`FlutterEngine`:

- `BroadcastIpc`, the broadcast-IPC modules (`dvma/broadcast_ipc`)
- `ComponentIpc`, exported Activity / Service modules (`dvma/component_ipc`)
- `ProviderIpc`, ContentProvider modules (`dvma/provider_ipc`)
- `PlatformIpc`, PendingIntent / notification / overlay / widget / dynamic-code / accessibility (`dvma/platform_ipc`)
- `ResilienceProbe`, root/tamper/debugger probes (`dvma/resilience`)
- `SystemProviderProbe`, enablable system-provider surfaces, incl. the real IME (`dvma/system_provider`)
- an OTP broadcast channel (`dvma/otp_broadcast`) used by the cross-app OTP leak

## 2. A typed Dart bridge per channel

e.g. `PlatformIpcBridge` (`lib/core/native/platform_ipc_bridge.dart`) is the
client for `PlatformIpc.kt`. A module screen calls something like
`PlatformIpcBridge.postMutablePendingIntent()`.

## 3. The native op performs a real Android operation

It does not fake the effect, it posts an actual `Notification` carrying a
`FLAG_MUTABLE` + implicit `PendingIntent`, runs a real `DexClassLoader` over an
app-writable file, reads `Settings.canDrawOverlays`, sends a real broadcast, and
so on. Each of these is observable off-device (e.g.
`adb shell dumpsys notification`, or logcat under the `DVMA-EVIDENCE` tag).

## 4. Read-back via the native `EvidenceStore`

The native side records the effect into `EvidenceStore`, keyed by the module's
vuln id, and Dart reads it back with `applied(<id>)`. That recorded string is
what renders in the on-device **evidence panel**, so a populated panel is
on-device proof the vulnerable code path actually ran.

## 5. Graceful fallback off-Android

Every bridge is Android-only (`isAvailable => Platform.isAndroid`). On
iOS/desktop and under `flutter test`, calls return `null` and the screen falls
back to its in-memory model, so the demos and the test suite still work without
a device.

```text
   [Flutter module screen]  (lib/, Dart)
            │  MethodChannel call (e.g. postMutablePendingIntent)
            ▼
   [Native bridge]  PlatformIpc / BroadcastIpc / ComponentIpc / ProviderIpc / …  (Kotlin, same com.dvma APK)
            │  performs a real Android op (Notification, PendingIntent, DexClassLoader, broadcast, provider, …)
            │  → records into EvidenceStore  +  logs under the DVMA-EVIDENCE tag
            │
            ├──────────────► crosses the process boundary ─────────► [com.dvma.attacker]
            │                (implicit broadcast / exported component)   harvests → DVMA-ATTACKER log + capture file
            ▼
   Dart reads it back via applied(<id>) → renders the on-device Evidence Panel
            │
            ▼
   verify_all_modules.sh asserts the evidence panel is present  (on-device proof)
```
