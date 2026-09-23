# com.dvma.attacker - DVMA companion attacker app

**FOR AUTHORIZED SECURITY-TRAINING USE ONLY.**

A **separate, standalone Android app** (`com.dvma.attacker`) - its own package,
UID, and signing key, distinct from DVMA. It exists to exercise DVMA's
**cross-app vulnerabilities**: attacks whose entire premise is a *second
co-resident app* crossing an Android process/trust boundary cannot be
demonstrated inside DVMA alone (one app cannot attack itself across an IPC
boundary). This is the "malicious co-resident app" DVMA's docs reference.

It is deliberately minimal and **requests no special permissions** (only the
foreground-service/notification permissions it needs to stay resident). That is
the whole point: it shows what an *arbitrary* installed app can harvest from a
vulnerable DVMA.

> **This is not an agent.** It's a deterministic IPC peer/fixture - no LLM, no
> autonomy, no decision loop. It does exactly one thing when driven: harvest
> what a vulnerable DVMA leaks across the boundary.

## What it implements today

| DVMA module(s) | Attack primitive here |
| --- | --- |
| `cross_app_otp_credential_leak` | `OtpLeakReceiver` + `OtpHarvestService` harvest the OTP + auth deep link DVMA broadcasts unprotected. |
| `exported_broadcast_receiver_spoof`, `dynamic_broadcast_receiver_exposure` | `BroadcastForger` sends spoofed/forged broadcasts to DVMA's exported receivers (`--es send location`/`promo`). |
| `implicit_intent_sensitive_data`, `ordered_broadcast_result_injection`, `default_role_holder_confusion` | `BroadcastHarvestReceiver` receives/reorders broadcasts DVMA emits. |
| 8 exported-Activity modules (`exported_android_components`, `exported_component_arbitrary_url_activity`, `exported_component_state_manipulation`, `confused_deputy_intent_validation`, `intent_redirection`, `intent_arg_injection_rce`, `activity_alias_exposure`, `cross_app_scripting`) | `ComponentInvoker` starts DVMA's exported Activities by component name (`--es start <kind>`). |
| `privileged_service_binding_exposure` | `ServiceBinderClient` binds DVMA's exported Messenger service and harvests the privileged reply (`--es bind service`). |
| `activity_task_stack_hijacking` | `HijackActivity` declares DVMA's `taskAffinity` + `allowTaskReparenting` and reparents into DVMA's task (`--es start hijack`). |

---

## How the OTP-leak vertical works

```text
 DVMA (victim, com.dvma)        com.dvma.attacker (attacker)
 ─────────────────────────────────────        ────────────────────────────
 Cross-App OTP screen (Dart)
   │ tap "Broadcast OTP (unprotected)"
   ▼
 otp_broadcast_bridge.dart  ──MethodChannel──▶ MainActivity.kt
                                                 context.sendBroadcast(
                                                   action OTP_ISSUED, extras)   ─┐
                                                 (implicit, NO permission)        │
                                                                                  ▼
                                              OtpHarvestService (foreground)
                                                └─ OtpLeakReceiver.onReceive()
                                                     • Log.w("DVMA-ATTACKER", …)
                                                     • append attacker_captures.txt

 tap "Broadcast OTP (permission-scoped)"
   ▼  sendBroadcast(…, RECEIVE_OTP)   ── Android drops delivery: the attacker is
                                          not signed with DVMA's key, so it can't
                                          hold the signature-level permission.
```

### Why a foreground service (and what you must do)

Android 8+ does **not** deliver *implicit* broadcasts to most manifest-declared
receivers. A real co-resident attacker therefore keeps a **runtime-registered**
receiver alive via a **foreground service**. `OtpHarvestService` does exactly
that, so the attacker keeps harvesting **even while DVMA (not this app) is in the
foreground**.

Practically this means the only manual step is: **launch the DVMA Attacker app
once.** Its `AttackerActivity.onCreate` starts the service; you can then switch
to DVMA and it keeps harvesting in the background. You do **not** need to keep
the attacker on screen.

> **OEM battery managers:** aggressive power management on some non-Pixel devices
> can eventually kill foreground services. If harvesting stops after a while,
> exempt "DVMA Attacker" from battery optimization (Settings ▸ Apps ▸ DVMA
> Attacker ▸ Battery ▸ Unrestricted). On a Pixel the defaults are fine.

---

## Run it - three ways

Install DVMA first, then this app. All commands are run from the repo root.

### 1) One-command narrated demo (recommended)

Does everything - builds + installs both apps, starts the attacker service,
drives DVMA to the module by its stable Semantics ids (no screen coordinates),
fires both broadcasts, and prints the evidence:

```sh
automation/scripts/demo.sh otp
# already built the two APKs? skip the builds:
SKIP_BUILD=1 automation/scripts/demo.sh otp
```

Expected tail:

```text
▶ VULN: tapping 'Broadcast OTP (unprotected)' - DVMA fires a broadcast
  ✓ attacker HARVESTED the secret across the process boundary:
    HARVESTED cross-app OTP: otp=538056 link=myauth://login?otp=538056&token=…
▶ FIX: tapping 'Broadcast OTP (permission-scoped)' - signature permission gate
  ✓ attacker received NOTHING - Android dropped the delivery
```

### 2) CI-grade regression test (pass/fail)

A UiAutomator instrumentation test drives DVMA, launches this app, and
**asserts** it harvested the OTP (and that the secure path blocks it). It is
opt-in (same flag as the walk-all suite) and **skips** cleanly if this app isn't
installed:

```sh
# build + install both apps first (or run the demo script once), then:
cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true \
  -Pandroid.testInstrumentationRunnerArguments.class=\
com.dvma.DvmaCrossAppOtpLeakTest
```

### 3) Fully manual (see it yourself)

```sh
# build + install
cd companion/dvma-attacker && ./gradlew :app:assembleDebug && cd ../..
adb install -r companion/dvma-attacker/app/build/outputs/apk/debug/app-debug.apk

# start the attacker once (starts the harvest service), then watch its logcat:
adb shell am start -n com.dvma.attacker/.AttackerActivity
adb logcat -s DVMA-ATTACKER:*
```

Now open DVMA ▸ **Cross-App OTP / Credential Leak** and tap the two buttons:

- **Broadcast OTP (unprotected)** → a `DVMA-ATTACKER: HARVESTED …` line appears.
- **Broadcast OTP (permission-scoped)** → nothing (the fix).

The harvest is also written to a pullable file:

```sh
adb shell cat /sdcard/Android/data/com.dvma.attacker/files/attacker_captures.txt
```

The multi-module capture harness folds this into its report when run with
`ATTACKER=1` (see [`automation/README.md`](../../automation/README.md)):

```sh
ATTACKER=1 automation/scripts/capture_run.sh
```

---

## Exported-component modules

DVMA declares Activities/a Service/an alias `exported` with no caller check.
This app reaches them **by explicit component name** from its own UID - a real
cross-process start/bind. DVMA records the effect in `EvidenceStore`; the Dart
side reads it back over the `dvma/component_ipc` channel, and it is also logged
under `DVMA-EVIDENCE`.

### Trigger map

`AttackerActivity` reads an extra and drives the matching primitive:

| Extra | Primitive | DVMA component reached |
| --- | --- | --- |
| `--es start admin` | `ComponentInvoker.startActivity` | `AdminActivity` |
| `--es start url` | `ComponentInvoker.startActivity` | `UrlDispatchActivity` |
| `--es start state` | `ComponentInvoker.startActivity` | `StateControlActivity` |
| `--es start deputy` | `ComponentInvoker.startActivity` | `DeputyActivity` |
| `--es start redirect` | `ComponentInvoker.startWithForward` | `ProxyActivity` → `InternalAdminActivity` |
| `--es start arg` | `ComponentInvoker.startActivity` | `LauncherActivity` |
| `--es start alias` | `ComponentInvoker.startActivity` | `AdminAlias` → `ProtectedAdminActivity` |
| `--es start xss` | `ComponentInvoker.startActivity` | `WebViewActivity` |
| `--es bind service` | `ServiceBinderClient.bindAndHarvest` | `PrivilegedService` (Messenger bind) |
| `--es start hijack` | `ComponentInvoker.startActivity` + own `HijackActivity` | `HijackTargetActivity` (+ reparent) |

### Device-behavior requirement (freshness)

The extra must be handled in a fresh `onCreate` while the attacker is the
resumed app. Otherwise `am start` reports *"delivered to the top-most
instance"*, the extra routes to `onNewIntent` on a non-foreground instance, and
Android's background-activity-launch (BAL) limits drop the exported-component
start.

Two consequences the demo script handles:

1. **Force-stop both apps** before each trigger. Stopping only the attacker
   leaves DVMA's `NoDisplay`/`WebView` activities - which the attacker launched
   into its own task via `startActivityForResult` - reparented in that task,
   poisoning the next fresh start.
2. **`activity_task_stack_hijacking` is a race** between DVMA's target Activity
   and the attacker's reparented one. The reliable proof is the task placement
   in `dumpsys activity activities` (attacker activity in a task whose affinity
   is `com.dvma`), not the `DVMA-EVIDENCE` line.

### Run it

```sh
automation/scripts/demo.sh components
# reuse already-built APKs:
SKIP_BUILD=1 automation/scripts/demo.sh components
# pick a device when more than one is attached:
SERIAL=<serial> automation/scripts/demo.sh components
```

`adb` is auto-located (PATH, then `$ANDROID_HOME`/`$ANDROID_SDK_ROOT`, then the
default SDK path); override with `ADB=/path/to/adb`.

Expected tail:

```text
▶ privileged_service_binding_exposure - attacker binds DVMA's exported service (--es bind service)
  ✓ privileged_service_binding_exposure (DVMA served): …
    readSecret served to bound client: svc-secret://session-key=…
  ✓ privileged_service_binding_exposure (attacker harvested): …
    HARVESTED service secret: svc-secret://session-key=…
▶ activity_task_stack_hijacking - attacker reparents into DVMA's task (--es start hijack)
  ✓ activity_task_stack_hijacking (attacker launched): …
  ✓ activity_task_stack_hijacking (task placement): attacker activity reparented into a task with DVMA's affinity
▶ All exported-component modules verified across the process boundary.
```

### Manual trigger (one module)

```sh
adb shell am force-stop com.dvma
adb shell am force-stop com.dvma.attacker
adb shell input keyevent KEYCODE_HOME
adb shell am start -n com.dvma.attacker/.AttackerActivity --es start admin
adb logcat -d DVMA-EVIDENCE:W DVMA-ATTACKER:W '*:S'
```

---

## Build & install (standalone)

Isolated Gradle project (own wrapper), so it never touches DVMA's Flutter build:

```sh
cd companion/dvma-attacker
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Source layout

```text
app/src/main/
├── AndroidManifest.xml            # activity + foreground service + manifest receiver; no dangerous perms
└── kotlin/com/dvma/attacker/
    ├── AttackerActivity.kt         # starts OtpHarvestService; reads --es send/start/bind; shows latest capture
    ├── OtpHarvestService.kt        # foreground service; keeps the runtime receivers alive
    ├── OtpLeakReceiver.kt          # OTP broadcast → logcat (DVMA-ATTACKER) + capture file
    ├── BroadcastHarvestReceiver.kt # broadcast-IPC modules: harvest/reorder DVMA's broadcasts
    ├── BroadcastForger.kt          # sends spoofed/forged broadcasts to DVMA's exported receivers
    ├── ComponentInvoker.kt         # starts DVMA's exported Activities by component name (+ nested forward intent)
    ├── ServiceBinderClient.kt      # binds DVMA's exported Messenger service, harvests the privileged reply
    ├── HijackActivity.kt           # reparents into DVMA's task (taskAffinity + allowTaskReparenting)
    ├── Dvma.kt                     # DVMA package + derived action/permission/component names (synced from config/app.json)
    └── AttackerCapture.kt          # in-memory latest + adb-pullable capture file
```
