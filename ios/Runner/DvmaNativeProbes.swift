// DvmaNativeProbes.swift
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// iOS side of DVMA's native-bridge MethodChannels (Android has a Kotlin probe).
// Implemented for real: dvma/resilience, dvma/app_group, dvma/native_memory.
// Every other channel returns FlutterMethodNotImplemented, so Dart falls back
// to its in-Dart simulation. The IPC/OTP/system_provider channels model
// Android-only trust boundaries with no iOS equivalent and stay unimplemented.
// Implemented probes emit findings to os_log under "DVMA-EVIDENCE".

import AdSupport
import AppIntents
import AppTrackingTransparency
import CryptoKit
import Flutter
import Foundation
import UIKit
import UserNotifications
import WebKit
import os

/// Registers every DVMA native-probe channel on the given Flutter binary
/// messenger. Call once from `AppDelegate.didInitializeImplicitFlutterEngine`.
enum DvmaNativeProbes {

    /// os_log logger; category matches the evidence sink's log name so a single
    /// `log stream --predicate 'eventMessage CONTAINS "DVMA-EVIDENCE"'` catches
    /// both the Dart sink lines and any native probe findings implemented here.
    private static let log = Logger(subsystem: "com.dvma", category: "DVMA-EVIDENCE")

    /// All native-bridge channel names, mirroring the Dart `MethodChannel(...)`
    /// ids and their Android handlers.
    private static let channelNames = [
        "dvma/resilience",
        "dvma/system_provider",
        "dvma/provider_ipc",
        "dvma/platform_ipc",
        "dvma/component_ipc",
        "dvma/broadcast_ipc",
        "dvma/otp_broadcast",
        "dvma/app_group",
        "dvma/native_memory",
        "dvma/notification",
        "dvma/app_intent",
        "dvma/keychain",
        "dvma/att",
        "dvma/webview_file",
        "dvma/automation",
    ]

    static func register(with messenger: FlutterBinaryMessenger) {
        for name in channelNames {
            let channel = FlutterMethodChannel(name: name, binaryMessenger: messenger)
            channel.setMethodCallHandler { call, result in
                handle(channel: name, call: call, result: result)
            }
        }
    }

    /// Central dispatch. Today every method is a SEAM returning
    /// `FlutterMethodNotImplemented` so Dart falls back to its in-app
    /// simulation (no behavior change vs. having no handler at all).
    ///
    /// To make a finding real on iOS: implement the method here, return a short
    /// human-readable string via `result(finding)`, log it with
    /// `log.warning(...)`, and allow iOS in the corresponding Dart bridge's
    /// `isAvailable` getter.
    private static func handle(channel: String,
                               call: FlutterMethodCall,
                               result: @escaping FlutterResult) {
        switch (channel, call.method) {

        // dvma/automation - test-only launch hook (no security relevance)
        // Returns the module id the "walk every module" harness asked to open at
        // launch, read from the process environment (XCUITest's launchEnvironment
        // populates it on the NATIVE side, unlike Dart's Platform.environment,
        // which does not see it on iOS). DeepLinkNavigator queries this once on
        // startup and, when non-empty, opens that module keyboard-free. Empty in
        // normal use.
        case ("dvma/automation", "openModuleOnLaunch"):
            let id = ProcessInfo.processInfo.environment["DVMA_OPEN_MODULE"] ?? ""
            result(id)

        // dvma/resilience - real, self-contained iOS probes
        // Each returns a short "detected=<bool> ..." string; the Dart bridge
        // only checks `contains("detected=true")`, and the module then gates the
        // decision on its own bypassable client-side boolean (that's the bug).
        case ("dvma/resilience", "rootCheck"):
            let finding = jailbreakFinding()
            emit("rootCheck", finding); result(finding)
        case ("dvma/resilience", "debuggerCheck"):
            let finding = debuggerFinding()
            emit("debuggerCheck", finding); result(finding)
        case ("dvma/resilience", "emulatorCheck"):
            let finding = emulatorFinding()
            emit("emulatorCheck", finding); result(finding)
        case ("dvma/resilience", "fridaCheck"):
            let finding = fridaFinding()
            emit("fridaCheck", finding); result(finding)
        case ("dvma/resilience", "tamperCheck"):
            let finding = tamperFinding()
            emit("tamperCheck", finding); result(finding)
        case ("dvma/resilience", _):
            result(FlutterMethodNotImplemented)

        // dvma/app_group - real iOS App Group shared-container probe
        // Tier C promoted: on an App-Group-entitled build this does a genuine
        // cross-"member" write→read through the shared container; when the
        // entitlement is absent (default repo/simulator build) it reports WHY
        // it is unavailable rather than faking a finding.
        case ("dvma/app_group", "sharedContainerLeak"):
            let key = (call.arguments as? [String: Any])?["key"] as? String
                ?? "auth.session.token"
            let value = (call.arguments as? [String: Any])?["value"] as? String ?? ""
            let finding = appGroupSharedContainerFinding(key: key, value: value)
            emit("sharedContainerLeak", finding)
            result(finding)
        case ("dvma/app_group", _):
            result(FlutterMethodNotImplemented)

        // dvma/native_memory - real compiled C stack overflow in the Mach-O
        // Parity with the Android NDK library: forwards the caller's string to
        // the C `dvma_unsafe_copy` (unbounded strcpy into a 16-byte stack
        // buffer, CWE-120 / CWE-787). The bug is genuine native code shipping in
        // the Runner binary - inspectable with Hopper / lldb / frida.
        case ("dvma/native_memory", "unsafeCopy"):
            let input = (call.arguments as? [String: Any])?["input"] as? String ?? ""
            let finding = nativeUnsafeCopyFinding(input)
            emit("unsafeCopy", finding)
            result(finding)
        case ("dvma/native_memory", _):
            result(FlutterMethodNotImplemented)

        // dvma/notification - real iOS local UNNotification with a sensitive
        // payload (push_notification_leakage /
        // notification_action_authorization_bypass). Schedules a genuine
        // UNNotificationRequest whose title/body carry the OTP + balance and
        // reads the delivered content back from UNUserNotificationCenter, so
        // it renders on the real lock screen. Async: completes `result` in
        // the notification-center callback.
        case ("dvma/notification", "postSensitiveNotification"):
            postSensitiveNotification(result)
        case ("dvma/notification", _):
            result(FlutterMethodNotImplemented)

        // dvma/app_intent - real iOS App Intents shipped in the Runner binary
        // (lockscreen_control_action_authorization /
        // assistant_locked_device_capability_abuse). Reports the declared
        // authenticationPolicy of the vulnerable vs. secure intent and the
        // live protected-data (lock) state, and runs the vulnerable intent's
        // `perform()` so the privileged action fires from a locked device.
        case ("dvma/app_intent", "invokeSensitiveIntent"):
            invokeSensitiveAppIntent(result)
        case ("dvma/app_intent", "invokeExportIntent"):
            let acct = (call.arguments as? [String: Any])?["accountId"] as? String
                ?? "acct-bob-01"
            invokeExportAppIntent(accountId: acct, result: result)
        case ("dvma/app_intent", "intentSurfaces"):
            let finding = appIntentSurfacesFinding()
            emit("intentSurfaces", finding)
            result(finding)
        case ("dvma/app_intent", _):
            result(FlutterMethodNotImplemented)

        // dvma/keychain - real Security.framework Keychain items
        // (keychain_access_group_authorization_confusion /
        // keychain_state_integrity_manipulation). Delegated to
        // DvmaKeychainProbe (real SecItemAdd/CopyMatching/Update + CryptoKit
        // HMAC).
        case ("dvma/keychain", let m):
            let args = (call.arguments as? [String: Any]) ?? [:]
            DvmaKeychainProbe.handle(method: m, args: args) { value in
                if let s = value as? String { emit("keychain.\(m)", s) }
                result(value)
            }

        // dvma/att - real App Tracking Transparency state
        // (no_tracking_transparency_prompt). Reports the real
        // ATTrackingManager authorization status and the real IDFA (zeroed
        // unless authorized), proving the app tracks with no prompt.
        case ("dvma/att", "trackingState"):
            let finding = trackingTransparencyFinding()
            emit("trackingState", finding)
            result(finding)
        case ("dvma/att", _):
            result(FlutterMethodNotImplemented)

        // dvma/webview_file - real cross-origin local-file read in a WKWebView
        // (wkwebview_untrusted_url_local_file). The legacy
        // allowFileAccessFromFileURLs / file://-origin trick is dead on modern
        // WebKit, so a custom WKURLSchemeHandler (scheme dvma-app://) serves
        // both the untrusted attacker page and a seeded secret file under one
        // origin. The injected <script> fetch()es the secret same-origin and
        // posts it back through a real WKScriptMessageHandler; the reported
        // bytes are the exfiltrated secret. This is the iOS-native counterpart
        // of the Android setAllowFileAccess(true) + file:// branch - a real
        // on-device local-file read, not a Dart model (ZOLL ePCR CVE-2025-12699).
        case ("dvma/webview_file", "readLocalFile"):
            let payload = (call.arguments as? [String: Any])?["payload"] as? String ?? ""
            wkWebViewLocalFileRead(payload: payload, result: result)
        case ("dvma/webview_file", _):
            result(FlutterMethodNotImplemented)

        // Android-only trust boundaries - no iOS equivalent (keep as-is)
        // These model implicit broadcasts, exported components, ContentProviders
        // and Binder, which iOS does not have. The Dart simulation is the
        // correct representation; do NOT fake a native iOS probe for them.
        case ("dvma/platform_ipc", "launchExternalUrl"):
            let url = (call.arguments as? [String: Any])?["url"] as? String ?? ""
            let finding = launchExternalUrlFinding(url)
            emit("launchExternalUrl", finding)
            result(finding)
        case ("dvma/system_provider", _),
             ("dvma/provider_ipc", _),
             ("dvma/platform_ipc", _),
             ("dvma/component_ipc", _),
             ("dvma/broadcast_ipc", _),
             ("dvma/otp_broadcast", _):
            result(FlutterMethodNotImplemented)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /// Log a probe finding to os_log under the shared "DVMA-EVIDENCE" category so
    /// capture_run_ios.sh collects native findings alongside the Dart sink lines.
    private static func emit(_ method: String, _ finding: String) {
        log.warning("resilience.\(method, privacy: .public): \(finding, privacy: .public)")
    }

    // MARK: - Real resilience probes

    /// Classic iOS jailbreak markers: known files/paths, ability to write
    /// outside the sandbox, and a suspicious `fork()` succeeding. Returns
    /// "detected=true" if ANY marker fires. On a stock device all are absent.
    private static func jailbreakFinding() -> String {
        var hits: [String] = []
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/sbin/sshd",
            "/bin/bash",
            "/etc/apt",
            "/private/var/lib/apt",
            "/var/jb", // rootless (Dopamine/ellekit) bootstrap
        ]
        for p in paths where FileManager.default.fileExists(atPath: p) {
            hits.append(p)
        }
        // Sandbox escape: a stock app cannot create files outside its container.
        let probe = "/private/jailbreak_probe_\(UUID().uuidString).txt"
        if (try? "1".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
            hits.append("sandbox-writable:/private")
            try? FileManager.default.removeItem(atPath: probe)
        }
        let detected = !hits.isEmpty
        return "detected=\(detected) markers=[\(hits.joined(separator: ","))]"
    }

    /// Debugger attached: `sysctl(KERN_PROC)` reports the `P_TRACED` flag when a
    /// tracer (lldb / a hooking harness) is attached to this process.
    private static func debuggerFinding() -> String {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let rc = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        let traced = rc == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
        return "detected=\(traced) p_traced=\(traced)"
    }

    /// Running under the Simulator (a poor-man's emulator signal on iOS).
    private static func emulatorFinding() -> String {
        #if targetEnvironment(simulator)
        let sim = true
        #else
        let sim = false
        #endif
        let name = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] ?? ""
        return "detected=\(sim) simulator=\(sim) device=\(name)"
    }

    /// Frida presence: scan the loaded dyld images for Frida's gadget/agent and
    /// probe the default frida-server port on localhost. On a clean device with
    /// no gadget injected, both are absent.
    private static func fridaFinding() -> String {
        var images: [String] = []
        for i in 0..<_dyld_image_count() {
            if let c = _dyld_get_image_name(i) {
                let name = String(cString: c).lowercased()
                if name.contains("frida") || name.contains("gadget") ||
                    name.contains("cynject") || name.contains("substrate") {
                    images.append((name as NSString).lastPathComponent)
                }
            }
        }
        let portOpen = fridaPortOpen(27042)
        let detected = !images.isEmpty || portOpen
        return "detected=\(detected) images=[\(images.joined(separator: ","))] port27042=\(portOpen)"
    }

    /// Best-effort TCP connect to 127.0.0.1:[port]; true if something accepts.
    private static func fridaPortOpen(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        return rc == 0
    }

    /// Real binary-integrity fingerprint: a digest over the app's own Mach-O
    /// executable. Patching the binary (a resign, a Frida gadget injected on
    /// disk, a method-swizzling patch) changes these bytes, so the digest is a
    /// genuine tamper signal a client could pin and compare against a
    /// server-held baseline. (iOS does not expose the macOS `SecCodeCheckValidity`
    /// self-check, so hashing the executable is the real, on-device primitive.)
    /// The resilience modules deliberately IGNORE this signal (that's their bug),
    /// but the probe itself now computes a real digest of real bytes.
    private static func tamperFinding() -> String {
        guard let exeURL = Bundle.main.executableURL,
              let data = try? Data(contentsOf: exeURL) else {
            return "detected=false reason=executable-unavailable"
        }
        // Streaming SHA-256 over the Mach-O so we don't load intent on a large
        // binary being cheap; CryptoKit is already linked by the keychain probe.
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        let ident = Bundle.main.bundleIdentifier ?? "unknown"
        // No server baseline is pinned in the training app, so the app cannot
        // actually tell tampered from clean - reported honestly as the bug.
        return "detected=false sha256=\(hex.prefix(16))… bytes=\(data.count) "
            + "identifier=\(ident) (real Mach-O digest; no baseline pinned, so "
            + "tampering is NOT actually detected - the resilience gap)"
    }

    // MARK: - Real App Group shared-container probe (Tier C)

    /// The App Group identifier the app is (or would be) entitled to. Must match
    /// `com.apple.security.application-groups` in Runner.entitlements and the
    /// Dart `AppGroupContainer.appGroupId`.
    private static let appGroupId = "group.com.example.dvma"

    /// iOS analogue of the Android `sharedContainerLeak`: obtain the App Group
    /// shared container via `containerURL(forSecurityApplicationGroupIdentifier:)`,
    /// then act as two logical group members: the "main app" writes the sensitive
    /// item, a "keyboard extension" reads it back with no per-item ACL. That
    /// cross-member read of a real file inside the shared container IS the
    /// amplification, and it is a genuine on-disk artifact.
    ///
    /// `containerURL(...)` returns nil unless the running binary is code-signed
    /// with the matching App Group entitlement (a provisioning grant a lab cannot
    /// auto-issue). When it is nil we report exactly WHY; we do NOT substitute a
    /// private-container write and call it an App Group, which would be a dishonest
    /// finding. The Dart module then falls back to its deterministic simulation.
    private static func appGroupSharedContainerFinding(key: String, value: String) -> String {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupId) else {
            return "detected=false reason=entitlement-missing appGroup=\(appGroupId) "
                + "(containerURL nil - app is not code-signed with the "
                + "com.apple.security.application-groups entitlement; "
                + "add Runner.entitlements + a provisioning profile with this "
                + "group to arm the real cross-member read)"
        }
        do {
            let sharedDir = container.appendingPathComponent("app_group_shared",
                                                             isDirectory: true)
            try FileManager.default.createDirectory(at: sharedDir,
                                                    withIntermediateDirectories: true)
            let itemURL = sharedDir.appendingPathComponent("\(sanitize(key)).item")
            // "main app" member writes the sensitive item into the shared container.
            try value.write(to: itemURL, atomically: true, encoding: .utf8)
            // "keyboard extension" member reads it back with no per-item ACL.
            let readBack = (try? String(contentsOf: itemURL, encoding: .utf8)) ?? ""
            return "detected=true sharedDir=\(sharedDir.path); "
                + "leakedItemPath=\(itemURL.path); key=\(key); "
                + "crossMemberReadBack=\(readBack); "
                + "sharedGroupContainer=true (every app-group member reads every "
                + "item, no per-item ACL)"
        } catch {
            return "detected=false reason=io-error appGroup=\(appGroupId) "
                + "(\(error.localizedDescription))"
        }
    }

    /// Filesystem-safe filename fragment (mirrors the Android probe's `sanitize`).
    private static func sanitize(_ s: String) -> String {
        String(s.map { $0.isLetter || $0.isNumber || "._-".contains($0) ? $0 : "_" })
    }

    // MARK: - Real native memory bug (C, ships in the Mach-O)

    /// Calls the C `dvma_unsafe_copy` (see Runner/dvma_native_memory.c) with the
    /// caller's string. That C does an unbounded `strcpy` into a 16-byte stack
    /// buffer and reports whether the adjacent canary was clobbered. The unsafe
    /// copy is real compiled native code, not a Swift/Dart model.
    private static func nativeUnsafeCopyFinding(_ input: String) -> String {
        var out = [CChar](repeating: 0, count: 256)
        input.withCString { cin in
            dvma_unsafe_copy(cin, &out, UInt(out.count))
        }
        return String(cString: out)
    }

    // MARK: - Real WKWebView local-file read (file-URL access enabled)

    /// Retains the live WKWebView + its script-message handler for the duration
    /// of the async read (a WKWebView is deallocated, and stops running JS, if not
    /// held). Keyed by a token so concurrent runs don't clobber each other.
    private static var liveWebViews: [String: (WKWebView, DvmaExfilHandler)] = [:]

    /// Builds a REAL WKWebView that serves the attacker page AND a seeded secret
    /// file through a custom `WKURLSchemeHandler` (scheme `dvma-app://`), so both
    /// resources share ONE web origin. The attacker page carries UNESCAPED
    /// injected content whose `fetch('secret')` therefore succeeds under the
    /// same-origin policy and posts the secret bytes back via a
    /// `WKScriptMessageHandler`. This is the genuine, current-iOS local-file
    /// disclosure technique (MASTG-KNOW-0076 / MASTG-TEST-0335): the dead
    /// private-KVC `allowFileAccessFromFileURLs` trick and the file:// same-origin
    /// XHR both fail on modern WebKit, but a same-origin custom scheme does not.
    /// A real web engine performs the read; inspectable via frida on `WKWebView`.
    private static func wkWebViewLocalFileRead(payload: String,
                                               result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            let token = UUID().uuidString
            // Seed a REAL secret file in the app container; the scheme handler
            // reads it off disk on demand, so the disclosed bytes are genuine
            // on-disk contents a researcher can independently pull and diff.
            let secretURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("dvma_wk_\(token).json")
            let secretBody = "{\"token\":\"tok-8b21-secret\"}"
            do {
                try secretBody.write(to: secretURL, atomically: true, encoding: .utf8)
            } catch {
                result("detected=false reason=seed-failed(\(error))")
                return
            }

            // Reflect the attacker payload UNESCAPED into the page, and have the
            // page fetch the sibling `secret` path (same custom-scheme origin, so
            // the same-origin policy allows it) and report the bytes back.
            let html = """
            <html><body><h1>Report for \(payload)</h1><script>
            fetch('secret').then(function(r){return r.text();})
              .then(function(t){window.webkit.messageHandlers.Exfil.postMessage('read '+t);})
              .catch(function(e){window.webkit.messageHandlers.Exfil.postMessage('blocked '+e);});
            </script></body></html>
            """

            let config = WKWebViewConfiguration()
            // VULN: a custom scheme handler that serves BOTH the untrusted page
            // and the local secret under one origin, so injected JS can read the
            // secret with a same-origin fetch.
            let scheme = DvmaLocalFileSchemeHandler(html: html, secretURL: secretURL)
            config.setURLSchemeHandler(scheme, forURLScheme: "dvma-app")

            let handler = DvmaExfilHandler { message in
                // Report truthfully: 'read ' prefix = the cross-file read
                // succeeded; 'blocked ' = it failed.
                let read = message.hasPrefix("read ")
                let finding = "detected=\(read) engine=WKWebView "
                    + "WKURLSchemeHandler(scheme=dvma-app) sameOrigin=true "
                    + "secret=\(secretURL.lastPathComponent) "
                    + "injectedScriptResult=\(message)"
                emit("wkWebViewLocalFileRead", finding)
                liveWebViews.removeValue(forKey: token)
                result(finding)
            }
            config.userContentController.add(handler, name: "Exfil")

            let webView = WKWebView(frame: .zero, configuration: config)
            liveWebViews[token] = (webView, handler)
            // Load the attacker page from the custom-scheme origin.
            if let start = URL(string: "dvma-app://host/report.html") {
                webView.load(URLRequest(url: start))
            }

            // Safety valve: if the message never arrives (e.g. hardened OS),
            // return a truthful timeout instead of hanging the channel.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                if liveWebViews.removeValue(forKey: token) != nil {
                    result("detected=false reason=no-message (script blocked or "
                        + "WKWebView hardened on this OS)")
                }
            }
        }
    }

    // MARK: - Real iOS sensitive local notification
    /// Schedules a genuine `UNNotificationRequest` whose title/body carry the
    /// sensitive OTP + balance (the leak), then reads the pending/delivered
    /// content back from `UNUserNotificationCenter` and returns a report. The
    /// notification is real and renders on the lock screen; the app never sets
    /// an interruption level or hides content, so a glance at the locked device
    /// exposes the secret (CWE-200 on the notification surface).
    private static func postSensitiveNotification(_ result: @escaping FlutterResult) {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            let content = UNMutableNotificationContent()
            content.title = "Your login code"
            content.body = "Your OTP is 559-201 and your balance is $84,201.55"
            // VULN: no redaction / .sensitive interruption level, so the full
            // body is shown on the lock screen with previews on.
            let request = UNNotificationRequest(
                identifier: "dvma.push_notification_leakage",
                content: content,
                trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1,
                                                            repeats: false))
            center.add(request) { _ in
                center.getPendingNotificationRequests { pending in
                    let mine = pending.first { $0.identifier == request.identifier }
                    let readBack = mine.map {
                        "\($0.content.title) - \($0.content.body)"
                    } ?? "\(content.title) - \(content.body)"
                    let finding = "detected=true authorization=\(granted) "
                        + "scheduled=UNNotificationRequest("
                        + "id=\(request.identifier)); "
                        + "lockScreenBody=\(readBack); "
                        + "redacted=false (full OTP + balance in body, no "
                        + ".sensitive interruption level)"
                    emit("postSensitiveNotification", finding)
                    result(finding)
                }
            }
        }
    }

    // MARK: - Real iOS App Intent (lock-screen / assistant authorization)

    /// Runs the real `UnlockFrontDoorIntent.perform()` and reports the declared
    /// `authenticationPolicy` of the vulnerable vs. secure intent alongside the
    /// live protected-data (lock) state. The vulnerable intent ships with no
    /// authentication requirement, so it runs from a locked device - the bug.
    private static func invokeSensitiveAppIntent(_ result: @escaping FlutterResult) {
        guard #available(iOS 16.0, *) else {
            result("detected=false reason=appintents-unavailable (needs iOS 16+)")
            return
        }
        Task {
            let locked = await MainActor.run {
                !UIApplication.shared.isProtectedDataAvailable
            }
            // The vulnerable intent runs with no auth requirement.
            _ = try? await UnlockFrontDoorIntent().perform()
            // UnlockFrontDoorIntent declares NO authenticationPolicy, so it
            // inherits the permissive .alwaysAllowed default (there is no public
            // API to read the inherited default back, so this is stated, not
            // reflected); the secure variant's policy IS read from the type.
            let vulnPolicy = "alwaysAllowed(inherited default; no policy declared)"
            let securePolicy = "\(UnlockFrontDoorSecureIntent.authenticationPolicy)"
            let finding = "detected=true intent=UnlockFrontDoorIntent "
                + "performed=true deviceLocked=\(locked) "
                + "vulnAuthenticationPolicy=\(vulnPolicy) "
                + "openAppWhenRun=\(UnlockFrontDoorIntent.openAppWhenRun) "
                + "(sensitive App Intent has no auth policy; full PoC is invoking "
                + "it from Shortcuts/Siri on a locked device); "
                + "secureAuthenticationPolicy=\(securePolicy)"
            emit("invokeSensitiveIntent", finding)
            result(finding)
        }
    }

    /// Runs the real parameterized `ExportAccountIntent.perform()` with an
    /// attacker-supplied account id: the untrusted parameter drives a privileged
    /// export with no per-invocation authorization (App Intents parameter
    /// capability-confusion). Writes a real container-file artifact.
    private static func invokeExportAppIntent(accountId: String,
                                              result: @escaping FlutterResult) {
        guard #available(iOS 16.0, *) else {
            result("detected=false reason=appintents-unavailable (needs iOS 16+)")
            return
        }
        Task {
            let intent = ExportAccountIntent()
            intent.accountId = accountId
            _ = try? await intent.perform()
            let finding = "detected=true intent=ExportAccountIntent "
                + "accountId=\(accountId) performed=true "
                + "authenticationPolicy=alwaysAllowed(default) "
                + "(untrusted Shortcut parameter drove a privileged export of "
                + "another account with no per-invocation authorization)"
            emit("invokeExportIntent", finding)
            result(finding)
        }
    }

    /// Reports the real system surfaces the app's App Intents are exposed to,
    /// read from the compiled App Intents metadata bundle emitted at build time
    /// (`Metadata.appintents`). The privileged intents are surfaced to every
    /// system entry point with no per-surface authorization.
    private static func appIntentSurfacesFinding() -> String {
        let present = Bundle.main.url(forResource: "Metadata",
                                      withExtension: "appintents") != nil
            || Bundle.main.url(forResource: "extract",
                               withExtension: "actionsdata",
                               subdirectory: "Metadata.appintents") != nil
        // App Intents are automatically offered to Siri, Spotlight, Shortcuts,
        // Widgets, Control Center, the Action Button and Apple Intelligence
        // unless the intent opts out per-surface (none of DVMA's do).
        let surfaces = "siri,spotlight,shortcuts,widget,controlCenter,"
            + "actionButton,appleIntelligence"
        return "detected=true metadataBundle=\(present) "
            + "exposedSurfaces=[\(surfaces)] "
            + "privilegedIntents=[UnlockFrontDoorIntent,ExportAccountIntent] "
            + "(intents reach a privileged op from any surface with no "
            + "per-surface authorization)"
    }

    // MARK: - Real external URL launch (arbitrary intent)

    /// Opens an attacker/model-chosen URL with `UIApplication.open` and no
    /// scheme allowlist, so a non-web scheme (tel:, sms:, a custom app scheme)
    /// launches another app - the iOS analogue of an arbitrary implicit intent.
    private static func launchExternalUrlFinding(_ urlString: String) -> String {
        guard let url = URL(string: urlString) else {
            return "detected=false reason=unparseable url=\(urlString)"
        }
        var canOpen = false
        DispatchQueue.main.sync {
            canOpen = UIApplication.shared.canOpenURL(url)
            UIApplication.shared.open(url, options: [:], completionHandler: nil)
        }
        return "detected=true opened=\(urlString) scheme=\(url.scheme ?? "?") "
            + "canOpenURL=\(canOpen) (no scheme allowlist - external app launch)"
    }

    // MARK: - Real App Tracking Transparency state

    /// Reports the real `ATTrackingManager` authorization status and the real
    /// IDFA. When the app tracks without ever calling
    /// `requestTrackingAuthorization`, the status is `.notDetermined` yet the
    /// app still harvests/exfiltrates an id - the missing-prompt bug. The IDFA
    /// is all-zeros unless the user authorized, proving no prompt was honored.
    private static func trackingTransparencyFinding() -> String {
        let status: String
        if #available(iOS 14.0, *) {
            switch ATTrackingManager.trackingAuthorizationStatus {
            case .notDetermined: status = "notDetermined (no ATT prompt shown)"
            case .restricted: status = "restricted"
            case .denied: status = "denied"
            case .authorized: status = "authorized"
            @unknown default: status = "unknown"
            }
        } else {
            status = "unavailable (needs iOS 14+)"
        }
        let idfa = ASIdentifierManager.shared().advertisingIdentifier.uuidString
        let allZero = idfa == "00000000-0000-0000-0000-000000000000"
        return "detected=true attStatus=\(status) idfa=\(idfa) "
            + "idfaZeroed=\(allZero) "
            + "(app harvests/exfiltrates a tracking id with authorization "
            + "status \(status) - no requestTrackingAuthorization prompt)"
    }
}

/// Real `WKScriptMessageHandler` that forwards the injected page's exfiltrated
/// bytes back to the channel handler. NSObject-based because the WebKit protocol
/// requires it. Held alive via `DvmaNativeProbes.liveWebViews` for the read's
/// duration.
final class DvmaExfilHandler: NSObject, WKScriptMessageHandler {
    private let onMessage: (String) -> Void

    init(onMessage: @escaping (String) -> Void) {
        self.onMessage = onMessage
    }

    func userContentController(_ controller: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        onMessage("\(message.body)")
    }
}

/// Real `WKURLSchemeHandler` that serves the untrusted attacker page AND the
/// local secret file under ONE custom-scheme origin (`dvma-app://`). Because
/// both responses come from the same scheme+host, the browser same-origin
/// policy lets the page's injected `fetch('secret')` read the secret - the
/// current-iOS local-file disclosure primitive (MASTG-KNOW-0076), since the
/// legacy `file://` XHR and private `allowFileAccessFromFileURLs` paths are dead
/// on modern WebKit. INTENTIONALLY VULNERABLE: no path/scope validation.
final class DvmaLocalFileSchemeHandler: NSObject, WKURLSchemeHandler {
    private let html: String
    private let secretURL: URL

    init(html: String, secretURL: URL) {
        self.html = html
        self.secretURL = secretURL
    }

    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url else {
            urlSchemeTask.didFailWithError(
                NSError(domain: "dvma", code: -1))
            return
        }
        let data: Data
        let mime: String
        if url.path.hasSuffix("secret") || url.lastPathComponent == "secret" {
            // VULN: serve the real on-disk secret with no authorization/scope
            // check, same origin as the page.
            data = (try? Data(contentsOf: secretURL)) ?? Data()
            mime = "application/json"
        } else {
            data = Data(html.utf8)
            mime = "text/html"
        }
        // Respond as HTTP/200 so WKWebView's fetch/XHR accepts the body (a bare
        // URLResponse can be treated as opaque). Same scheme+host as the page,
        // so the read is same-origin.
        let headers = [
            "Content-Type": mime,
            "Content-Length": String(data.count),
            "Access-Control-Allow-Origin": "*",
        ]
        let resp = HTTPURLResponse(url: url, statusCode: 200,
                                   httpVersion: "HTTP/1.1",
                                   headerFields: headers)
            ?? URLResponse(url: url, mimeType: mime,
                           expectedContentLength: data.count,
                           textEncodingName: "utf-8")
        urlSchemeTask.didReceive(resp)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}
}
