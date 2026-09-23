//
//  DvmaLockscreenIntents.swift
//
//  Real iOS App Intents for DVMA - INTENTIONALLY VULNERABLE.
//  FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
//  Genuine `AppIntent`s (iOS 16+) compiled into the Runner binary, exposed to
//  Siri, Shortcuts, Control Center / Lock Screen Controls and the Action Button.
//  They back lockscreen_control_action_authorization and
//  assistant_locked_device_capability_abuse.
//
//  The bug: a SENSITIVE intent (`UnlockFrontDoorIntent`) declares no
//  `AuthenticationPolicy` (defaults to `.alwaysAllowed`) with
//  `openAppWhenRun = false`, so the system runs it in the background from a
//  locked device with no auth gate. The secure contrast intent sets
//  `authenticationPolicy = .requiresAuthentication`.

import AppIntents
import Foundation
import UIKit

/// VULN: a privileged intent the system can run with no authentication.
///
/// `authenticationPolicy` is left at its permissive default and
/// `openAppWhenRun` is false, so Siri / a Lock Screen Control / the Shortcuts
/// app dispatches it in the background while the device is locked.
@available(iOS 16.0, *)
struct UnlockFrontDoorIntent: AppIntent {
    static var title: LocalizedStringResource = "Unlock Front Door"
    static var description = IntentDescription(
        "Unlocks the front door lock.")

    // VULN: no authentication required, and the app is not opened to present
    // its own auth gate, so the sensitive action runs straight from the system
    // surface on a locked device.
    static var openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        // Real side effect: record that the privileged action ran (and whether
        // device data was protected/locked at the time) to a container file.
        let locked = await MainActor.run { !UIApplication.shared.isProtectedDataAvailable }
        DvmaIntentEvidence.record(
            intent: "UnlockFrontDoorIntent",
            authRequired: false,
            deviceLocked: locked)
        return .result(dialog: "Front door unlocked.")
    }
}

/// SECURE contrast: the same sensitive operation, correctly gated so the system
/// must authenticate the user before `perform()` runs.
@available(iOS 16.0, *)
struct UnlockFrontDoorSecureIntent: AppIntent {
    static var title: LocalizedStringResource = "Unlock Front Door (secure)"
    static var description = IntentDescription(
        "Unlocks the front door lock after device authentication.")

    // SECURE: require device auth; the system refuses to run this from a locked
    // device until the user authenticates.
    static var authenticationPolicy: IntentAuthenticationPolicy =
        .requiresAuthentication
    static var openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let locked = await MainActor.run { !UIApplication.shared.isProtectedDataAvailable }
        DvmaIntentEvidence.record(
            intent: "UnlockFrontDoorSecureIntent",
            authRequired: true,
            deviceLocked: locked)
        return .result(dialog: "Front door unlocked.")
    }
}

/// VULN: a parameterized privileged intent that maps its UNTRUSTED
/// system-supplied `accountId` parameter straight to a data export with no
/// per-invocation authorization and no ownership check. A crafted Shortcut
/// passes another user's account id and the intent exports it - the App Intents
/// parameter capability-confusion class. Backs app_intent_parameter_authorization
/// and the iОS capability-composition chain's App-Intent hop.
@available(iOS 16.0, *)
struct ExportAccountIntent: AppIntent {
    static var title: LocalizedStringResource = "Export Account"
    static var description = IntentDescription("Exports an account's data.")

    // The attacker-controllable parameter arriving from Siri / Shortcuts.
    @Parameter(title: "Account ID")
    var accountId: String

    // VULN: no authenticationPolicy, so the system runs it with no auth.
    static var openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        // Real side effect: append the exported account to a container file,
        // proving the untrusted parameter drove a privileged export.
        DvmaIntentEvidence.recordExport(accountId: accountId, authorized: false)
        return .result(dialog: "Exported account \(accountId).")
    }
}

/// Small file-backed evidence recorder shared by the intents, mirroring the
/// Dart `DvmaEvidence` sink so `capture_run_ios.sh` can pull the artifact.
enum DvmaIntentEvidence {
    /// Records an unauthenticated ExportAccount invocation (untrusted param →
    /// privileged export).
    static func recordExport(accountId: String, authorized: Bool) {
        write("export intent=ExportAccountIntent accountId=\(accountId) "
            + "authorized=\(authorized) ts=\(Date().timeIntervalSince1970)\n")
    }

    static func record(intent: String, authRequired: Bool, deviceLocked: Bool) {
        write("intent=\(intent) authRequired=\(authRequired) "
            + "deviceLocked=\(deviceLocked) ts=\(Date().timeIntervalSince1970)\n")
    }

    private static func write(_ line: String) {
        let dir = FileManager.default.urls(for: .documentDirectory,
                                           in: .userDomainMask)[0]
        let url = dir.appendingPathComponent("dvma_appintent_invocations.log")
        if let data = line.data(using: .utf8) {
            if let handle = try? FileHandle(forWritingTo: url) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? data.write(to: url)
            }
        }
    }
}
