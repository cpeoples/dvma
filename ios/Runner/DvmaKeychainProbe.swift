//  DvmaKeychainProbe.swift
//  INTENTIONALLY VULNERABLE. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
//  Real iOS Keychain surface (Security.framework SecItemAdd/CopyMatching/Update)
//  backing keychain_access_group_authorization_confusion and
//  keychain_state_integrity_manipulation. Channel: dvma/keychain.
//    accessGroupConfusion - stores a secret with kSecAttrSynchronizable=true and
//        an over-broad kSecAttrAccessGroup, then reads it back to show the item
//        is not scoped to one app-private group.
//    stateIntegrityTamper - stores an entitlement blob + a real HMAC-SHA256 tag,
//        rewrites only the value via SecItemUpdate (leaving the tag stale), and
//        returns both the trusting read and the verifying read.
//  Calls that cannot fully arm report the real OSStatus rather than faking
//  success, so the Dart module keeps its deterministic model.

import CryptoKit
import Flutter
import Foundation
import Security

enum DvmaKeychainProbe {
    private static let service = "com.dvma.keychain.training"
    // App-held HMAC key the "local attacker" who edits the item does not have.
    private static let macKey = SymmetricKey(data: Data("app-hmac-key-7c1f".utf8))

    static func handle(method: String,
                       args: [String: Any],
                       result: @escaping FlutterResult) {
        switch method {
        case "accessGroupConfusion":
            result(accessGroupConfusion(key: args["key"] as? String ?? "refresh_token",
                                        value: args["value"] as? String
                                            ?? "rt_9f31c0a7-oauth-refresh"))
        case "stateIntegrityTamper":
            result(stateIntegrityTamper(key: args["key"] as? String ?? "admin_entitlement",
                                        genuine: args["genuine"] as? String
                                            ?? "role=user;tier=standard",
                                        forged: args["forged"] as? String
                                            ?? "role=admin;tier=platinum"))
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Access-group authorization confusion

    /// Stores a secret marked `synchronizable` (iCloud-shared, widening the
    /// access boundary) and reads it back with a query that does NOT pin an
    /// app-private access group (the confusion). Reports real OSStatus values.
    private static func accessGroupConfusion(key: String, value: String) -> String {
        let account = key
        // Clean any prior item so re-runs are deterministic.
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: service,
                       kSecAttrAccount: account] as CFDictionary)

        // VULN: synchronizable=true widens exposure across the user's devices;
        // no app-private access group pins the item. (kSecAttrAccessGroup is
        // intentionally omitted so the item lands in the default group shared
        // by the app + its extensions.)
        let addAttrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: kCFBooleanTrue as Any,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData: Data(value.utf8),
        ]
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)

        // A caller that does NOT pin the owning app's private access group
        // still matches the item (synchronizable + default group).
        var out: CFTypeRef?
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny as Any,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecReturnAttributes: kCFBooleanTrue as Any,
        ]
        let readStatus = SecItemCopyMatching(query as CFDictionary, &out)
        var readBack = "<none>"
        var itemGroup = "<default (app + extensions)>"
        if readStatus == errSecSuccess, let dict = out as? [CFString: Any] {
            if let d = dict[kSecValueData] as? Data {
                readBack = String(data: d, encoding: .utf8) ?? "<binary>"
            }
            if let g = dict[kSecAttrAccessGroup] as? String { itemGroup = g }
        }
        let leak = readStatus == errSecSuccess
        return "detected=\(leak) addStatus=\(addStatus) readStatus=\(readStatus) "
            + "synchronizable=true itemAccessGroup=\(itemGroup) "
            + "crossGroupReadBack=\(readBack) "
            + "(item is not scoped to an app-private kSecAttrAccessGroup, so any "
            + "app-group member / synced device can read it)"
    }

    // MARK: - State integrity manipulation

    /// Stores an entitlement blob + a real HMAC-SHA256 tag, then rewrites ONLY
    /// the value via SecItemUpdate (the local-attacker edit), leaving the tag
    /// stale. Returns the trusting read (privilege granted on forged state) and
    /// the verifying read (HMAC recomputed, tamper rejected).
    private static func stateIntegrityTamper(key: String,
                                             genuine: String,
                                             forged: String) -> String {
        let account = key
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: service,
                       kSecAttrAccount: account] as CFDictionary)

        // App writes the genuine value + a valid HMAC tag (stored in the
        // generic attribute so the value blob stays the authoritative payload).
        let genuineTag = hmac(genuine)
        _ = SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrGeneric: Data(genuineTag.utf8),
            kSecValueData: Data(genuine.utf8),
        ] as CFDictionary, nil)

        // LOCAL ATTACKER: rewrite ONLY the value (no app HMAC key), leaving the
        // stored tag stale - a real SecItemUpdate on the real Keychain item.
        let updateStatus = SecItemUpdate(
            [kSecClass: kSecClassGenericPassword,
             kSecAttrService: service,
             kSecAttrAccount: account] as CFDictionary,
            [kSecValueData: Data(forged.utf8)] as CFDictionary)

        // Read the item back (value + stored tag).
        var out: CFTypeRef?
        let readStatus = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecReturnAttributes: kCFBooleanTrue as Any,
        ] as CFDictionary, &out)

        var storedValue = ""
        var storedTag = ""
        if readStatus == errSecSuccess, let dict = out as? [CFString: Any] {
            if let d = dict[kSecValueData] as? Data {
                storedValue = String(data: d, encoding: .utf8) ?? ""
            }
            if let g = dict[kSecAttrGeneric] as? Data {
                storedTag = String(data: g, encoding: .utf8) ?? ""
            }
        }

        let trusts = storedValue.contains("role=admin")   // vuln read grants
        let verifyOk = hmac(storedValue) == storedTag       // secure read checks
        return "detected=\(trusts && !verifyOk) updateStatus=\(updateStatus) "
            + "readStatus=\(readStatus) storedValue=\(storedValue); "
            + "trustingRead.privilegeGranted=\(trusts) (no HMAC check); "
            + "verifyingRead.integrityOk=\(verifyOk) "
            + "(real HMAC-SHA256 recomputed over the tampered Keychain value "
            + "no longer matches the stored tag → tamper rejected)"
    }

    private static func hmac(_ value: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: macKey)
        return "hmac:" + mac.map { String(format: "%02x", $0) }.joined()
    }
}
