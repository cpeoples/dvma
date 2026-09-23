package com.dvma

import android.app.admin.DevicePolicyManager
import android.companion.CompanionDeviceManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

/**
 * Real native system-provider probes for the `system_provider` vulnerability
 * modules. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Unlike a pure-Dart in-memory simulation, each method here performs a GENUINE
 * on-device query/config against the actual OS capability the module is about
 * (DevicePolicyManager, the Settings.Secure enabled-provider lists,
 * MediaProjectionManager, VpnService consent, CompanionDeviceManager
 * associations, and a real world-readable-ish shared file). Many of these
 * capabilities cannot be *armed* without a user grant that a lab cannot
 * auto-provision (enabling an accessibility service, approving a screen-capture
 * MediaProjection token, confirming a VPN consent, enabling the custom IME).
 * For those, the probe reports the REAL current grant/config state plus what
 * enabling the capability would expose, so the module is genuinely
 * device-observable rather than a fabricated model.
 *
 * Every finding is returned to Dart as a short human-readable string AND
 * mirrored to logcat under [TAG] (`adb logcat -s DVMA-EVIDENCE:*`) so the
 * capture harness can pull it. The Dart side ALSO records it to the pullable
 * artifact dir via DvmaEvidence.record, so there is a real artifact on device
 * for every module regardless of whether the capability is fully armed.
 */
class SystemProviderProbe(private val app: Context) {

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                val finding: String? = when (call.method) {
                    "devicePolicyState" -> devicePolicyState()
                    "enabledProviders" -> enabledProviders()
                    "mediaProjectionState" -> mediaProjectionState()
                    "vpnConsentState" -> vpnConsentState()
                    "companionAssociations" -> companionAssociations()
                    "checkCustomPermission" -> checkCustomPermission()
                    "mediaStoreQuery" -> mediaStoreQuery()
                    "platformVersionKeystore" -> platformVersionKeystore()
                    "telephonyCapability" ->
                        telephonyCapability(call.argument<String>("number") ?: "900-555-0100")
                    "sharedContainerLeak" ->
                        sharedContainerLeak(
                            call.argument<String>("key") ?: "auth.session.token",
                            call.argument<String>("value") ?: "",
                        )
                    else -> null
                }
                if (finding == null) {
                    result.notImplemented()
                } else {
                    Log.w(TAG, "[${call.method}] $finding")
                    result.success(finding)
                }
            }
    }

    /**
     * device_policy_mdm_capability_abuse: query the REAL DevicePolicyManager for
     * this app's device-admin / device-owner posture. `isAdminActive` /
     * `getActiveAdmins` / `isDeviceOwnerApp` are genuine reads of the policy
     * boundary. Becoming an active admin (or device owner) is a user/MDM grant a
     * lab cannot auto-provision, so we report the real state plus what holding it
     * would expose (device wipe, password-policy control, camera disable).
     */
    private fun devicePolicyState(): String = runCatching {
        val dpm = app.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val pkg = app.packageName
        val selfAdmin = ComponentName(pkg, "$pkg.DummyDeviceAdminReceiver")
        val isSelfAdminActive = dpm.isAdminActive(selfAdmin)
        val activeAdmins: List<ComponentName> = dpm.activeAdmins ?: emptyList()
        val isDeviceOwner = dpm.isDeviceOwnerApp(pkg)
        val isProfileOwner =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                dpm.isProfileOwnerApp(pkg)
            } else {
                false
            }
        buildString {
            append("isSelfAdminActive=$isSelfAdminActive; ")
            append("isDeviceOwner=$isDeviceOwner; ")
            append("isProfileOwner=$isProfileOwner; ")
            append("activeAdmins=")
            append(
                if (activeAdmins.isEmpty()) "none"
                else activeAdmins.joinToString(",") { it.flattenToShortString() }
            )
            append("; wouldExpose=wipeData/resetPassword/setCameraDisabled/setPasswordQuality")
        }
    }.getOrElse { e ->
        "devicePolicy=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * privileged_provider_activation_abuse / privileged_input_provider_injection /
     * custom_keyboard_input_interception: enumerate the REAL enabled privileged
     * providers via Settings.Secure - enabled input methods (IMEs), enabled
     * accessibility services, and enabled notification listeners. These lists are
     * the actual OS record of which apps hold system-provider status. Enabling a
     * provider is a user grant (Settings toggle) a lab cannot auto-provision;
     * this reports which are currently active and whether DVMA's own custom IME
     * (declared in the manifest) is among them.
     */
    private fun enabledProviders(): String = runCatching {
        val cr = app.contentResolver
        val enabledImes =
            Settings.Secure.getString(cr, Settings.Secure.ENABLED_INPUT_METHODS) ?: ""
        val enabledA11y =
            Settings.Secure.getString(cr, ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        val enabledNotifListeners =
            Settings.Secure.getString(cr, ENABLED_NOTIFICATION_LISTENERS) ?: ""
        val defaultIme =
            Settings.Secure.getString(cr, Settings.Secure.DEFAULT_INPUT_METHOD) ?: ""
        val pkg = app.packageName
        val dvmaImeEnabled = enabledImes.contains(pkg)
        buildString {
            append("defaultIme=$defaultIme; ")
            append("dvmaCustomImeEnabled=$dvmaImeEnabled; ")
            append("enabledInputMethods=${listSummary(enabledImes)}; ")
            append("enabledAccessibilityServices=${listSummary(enabledA11y)}; ")
            append("enabledNotificationListeners=${listSummary(enabledNotifListeners)}")
        }
    }.getOrElse { e ->
        "enabledProviders=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * mediaprojection_screencapture_authorization_bypass: confirm the REAL
     * MediaProjectionManager is present and that its createScreenCaptureIntent
     * API exists (the consent surface). A granted projection token can be reused
     * to keep recording; obtaining the token itself requires the user to approve
     * the system consent dialog (not auto-provisionable), so we report API
     * availability + the token-reuse gap.
     */
    private fun mediaProjectionState(): String = runCatching {
        val mpm =
            app.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? MediaProjectionManager
        val available = mpm != null
        val hasConsentIntent = runCatching {
            mpm?.createScreenCaptureIntent() != null
        }.getOrDefault(false)
        buildString {
            append("mediaProjectionAvailable=$available; ")
            append("consentIntentApiPresent=$hasConsentIntent; ")
            append("tokenReusable=true (a granted MediaProjection token is not ")
            append("bound to a single capture and can be reused/forwarded); ")
            append("wouldExpose=full-screen recording of every app until stopped")
        }
    }.getOrElse { e ->
        "mediaProjection=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * vpn_provider_trust_anchor_abuse: query the REAL VpnService.prepare() state.
     * A null return means a VPN consent already exists for this app (it is the
     * prepared VPN); a non-null Intent is the consent dialog that would have to
     * be shown. Establishing the tunnel needs that user consent + a real
     * endpoint, so we report the consent state plus the trust-anchor gap (a
     * device-wide VPN that skips endpoint cert validation MITMs all traffic).
     */
    private fun vpnConsentState(): String = runCatching {
        val prepare = VpnService.prepare(app)
        val consentAlreadyGranted = prepare == null
        buildString {
            append("vpnConsentAlreadyGranted=$consentAlreadyGranted; ")
            append(
                if (consentAlreadyGranted) {
                    "state=this app is (or is authorized as) the active VPN; "
                } else {
                    "state=consent dialog required before tunnel establishes; "
                }
            )
            append("trustAnchorGap=a VPN provider that authenticates its endpoint ")
            append("with an accept-all trust manager (no chain/hostname/CA check) ")
            append("MITMs ALL tunneled traffic; ")
            append("wouldExpose=every flow routed through the device-wide tunnel")
        }
    }.getOrElse { e ->
        "vpnConsent=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * companion_device_pairing_confusion: query the REAL CompanionDeviceManager
     * for this app's current associations. Each association is a paired
     * companion device; the over-broad capability is that "paired" is treated as
     * "authorized for every action" with no per-capability trust binding.
     * Creating an association needs the user to pick a device in the system
     * dialog (not auto-provisionable), so we report the real association list +
     * the over-broad-capability gap.
     */
    private fun companionAssociations(): String = runCatching {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return "companion=unavailable (requires API 26+, sdk=${Build.VERSION.SDK_INT})"
        }
        val cdm =
            app.getSystemService(Context.COMPANION_DEVICE_SERVICE) as? CompanionDeviceManager
        if (cdm == null) {
            return "companion=unavailable (CompanionDeviceManager service null)"
        }
        val associations: List<String> = runCatching {
            @Suppress("DEPRECATION")
            cdm.associations ?: emptyList()
        }.getOrDefault(emptyList())
        buildString {
            append("associationCount=${associations.size}; ")
            append("associations=")
            append(if (associations.isEmpty()) "none" else associations.joinToString(","))
            append("; overBroadCapability=an association only proves proximity+identity, ")
            append("not authorization; treating paired==authorized grants a spoofed/")
            append("low-trust device high-privilege actions (unlock-door, send-sms)")
        }
    }.getOrElse { e ->
        "companion=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * app_group_shared_container_amplification (FULLY REAL): write a token to a
     * real shared file under getExternalFilesDir (the Android app-group analogue
     * - world-readable-ish, adb-pullable) as the "main app", then read it back as
     * a different "member" (the keyboard extension). Records the leaked absolute
     * path + contents. This is a genuine cross-member over-read on the real
     * filesystem, not a model.
     */
    private fun sharedContainerLeak(key: String, value: String): String = runCatching {
        val base = app.getExternalFilesDir(null)
            ?: return "sharedContainer=unavailable (no external files dir)"
        val shared = File(base, "app_group_shared")
        shared.mkdirs()
        val item = File(shared, "${sanitize(key)}.item")
        // "main app" member writes the sensitive item into the shared container.
        item.writeText(value)
        // "keyboard extension" member (different logical member, same group dir)
        // reads it back with NO per-item ACL - the amplification.
        val readBack = if (item.exists()) item.readText() else ""
        buildString {
            append("sharedDir=${shared.absolutePath}; ")
            append("leakedItemPath=${item.absolutePath}; ")
            append("key=$key; ")
            append("crossMemberReadBack=$readBack; ")
            append("worldReadableGroupDir=true (every app-group member reads every item, no per-item ACL)")
        }
    }.getOrElse { e ->
        "sharedContainer=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * custom_signature_permission_squatting: read the REAL runtime protection
     * level of DVMA's custom ADMIN_OP permission via PackageManager, and check
     * whether the app itself holds it. A permission declared protectionLevel=
     * "normal" is auto-granted to any requester, so checkPermission returns
     * GRANTED and the exported SquatGuardedActivity it guards is reachable.
     */
    private fun checkCustomPermission(): String = runCatching {
        val pm = app.packageManager
        val perm = "${app.packageName}.permission.ADMIN_OP"
        val info = runCatching { pm.getPermissionInfo(perm, 0) }.getOrNull()
        val protectionLevel = info?.protectionLevel?.let { levelName(it) } ?: "unknown"
        val selfGranted =
            pm.checkPermission(perm, app.packageName) == PackageManager.PERMISSION_GRANTED
        buildString {
            append("permission=$perm; ")
            append("protectionLevel=$protectionLevel; ")
            append("checkPermission(self)=${if (selfGranted) "GRANTED" else "DENIED"}; ")
            append("guardedComponent=.SquatGuardedActivity (exported); ")
            append(
                if (protectionLevel.contains("normal")) {
                    "=> NORMAL-level permission is auto-granted to any requester (and " +
                        "squattable by install order): the guard is trivially obtained, " +
                        "the exported component is externally reachable"
                } else {
                    "=> protectionLevel is not normal"
                }
            )
        }
    }.getOrElse { e ->
        "checkCustomPermission=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * photo_picker_over_access: run a REAL MediaStore query over
     * EXTERNAL_CONTENT_URI to enumerate on-device images. A full media grant
     * returns every image row (over-collection); the scoped photo picker would
     * return only the one item the user chose. Reports the real accessible
     * count + whether the broad media permission is held.
     */
    private fun mediaStoreQuery(): String = runCatching {
        val readPerm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            "android.permission.READ_MEDIA_IMAGES"
        } else {
            "android.permission.READ_EXTERNAL_STORAGE"
        }
        val held = app.packageManager.checkPermission(readPerm, app.packageName) ==
            PackageManager.PERMISSION_GRANTED
        val uri = android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val projection = arrayOf(
            android.provider.MediaStore.Images.Media._ID,
            android.provider.MediaStore.Images.Media.DISPLAY_NAME,
        )
        var count = 0
        val sample = StringBuilder()
        runCatching {
            app.contentResolver.query(uri, projection, null, null, null)?.use { c ->
                count = c.count
                var shown = 0
                while (c.moveToNext() && shown < 5) {
                    sample.append(c.getString(1)).append(' ')
                    shown++
                }
            }
        }
        buildString {
            append("mediaPermission=$readPerm held=$held; ")
            append("MediaStore.Images query returned count=$count rows ")
            append("(FULL-library scope, standing access to future photos); ")
            append("sample=[${sample.toString().trim()}]; ")
            append("scoped picker would return ONLY the user-selected item with no " +
                "standing permission")
        }
    }.getOrElse { e ->
        "mediaStoreQuery=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /**
     * platform_version_security_fallback: read the REAL Build.VERSION.SDK_INT
     * and attempt a genuine hardware-backed (StrongBox) Keystore key generation,
     * catching StrongBoxUnavailableException. Reports whether the platform
     * actually provided the hardware guarantee vs. silently fell back to a
     * software key - the real device-observable posture.
     */
    private fun platformVersionKeystore(): String = runCatching {
        val sdk = Build.VERSION.SDK_INT
        val strongBoxThreshold = Build.VERSION_CODES.P // API 28
        var hardwareBacked = false
        var note: String
        if (sdk < strongBoxThreshold) {
            note = "SDK_INT=$sdk < 28: StrongBox API unavailable; a version-gated " +
                "fallback would silently store a SOFTWARE key and proceed"
        } else {
            val result = tryGenerateKey(strongBox = true)
            hardwareBacked = result.first
            note = result.second
        }
        buildString {
            append("SDK_INT=$sdk; strongBoxThreshold=28; ")
            append("hardwareBacked=$hardwareBacked; ")
            append(note)
        }
    }.getOrElse { e ->
        "platformVersionKeystore=error (${e.javaClass.simpleName}: ${e.message})"
    }

    /** Generate a real AES key in the AndroidKeyStore, requesting StrongBox.
     *  Returns (hardwareBacked, note) - catching a real StrongBox unavailable. */
    private fun tryGenerateKey(strongBox: Boolean): Pair<Boolean, String> {
        return try {
            val kpg = javax.crypto.KeyGenerator.getInstance(
                android.security.keystore.KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore",
            )
            val specBuilder = android.security.keystore.KeyGenParameterSpec.Builder(
                "dvma_version_fallback_key",
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                    android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(
                    android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE,
                )
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(true)
            }
            kpg.init(specBuilder.build())
            kpg.generateKey()
            true to "generated StrongBox-backed key in AndroidKeyStore (real hardware guarantee)"
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            false to "StrongBoxUnavailableException: no StrongBox on this device; a " +
                "version-gated fallback would silently store a SOFTWARE key and proceed " +
                "insecurely (should FAIL CLOSED)"
        } catch (e: Throwable) {
            false to "keystore generation failed: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    /**
     * telephony_capability_abuse: build the REAL Intent.ACTION_CALL for the
     * given number and resolve whether the app holds CALL_PHONE. The declared
     * capability + runtime permission state is device-observable; actually
     * placing the call needs the CALL_PHONE grant + a real SIM, so we report the
     * capability and the missing per-invocation check rather than dialing.
     */
    private fun telephonyCapability(number: String): String = runCatching {
        val callIntent = android.content.Intent(
            android.content.Intent.ACTION_CALL,
            android.net.Uri.parse("tel:$number"),
        )
        val resolvable = callIntent.resolveActivity(app.packageManager) != null
        val callPhoneHeld = app.packageManager.checkPermission(
            "android.permission.CALL_PHONE",
            app.packageName,
        ) == PackageManager.PERMISSION_GRANTED
        val telecom = app.getSystemService(Context.TELECOM_SERVICE)
        buildString {
            append("capability=ACTION_CALL tel:$number; ")
            append("intentResolvable=$resolvable; ")
            append("CALL_PHONE held=$callPhoneHeld; ")
            append("telecomServiceAvailable=${telecom != null}; ")
            append("=> the telephony sink is reachable with NO per-invocation check; ")
            append(
                if (callPhoneHeld) {
                    "CALL_PHONE granted -> ACTION_CALL would place the call directly"
                } else {
                    "CALL_PHONE not granted -> the missing per-invocation authorization " +
                        "is the device-observable gap (placing the call needs the grant + SIM)"
                }
            )
        }
    }.getOrElse { e ->
        "telephonyCapability=error (${e.javaClass.simpleName}: ${e.message})"
    }

    private fun levelName(level: Int): String {
        val base = when (level and 0xf) {
            android.content.pm.PermissionInfo.PROTECTION_NORMAL -> "normal"
            android.content.pm.PermissionInfo.PROTECTION_DANGEROUS -> "dangerous"
            android.content.pm.PermissionInfo.PROTECTION_SIGNATURE -> "signature"
            else -> "level_$level"
        }
        return base
    }

    private fun listSummary(raw: String): String {
        if (raw.isBlank()) return "none"
        val entries = raw.split(":").filter { it.isNotBlank() }
        return "count=${entries.size} [${entries.joinToString(",")}]"
    }

    private fun sanitize(s: String): String = s.replace(Regex("[^A-Za-z0-9._-]"), "_")

    private companion object {
        const val CHANNEL = "dvma/system_provider"
        const val TAG = EvidenceStore.TAG

        // Settings.Secure keys that are public constants only on newer APIs;
        // reference the stable string values directly to stay minSdk-safe.
        const val ENABLED_ACCESSIBILITY_SERVICES = "enabled_accessibility_services"
        const val ENABLED_NOTIFICATION_LISTENERS = "enabled_notification_listeners"
    }
}
