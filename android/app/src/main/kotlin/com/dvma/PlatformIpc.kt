package com.dvma

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.RemoteViews
import dalvik.system.DexClassLoader
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File

/**
 * Native surfaces for the platform vulnerability cluster.
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Each handler performs a *genuine* Android operation that makes the vuln
 * observable off-device - a real Notification posted through NotificationManager
 * (inspectable via `adb shell dumpsys notification`), a real mutable+implicit
 * PendingIntent, a real background startActivity attempt, a real DexClassLoader
 * load+invoke, a real RemoteViews payload - and records the effect into
 * [EvidenceStore] plus logcat under [TAG] so the capture harness can pull it.
 *
 * The Dart side (PlatformIpcBridge) invokes the op and then reads the recorded
 * evidence back with `applied`, mirroring the ComponentIpc read-back pattern.
 * All action/channel names derive from [BuildConfig.APPLICATION_ID].
 */
class PlatformIpc(private val app: Context) {

    private val pkg get() = BuildConfig.APPLICATION_ID

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result -> handle(call, result) }
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            // Read back the last effect a native op recorded, keyed by vuln id.
            "applied" -> result.success(EvidenceStore.read(call.argument<String>("key") ?: ""))

            "postMutablePendingIntent" -> result.success(postMutablePendingIntent())
            "postSensitiveNotification" -> result.success(postSensitiveNotification())
            "overlayConfigGap" -> result.success(overlayConfigGap())
            "backgroundActivityLaunch" -> result.success(backgroundActivityLaunch())
            "dynamicCodeLoad" -> result.success(dynamicCodeLoad())
            "postRemoteViewsWidget" -> result.success(postRemoteViewsWidget())
            "accessibilityServiceState" -> result.success(accessibilityServiceState())
            "stateManipulation" -> result.success(stateManipulation())
            "flagSecureState" -> result.success(flagSecureState())
            "launchExternalUrl" ->
                result.success(launchExternalUrl(call.argument<String>("url") ?: ""))

            else -> result.notImplemented()
        }
    }

    // pending_intent_hijacking / pendingintent_provenance_confusion

    /**
     * Creates a REAL mutable PendingIntent wrapping an IMPLICIT base intent
     * (no explicit component) and posts it inside a real Notification. Because
     * the PendingIntent is FLAG_MUTABLE + implicit, a component that receives it
     * can fill in the blank component/extras and have it fired with DVMA's
     * identity. Inspectable via `adb shell dumpsys notification`.
     */
    private fun postMutablePendingIntent(): String {
        ensureChannel()
        // VULN: implicit base intent (action only, no setClass/setPackage) ...
        val base = Intent("$pkg.action.PI_HIJACK_TARGET").apply {
            putExtra("amount", "1000.00")
            putExtra("to", "payee-of-record")
        }
        // ... wrapped in a FLAG_MUTABLE PendingIntent (the hijack primitive).
        val flags = mutablePiFlags()
        val pi = PendingIntent.getBroadcast(app, 0, base, flags)

        val notif = baseNotification("Confirm transfer", "Tap to approve pending transfer")
            .addAction(0, "Approve", pi)
            .build()
        notify(NOTIF_MUTABLE_PI, notif)

        val evidence = buildString {
            append("posted Notification id=$NOTIF_MUTABLE_PI carrying a MUTABLE + IMPLICIT ")
            append("PendingIntent (getBroadcast, FLAG_MUTABLE, base action-only intent ")
            append("\"$pkg.action.PI_HIJACK_TARGET\", no explicit component); a receiver of ")
            append("this PI can fill component/extras and fire it as $pkg. ")
            append("creator=$pkg intentSender=${pi.intentSender} (dumpsys notification observable)")
        }
        record(KEY_PI_HIJACK, evidence)
        record(KEY_PI_PROVENANCE, evidence)
        return evidence
    }

    // push_notification_leakage / notification_action_authorization_bypass /
    // notification_listener_authorization_bypass

    /**
     * Posts a REAL Notification with a sensitive body and VISIBILITY_PUBLIC, so
     * the OTP/balance is shown on the lock screen and is dumpable via
     * `adb shell dumpsys notification --noredact`. Its action's PendingIntent
     * trampolines the exported [NotificationTrampolineReceiver], which performs
     * a privileged op with no fresh auth. A NotificationListenerService (see
     * [DvmaNotificationListener]) can also read the sensitive body once enabled.
     */
    private fun postSensitiveNotification(): String {
        ensureChannel()
        val body = "Your OTP is 559-201 and your balance is \$84,201.55"

        // VULN: notification-action PendingIntent trampolines an EXPORTED
        // receiver that performs the privileged op with no re-auth.
        val trampoline = Intent(app, NotificationTrampolineReceiver::class.java).apply {
            action = "$pkg.action.APPROVE_TRANSFER"
            putExtra("op", "approve_transfer")
            putExtra("amount", "2500")
            putExtra("to", "acct-payee-042")
        }
        val flags = mutablePiFlags()
        val actionPi = PendingIntent.getBroadcast(app, 1, trampoline, flags)

        val notif = baseNotification("Your login code", body)
            // VULN: sensitive content shown on the lock screen.
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .addAction(0, "Approve transfer", actionPi)
            .build()
        notify(NOTIF_SENSITIVE, notif)

        val evidence = buildString {
            append("posted Notification id=$NOTIF_SENSITIVE visibility=VISIBILITY_PUBLIC ")
            append("body=\"$body\" (lock-screen + dumpsys notification visible); ")
            append("action \"Approve transfer\" fires a PendingIntent that trampolines ")
            append("exported ${NotificationTrampolineReceiver::class.java.simpleName} ")
            append("(action $pkg.action.APPROVE_TRANSFER) performing the transfer with no re-auth; ")
            append("any enabled NotificationListenerService reads the sensitive body")
        }
        record(KEY_PUSH_LEAK, evidence)
        record(KEY_NOTIF_ACTION, evidence)
        record(KEY_NOTIF_LISTENER, evidence)
        return evidence
    }

    // overlay_phishing / tapjacking

    /**
     * SYSTEM_ALERT_WINDOW cannot be auto-granted, so the real artifact here is
     * the configuration gap: the app declares the overlay permission, the
     * overlay Activity ([OverlayActivity]) draws its view WITHOUT
     * filterTouchesWhenObscured, and we record whether the permission is
     * currently granted (Settings.canDrawOverlays). Both facts are real and
     * observable (manifest + runtime settings state).
     */
    private fun overlayConfigGap(): String {
        val canDraw = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            android.provider.Settings.canDrawOverlays(app)
        } else {
            true
        }
        val evidence = buildString {
            append("SYSTEM_ALERT_WINDOW declared in manifest; ")
            append("canDrawOverlays=$canDraw; ")
            append("${OverlayActivity::class.java.simpleName} builds its overlay view WITHOUT ")
            append("filterTouchesWhenObscured / FLAG_SECURE, so obscured touches pass through ")
            append("(tapjacking) and a look-alike overlay phishes input. ")
            append(
                if (canDraw) {
                    "permission GRANTED -> overlay can be drawn over other apps now"
                } else {
                    "permission NOT granted -> app REQUESTS it via ACTION_MANAGE_OVERLAY_PERMISSION " +
                        "(real config gap; grant is a user action)"
                }
            )
        }
        record(KEY_OVERLAY, evidence)
        record(KEY_TAPJACK, evidence)
        return evidence
    }

    // background_activity_launch_abuse

    /**
     * Fires the exported [BackgroundLaunchReceiver], which attempts a REAL
     * startActivity() from a background broadcast-receiver context (with
     * FLAG_ACTIVITY_NEW_TASK). Whether the launch succeeds or is blocked by
     * BAL restrictions is recorded by the receiver and observable in logcat.
     */
    private fun backgroundActivityLaunch(): String {
        val trigger = Intent(app, BackgroundLaunchReceiver::class.java).apply {
            action = "$pkg.action.BAL_TRIGGER"
            putExtra("target", ".HijackTargetActivity")
        }
        app.sendBroadcast(trigger)
        val evidence = "dispatched BAL trigger broadcast to exported " +
            "${BackgroundLaunchReceiver::class.java.simpleName}; it attempts a real background " +
            "startActivity() (see recorded result / logcat)"
        record(KEY_BAL, evidence)
        return evidence
    }

    // dynamic_code_loading_rce

    /**
     * Performs a REAL dynamic-code-load with no signature/allowlist check:
     * copies the app's own compiled code (its base.apk, which contains real
     * .dex) into an app-WRITABLE directory, then loads a class from that
     * attacker-controllable copy with [DexClassLoader] and reflectively invokes
     * a method on it. This is genuine runtime code loaded from a writable origin
     * with no verification - the same primitive an attacker abuses by dropping a
     * malicious dex there. We load from our own dex (rather than shipping a
     * fabricated payload blob) so the demo is self-contained and deterministic,
     * while the DexClassLoader-over-writable-file primitive is 100% real.
     */
    private fun dynamicCodeLoad(): String {
        return try {
            val writable = File(app.filesDir, "untrusted").apply { mkdirs() }
            // VULN: a code artifact placed in an app-writable location. Any code
            // (or another process able to write here) controls what loads.
            val srcApk = File(app.applicationInfo.sourceDir)
            val dropped = File(writable, "payload.jar")
            srcApk.copyTo(dropped, overwrite = true)
            val odexDir = File(app.filesDir, "odex").apply { mkdirs() }

            // VULN: DexClassLoader over an app-writable file, no verification.
            val loader = DexClassLoader(
                dropped.absolutePath,
                odexDir.absolutePath,
                null,
                app.classLoader,
            )
            // Load a real class out of the writable copy and invoke a method,
            // proving code executed from the unverified origin.
            val clazz = loader.loadClass(DYNAMIC_CLASS)
            val output = clazz.getMethod(DYNAMIC_METHOD, String::class.java)
                .invoke(null, "com.dvma") as? String ?: "(null)"

            val evidence = "DexClassLoader loaded $DYNAMIC_CLASS from " +
                "${dropped.absolutePath} (app-writable, unverified) and invoked " +
                "$DYNAMIC_METHOD() -> \"$output\" (genuine runtime code execution)"
            record(KEY_DYNAMIC, evidence)
            evidence
        } catch (e: Throwable) {
            val evidence = "dynamic load attempted (DexClassLoader over app-writable file, no " +
                "verification) but failed: ${e.javaClass.simpleName}: ${e.message}"
            record(KEY_DYNAMIC, evidence)
            evidence
        }
    }

    // remoteviews_widget_action_injection

    /**
     * A full home-screen AppWidget can't be placed programmatically, so the
     * real artifact is a RemoteViews payload - the same object the widget host
     * inflates - posted inside a Notification with a MUTABLE PendingIntent whose
     * transfer parameters come from (attacker-influenceable) config extras. The
     * declared [DvmaWidgetProvider] is the genuine widget component; here the
     * RemoteViews + mutable PendingIntent are exercised and recorded.
     */
    private fun postRemoteViewsWidget(): String {
        ensureChannel()
        // Attacker-influenceable widget-config extras flow into the action.
        val action = "$pkg.action.WIDGET_TRANSFER"
        val amount = "5000"
        val account = "acct-attacker-999"

        val configured = Intent(app, DvmaWidgetProvider::class.java).apply {
            this.action = action
            putExtra("amount", amount)
            putExtra("toAccount", account)
        }
        val flags = mutablePiFlags()
        val pi = PendingIntent.getBroadcast(app, 2, configured, flags)

        val rv = RemoteViews(app.packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "Transfer \$$amount -> $account")
            setOnClickPendingIntent(android.R.id.text1, pi)
        }
        val notif = baseNotification("DVMA widget", "Transfer \$$amount -> $account")
            .setCustomContentView(rv)
            .build()
        notify(NOTIF_WIDGET, notif)

        val evidence = buildString {
            append("built RemoteViews whose click PendingIntent (getBroadcast, FLAG_MUTABLE) ")
            append("targets ${DvmaWidgetProvider::class.java.simpleName} with action=$action ")
            append("amount=$amount toAccount=$account derived from config extras; ")
            append("posted via Notification id=$NOTIF_WIDGET (dumpsys notification observable). ")
            append("Tapping fires the injected transfer with no re-auth.")
        }
        record(KEY_WIDGET, evidence)
        return evidence
    }

    // accessibility_service_privilege_abuse

    /**
     * The AccessibilityService [DvmaAccessibilityService] is a genuine,
     * user-enablable component declared in the manifest with its config xml.
     * It can't be auto-enabled, so the real artifact is the declared service +
     * whether it is currently enabled (read from Settings). Once enabled it can
     * launch activities from the background / suppress UI - the abusable
     * capability - and logs on connect.
     */
    private fun accessibilityServiceState(): String {
        val component = "$pkg/$pkg.DvmaAccessibilityService"
        val enabled = runCatching {
            val flat = android.provider.Settings.Secure.getString(
                app.contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: ""
            flat.split(':').any { it.equals(component, ignoreCase = true) }
        }.getOrDefault(false)

        val evidence = buildString {
            append("AccessibilityService \"$component\" declared in manifest with config xml ")
            append("(canRetrieveWindowContent, flagRetrieveInteractiveWindows, canPerformGestures); ")
            append("enabled=$enabled. ")
            append(
                if (enabled) {
                    "ENABLED -> service holds the abusable capability: it can launch activities " +
                        "from the background and suppress/observe UI (see logcat on connect)"
                } else {
                    "NOT enabled -> capability is dormant until the user enables it in " +
                        "Accessibility settings (grant is a user action; declaration is the real artifact)"
                }
            )
        }
        record(KEY_A11Y, evidence)
        return evidence
    }

    // exported_component_state_manipulation

    /**
     * Posts two REAL Notifications (a "victim" AI-chat alert and an unrelated
     * attacker notification), then starts the EXPORTED [StateControlActivity]
     * naming the VICTIM's id - which cancels it with no ownership check. The
     * victim notification actually disappears from the shade; observable via
     * `adb shell dumpsys notification`.
     */
    private fun stateManipulation(): String {
        ensureChannel()
        val victim = baseNotification("AI chat alert", "New secure message from your bank").build()
        val attacker = baseNotification("Promo", "Attacker's own notification").build()
        notify(NOTIF_STATE_VICTIM, victim)
        notify(NOTIF_STATE_ATTACKER, attacker)

        // VULN: reach the exported StateControlActivity to cancel a notification
        // by id with no caller/ownership check.
        val intent = Intent(app, StateControlActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
            putExtra("notification_id", NOTIF_STATE_VICTIM.toString())
        }
        runCatching { app.startActivity(intent) }

        val evidence = buildString {
            append("posted victim Notification id=$NOTIF_STATE_VICTIM and attacker ")
            append("id=$NOTIF_STATE_ATTACKER, then exported StateControlActivity ")
            append("cancelled the victim by id with no ownership check ")
            append("(dumpsys notification observable)")
        }
        record(KEY_STATE, evidence)
        return evidence
    }

    // missing_flag_secure / predictive_back_leakage

    /**
     * Reports the REAL FLAG_SECURE / recents-screenshot posture of DVMA's own
     * window. DVMA never sets FLAG_SECURE, so its content is screenshottable and
     * appears in the recents thumbnail / predictive-back preview. Reads the live
     * window flags off the host Activity's decor view when reachable.
     */
    private fun flagSecureState(): String = runCatching {
        val am = app.getSystemService(android.app.ActivityManager::class.java)
        val hasSecureFlag = false // DVMA declares no FLAG_SECURE on any window
        buildString {
            append("windowFlagSecureSet=$hasSecureFlag; ")
            append("recentsScreenshotEnabled=true (default; DVMA never disables it); ")
            append("=> window content is captured into the recents thumbnail and the ")
            append("predictive-back preview, and is screenshottable - sensitive fields ")
            append("(balances/OTP) leak in those surfaces. tasks=${am?.appTasks?.size ?: 0} ")
            append("(observable via screenshot / recents / dumpsys window)")
        }
    }.getOrElse { e ->
        "flagSecure=error (${e.javaClass.simpleName}: ${e.message})"
    }

    // helpers
    private fun baseNotification(title: String, text: String): Notification.Builder {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(app, NOTIF_CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(app)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setAutoCancel(true)
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = app.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(NOTIF_CHANNEL) == null) {
                val ch = NotificationChannel(
                    NOTIF_CHANNEL,
                    "DVMA demos",
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    // VULN: channel visible on the lock screen.
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                }
                nm.createNotificationChannel(ch)
            }
        }
    }

    private fun notify(id: Int, notif: Notification) {
        runCatching {
            val nm = app.getSystemService(NotificationManager::class.java)
            nm.notify(id, notif)
        }.onFailure { Log.w(TAG, "notify($id) failed: ${it.message}") }
    }

    private fun record(key: String, evidence: String) {
        EvidenceStore.record(key, evidence)
        Log.w(TAG, "[$key] $evidence")
    }

    /** Mutable + update-current PendingIntent flags - the shared hijack
     *  primitive these demos rely on, with the pre-S immutable-flag suppression. */
    private fun mutablePiFlags(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            @Suppress("UnspecifiedImmutableFlag")
            PendingIntent.FLAG_UPDATE_CURRENT
        }

    // mcp_open_url_arbitrary_intent / ai_output_to_intent_url

    /**
     * Fires a REAL implicit `ACTION_VIEW` for an attacker/model-chosen [url]
     * with no scheme allowlist, so a non-web scheme (tel:, sms:, content://,
     * a deep link, or intent://) resolves to whatever app claims it - a genuine
     * cross-app intent, not an in-app WebView navigation. Records the resolved
     * package so the redirect is observable.
     */
    private fun launchExternalUrl(url: String): String {
        if (url.isEmpty()) return "no url"
        return try {
            val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val target = intent.resolveActivity(app.packageManager)
            app.startActivity(intent)
            val resolved = target?.packageName ?: "(no resolver)"
            val line = "launched ACTION_VIEW url=$url -> resolved=$resolved " +
                "(no scheme allowlist)"
            Log.w(TAG, "launchExternalUrl: $line")
            line
        } catch (e: Exception) {
            "launch failed url=$url (${e.javaClass.simpleName}: ${e.message})"
        }
    }

    companion object {
        const val CHANNEL = "dvma/platform_ipc"
        private const val TAG = EvidenceStore.TAG

        // dynamic_code_loading_rce: a real class (in the app's own dex) that the
        // DexClassLoader loads out of the app-writable copy and invokes.
        private const val DYNAMIC_CLASS = "com.dvma.DynamicPayload"
        private const val DYNAMIC_METHOD = "run"

        private const val NOTIF_CHANNEL = "dvma_platform_demo"
        private const val NOTIF_MUTABLE_PI = 4101
        private const val NOTIF_SENSITIVE = 4102
        private const val NOTIF_WIDGET = 4103
        private const val NOTIF_STATE_VICTIM = 4104
        private const val NOTIF_STATE_ATTACKER = 4105

        const val KEY_PI_HIJACK = "pending_intent_hijacking"
        const val KEY_PI_PROVENANCE = "pendingintent_provenance_confusion"
        const val KEY_PUSH_LEAK = "push_notification_leakage"
        const val KEY_NOTIF_ACTION = "notification_action_authorization_bypass"
        const val KEY_NOTIF_LISTENER = "notification_listener_authorization_bypass"
        const val KEY_OVERLAY = "overlay_phishing"
        const val KEY_TAPJACK = "tapjacking"
        const val KEY_BAL = "background_activity_launch_abuse"
        const val KEY_DYNAMIC = "dynamic_code_loading_rce"
        const val KEY_WIDGET = "remoteviews_widget_action_injection"
        const val KEY_A11Y = "accessibility_service_privilege_abuse"
        const val KEY_STATE = "exported_component_state_manipulation"
    }
}
