package com.dvma

import android.content.Intent
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * DVMA (Damn Vulnerable Mobile App) host Activity.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Beyond hosting the Flutter UI, this registers native MethodChannels that let
 * specific vulnerability modules perform Android IPC across a process/trust
 * boundary - observable via logcat, the companion attacker app, or the capture
 * harness. Each channel is intentionally insecure in a way that mirrors a
 * documented CWE; see the individual handlers.
 *
 * The app package is authored once in `config/app.json` and set as the Android
 * applicationId by Gradle. Everything here derives from
 * [BuildConfig.APPLICATION_ID] rather than hardcoding it.
 */
class MainActivity : FlutterActivity() {

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        registerOtpBroadcastChannel(flutterEngine)
        BroadcastIpc(applicationContext).register(flutterEngine)
        ComponentIpc(applicationContext).register(flutterEngine)
        ProviderIpc(applicationContext).register(flutterEngine)
        ResilienceProbe(applicationContext).register(flutterEngine)
        SystemProviderProbe(applicationContext).register(flutterEngine)
        PlatformIpc(applicationContext).register(flutterEngine)
        NativeMemoryProbe().register(flutterEngine)
        NativeHeapProbe().register(flutterEngine)
        NativeMediaProbe().register(flutterEngine)
        NativeProximityProbe().register(flutterEngine)
        NativeCallMediaProbe().register(flutterEngine)
    }

    /**
     * cross_app_otp_credential_leak (CWE-926 / CWE-200).
     *
     * The vulnerable path fires an unprotected implicit broadcast carrying the
     * current OTP + auth deep link. Because the broadcast declares no receiver
     * permission, any co-resident app (different UID, no special permission)
     * can register a receiver for [actionOtp] and harvest the second factor -
     * the Authenticator CVE-2026-26123 class.
     *
     * The secure path sends the same data but restricts delivery with a
     * signature-level permission, so only an app signed with DVMA's key
     * receives it.
     */
    private fun registerOtpBroadcastChannel(flutterEngine: FlutterEngine) {
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            OTP_CHANNEL,
        ).setMethodCallHandler { call, result ->
            val otp = call.argument<String>("otp") ?: ""
            val link = call.argument<String>("link") ?: ""
            when (call.method) {
                "broadcastUnprotected" -> {
                    // VULN: implicit broadcast, no receiverPermission. Any app
                    // can receive this.
                    val intent = Intent(actionOtp).apply {
                        putExtra("otp", otp)
                        putExtra("link", link)
                        addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                    }
                    applicationContext.sendBroadcast(intent)
                    result.success("sent unprotected broadcast $actionOtp")
                }
                "broadcastSecure" -> {
                    // SECURE: gate delivery behind a signature-level permission
                    // so only an app signed with DVMA's key can receive it.
                    val intent = Intent(actionOtp).apply {
                        putExtra("otp", otp)
                        putExtra("link", link)
                    }
                    applicationContext.sendBroadcast(intent, signaturePermission)
                    result.success("sent permission-scoped broadcast $actionOtp")
                }
                else -> result.notImplemented()
            }
        }
    }

    /** The unprotected action a malicious co-resident app listens for. */
    private val actionOtp: String
        get() = "${BuildConfig.APPLICATION_ID}.action.OTP_ISSUED"

    /** Signature-level permission gating the secure delivery path. */
    private val signaturePermission: String
        get() = "${BuildConfig.APPLICATION_ID}.permission.RECEIVE_OTP"

    private companion object {
        const val OTP_CHANNEL = "dvma/otp_broadcast"
    }
}
