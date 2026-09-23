package com.dvma

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Looper
import android.os.Handler
import android.os.Message
import android.os.Messenger
import android.util.Log

/**
 * android_capability_composition_chain (CWE-441).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * The composition is the bug, not any single hop. This exported receiver is the
 * first hop: it trusts whatever triggered it and, without re-checking the
 * original caller, binds the privileged service (next hop) and drives the
 * privileged "transfer" sink. A separate app fires the trigger broadcast and
 * the unauthenticated request is laundered through the chain into a privileged
 * operation. Records the outcome in [EvidenceStore].
 */
class ChainEntryReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val amount = intent.getStringExtra("amount") ?: "1000.00"
        val to = intent.getStringExtra("to") ?: "attacker-account"
        Log.w(TAG, "chain hop 1: exported receiver triggered (amount=$amount to=$to)")

        // Hop -> bind the privileged service and drive the transfer sink,
        // trusting the predecessor hop instead of the original caller.
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                val svc = Messenger(binder)
                runCatching { svc.send(Message.obtain(null, PrivilegedService.MSG_ELEVATE_ROLE)) }
                val evidence =
                    "chain reached sink: transfer $amount -> $to performed via " +
                        "notification->PendingIntent->receiver->service (no re-auth of original caller)"
                EvidenceStore.record(KEY, evidence)
                Log.w(TAG, evidence)
                runCatching { context.applicationContext.unbindService(this) }
            }

            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        val svcIntent = Intent(context, PrivilegedService::class.java)
        val pending = goAsync()
        val bound = runCatching {
            context.applicationContext.bindService(svcIntent, conn, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (!bound) {
            EvidenceStore.record(KEY, "chain broke: could not bind privileged sink")
        }
        Handler(Looper.getMainLooper()).postDelayed({ pending.finish() }, 1500)
    }

    companion object {
        const val KEY = "android_capability_composition_chain"
        private const val TAG = EvidenceStore.TAG
    }
}
