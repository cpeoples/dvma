package com.dvma

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * notification_action_authorization_bypass (CWE-862 / CWE-306).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * The EXPORTED receiver a notification action's PendingIntent trampolines to.
 * It performs the privileged "approve transfer" op purely on the strength of
 * the notification having fired it - no fresh authentication, weaker than the
 * in-app path - and records the effect. Because it is exported, any app can
 * also fire the same trampoline directly.
 */
class NotificationTrampolineReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val op = intent.getStringExtra("op") ?: "approve_transfer"
        val amount = intent.getStringExtra("amount") ?: "2500"
        val to = intent.getStringExtra("to") ?: "acct-payee-042"
        // VULN: privileged op runs with no re-auth, trusting the trampoline.
        val evidence = "notification-action trampoline performed op=$op transfer \$$amount -> $to " +
            "with NO fresh authentication (exported receiver, weaker than in-app path)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
    }

    companion object {
        const val KEY = "notification_action_authorization_bypass"
        private const val TAG = EvidenceStore.TAG
    }
}
