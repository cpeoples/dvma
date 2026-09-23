package com.dvma

import android.app.Activity
import android.app.NotificationManager
import android.content.Context
import android.os.Bundle
import android.util.Log

/**
 * exported_component_state_manipulation (Datadog Android CVE-2026-47361).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity that performs a state change (cancelling a notification
 * named by an extra) with no caller/ownership check. A separate app (or DVMA's
 * own module driving it in-process) names the victim's notification id and DVMA
 * mutates state on its behalf.
 */
class StateControlActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val notifId = intent.getStringExtra("notification_id") ?: "(none)"
        // VULN: cancel the named notification with no ownership check.
        val cancelled = notifId.toIntOrNull()?.let { id ->
            runCatching {
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            }.getOrNull()?.let { nm ->
                runCatching { nm.cancel(id); true }.getOrDefault(false)
            } ?: false
        } ?: false
        val evidence =
            "cancelled notification id=$notifId (applied=$cancelled) for caller=$caller " +
                "(no ownership check)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "exported_component_state_manipulation"
        private const val TAG = EvidenceStore.TAG
    }
}
