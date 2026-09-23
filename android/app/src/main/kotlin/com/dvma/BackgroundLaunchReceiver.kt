package com.dvma

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * background_activity_launch_abuse (CWE-284 / CWE-940, Android BAL CVE class).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An EXPORTED receiver that attempts a REAL startActivity() from a background
 * broadcast-receiver context. On older platforms (or when the app is granted a
 * BAL exemption) the launch succeeds and a security-sensitive UI is surfaced
 * with no foreground task; on locked-down platforms the framework blocks it.
 * Either outcome is recorded and observable in logcat - the launch is genuine,
 * not simulated.
 */
class BackgroundLaunchReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val targetClass = intent.getStringExtra("target") ?: ".HijackTargetActivity"
        val launch = Intent().apply {
            setClassName(context.packageName, context.packageName + targetClass)
            // Required to start an Activity from a non-Activity (background) context.
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("origin", "background-receiver")
        }
        val result = runCatching {
            // VULN: no BAL restriction respected - attempt to surface a
            // security-sensitive activity from the background.
            context.startActivity(launch)
            "startActivity() from background receiver SUCCEEDED -> " +
                "${launch.component?.className} surfaced with no foreground task"
        }.getOrElse { e ->
            "startActivity() from background receiver was BLOCKED by BAL policy: " +
                "${e.javaClass.simpleName}: ${e.message}"
        }
        EvidenceStore.record(KEY, result)
        Log.w(TAG, result)
    }

    companion object {
        const val KEY = "background_activity_launch_abuse"
        private const val TAG = EvidenceStore.TAG
    }
}
