package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * exported_android_components (CWE-926).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An Activity exported in the manifest with no permission guard. Any installed
 * app (or adb/drozer) can start it directly and reach the "admin panel" flow
 * that was only ever meant to be reachable from inside DVMA. On launch it
 * records the calling package into [EvidenceStore] and finishes; the Flutter
 * side reads that back over the component MethodChannel to show that an
 * external, unprivileged caller reached a privileged screen.
 */
class AdminActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // callingPackage is non-null only for startActivityForResult; fall back
        // to the referrer for a plain startActivity.
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val evidence = "admin panel opened by $caller (exported=true, no permission)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "exported_android_components"
        private const val TAG = EvidenceStore.TAG
    }
}
