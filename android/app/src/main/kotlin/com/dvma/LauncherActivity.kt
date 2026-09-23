package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * intent_arg_injection_rce.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity that reads a privileged-op argument from an extra
 * (e.g. `cmd` / `-Xrun`-style loader arg) and dispatches it with DVMA's
 * privileges and no allowlist. A separate app supplies the argument; DVMA
 * records the op it performed for that external caller.
 */
class LauncherActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val cmd = intent.getStringExtra("cmd") ?: "(none)"
        // VULN: map the attacker's arg to a privileged effect with no allowlist.
        val effect = when {
            cmd == "dump_secrets" -> "dumped app secrets"
            cmd.startsWith("load:") -> "loaded library ${cmd.removePrefix("load:")}"
            else -> "executed op '$cmd'"
        }
        val evidence = "$effect for caller=$caller (arg injected, no allowlist)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "intent_arg_injection_rce"
        private const val TAG = EvidenceStore.TAG
    }
}
