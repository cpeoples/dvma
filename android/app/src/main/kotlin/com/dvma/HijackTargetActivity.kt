package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * activity_task_stack_hijacking (StrandHogg class).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A normal in-app screen that uses the default (package-named) task affinity.
 * Because a separate app can declare the SAME taskAffinity with
 * allowTaskReparenting, the attacker's activity can be placed into this task,
 * so the attacker's UI appears as if it belongs to DVMA. Records that it was
 * launched (the hijack is observable in the task stack via dumpsys).
 */
class HijackTargetActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val evidence =
            "HijackTargetActivity started with default taskAffinity=$packageName " +
                "(a co-resident app sharing this affinity can reparent into this task)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
    }

    companion object {
        const val KEY = "activity_task_stack_hijacking"
        private const val TAG = EvidenceStore.TAG
    }
}
