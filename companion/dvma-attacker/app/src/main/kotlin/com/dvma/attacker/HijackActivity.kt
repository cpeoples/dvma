package com.dvma.attacker

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.TextView

/**
 * activity_task_stack_hijacking (StrandHogg class).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * This activity declares taskAffinity="com.dvma" + allowTaskReparenting in the
 * manifest, so it can be placed into DVMA's task. When it appears there, the
 * attacker's UI looks like it belongs to DVMA (a phishing overlay). It records
 * that it landed; the placement is observable in `dumpsys activity activities`.
 */
class HijackActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "Attacker screen (task-stack hijack demo)"
            gravity = Gravity.CENTER
            setPadding(32, 64, 32, 32)
        })
        val line = "HIJACK attacker activity launched with taskAffinity=com.dvma"
        Log.w(TAG, line)
        AttackerCapture.record(line)
    }

    private companion object {
        const val TAG = "DVMA-ATTACKER"
    }
}
