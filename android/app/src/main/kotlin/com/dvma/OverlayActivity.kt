package com.dvma

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.FrameLayout
import android.widget.TextView

/**
 * overlay_phishing / tapjacking (CWE-1021).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A real Activity whose sensitive "confirm" button is built WITHOUT
 * `filterTouchesWhenObscured`, so if another window (a SYSTEM_ALERT_WINDOW
 * overlay) is drawn on top, obscured touches pass straight through to the
 * hidden button (tapjacking) and a look-alike overlay can phish the input.
 * Drawing a true system overlay needs the runtime SYSTEM_ALERT_WINDOW grant
 * (a user action), so this Activity is the in-app confirm surface that is
 * missing the protection - the real config gap. Records that gap on create.
 */
class OverlayActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this)
        val label = TextView(this).apply {
            text = "Confirm transfer of \$2,500"
            setTextColor(Color.WHITE)
        }
        val confirm = Button(this).apply {
            text = "Confirm transfer"
            // VULN: no obscured-touch filtering, so a covering overlay's taps
            // pass through to this sensitive control.
            filterTouchesWhenObscured = false
            setOnClickListener {
                val evidence = "sensitive confirm tapped; filterTouchesWhenObscured=false " +
                    "(obscured touches pass through -> tapjacking / overlay phishing surface)"
                EvidenceStore.record(KEY_TAPJACK, evidence)
                EvidenceStore.record(KEY_OVERLAY, evidence)
                Log.w(TAG, evidence)
                finish()
            }
        }
        root.addView(confirm, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER,
        ))
        root.addView(label)
        setContentView(root)

        val evidence = "OverlayActivity shown; confirm button built with " +
            "filterTouchesWhenObscured=false and no FLAG_SECURE (overlay/tapjacking config gap)"
        EvidenceStore.record(KEY_OVERLAY, evidence)
        EvidenceStore.record(KEY_TAPJACK, evidence)
        Log.w(TAG, evidence)
    }

    companion object {
        const val KEY_OVERLAY = "overlay_phishing"
        const val KEY_TAPJACK = "tapjacking"
        private const val TAG = EvidenceStore.TAG
    }
}
