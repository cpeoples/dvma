package com.dvma.attacker

import android.content.Intent
import android.util.Log

/**
 * Sends spoofed/forged broadcasts to DVMA's exported receivers.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * The receive-side broadcast modules (exported_broadcast_receiver_spoof,
 * dynamic_broadcast_receiver_exposure) rely on DVMA registering a receiver that
 * any app can reach. This helper lets the (separately-signed, unprivileged)
 * attacker app fire those broadcasts with attacker-controlled extras - a
 * cross-process send, driven by the harness via `am start`/extras.
 */
object BroadcastForger {

    const val TAG = "DVMA-ATTACKER"

    /**
     * Fire [action] at DVMA with [extras]. If [target] is non-null the broadcast
     * is explicit (targeted at DVMA's receiver component); otherwise it is an
     * implicit action-only broadcast, mirroring how a real attacker probes an
     * exported receiver.
     */
    fun send(
        ctx: android.content.Context,
        action: String,
        extras: Map<String, String>,
        target: String? = null,
    ) {
        val intent = Intent(action).apply {
            if (target != null) setClassName(Dvma.PKG, target)
            addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
            for ((k, v) in extras) putExtra(k, v)
        }
        ctx.sendBroadcast(intent)
        Log.w(TAG, "SENT spoofed broadcast action=$action extras=$extras target=$target")
    }
}
