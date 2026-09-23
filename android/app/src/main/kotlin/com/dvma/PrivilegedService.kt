package com.dvma

import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.util.Log

/**
 * privileged_service_binding_exposure (Android service IPC, MASTG-KNOW-0133).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported, bindable Service exposing a privileged Messenger interface that
 * any app can bind and invoke with no caller-identity or permission check. A
 * separate app binds it and requests the protected secret / a role elevation;
 * the service performs the privileged call and (for readSecret) replies with
 * the secret over the caller's reply Messenger. Records what it did in
 * [EvidenceStore].
 */
class PrivilegedService : Service() {

    private val messenger = Messenger(IncomingHandler(Looper.getMainLooper(), this))

    // VULN: onBind returns the privileged binder to any caller, no check.
    override fun onBind(intent: Intent?): IBinder = messenger.binder

    private class IncomingHandler(
        looper: Looper,
        private val service: PrivilegedService,
    ) : Handler(looper) {
        override fun handleMessage(msg: Message) {
            when (msg.what) {
                MSG_READ_SECRET -> {
                    // Read the secret from a REAL app-private file, so the bytes
                    // handed to the (unauthenticated) bound client are genuine
                    // on-disk contents a researcher can independently adb-pull
                    // from the app sandbox and diff - not a hardcoded constant.
                    val secret = service.readOrSeedSecret()
                    val evidence = "readSecret served to bound client: $secret"
                    EvidenceStore.record(KEY, evidence)
                    Log.w(TAG, evidence)
                    // Reply to the caller's Messenger with the secret.
                    msg.replyTo?.let { reply ->
                        val out = Message.obtain(null, MSG_READ_SECRET).apply {
                            data = android.os.Bundle().apply { putString("secret", secret) }
                        }
                        runCatching { reply.send(out) }
                    }
                }
                MSG_ELEVATE_ROLE -> {
                    val evidence = "elevateRole granted to bound client (now admin)"
                    EvidenceStore.record(KEY, evidence)
                    Log.w(TAG, evidence)
                }
                else -> super.handleMessage(msg)
            }
        }
    }

    /** Reads the app-private session-key file, seeding it once if absent. */
    private fun readOrSeedSecret(): String = runCatching {
        val f = java.io.File(filesDir, SECRET_FILE)
        if (!f.exists()) f.writeText(SEED_SECRET)
        f.readText()
    }.getOrDefault(SEED_SECRET)

    companion object {
        const val KEY = "privileged_service_binding_exposure"
        const val MSG_READ_SECRET = 1
        const val MSG_ELEVATE_ROLE = 2
        private const val SECRET_FILE = "privileged_session_key.txt"
        private const val SEED_SECRET = "svc-secret://session-key=DE21-A907-8b3f"
        private const val TAG = EvidenceStore.TAG
    }
}
