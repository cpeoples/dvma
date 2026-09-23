package com.dvma

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Native broadcast IPC surfaces for the broadcast-based vulnerability
 * modules. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Two directions are exercised, matching how these classes present on-device:
 *
 *  - Receive-side: DVMA registers an exported / implicitly-exported receiver
 *    that applies attacker-controlled extras. A separate app sends the
 *    broadcast (see the companion attacker's BroadcastForger). Dart reads back
 *    the applied state via [applied].
 *
 *  - Send-side: DVMA emits a broadcast the companion attacker receives or
 *    reorders - an implicit intent carrying sensitive extras, and an ordered
 *    broadcast whose result a higher-priority receiver rewrites.
 *
 * The action/permission names derive from [BuildConfig.APPLICATION_ID] so the
 * two apps agree without hardcoding the package.
 */
class BroadcastIpc(private val app: Context) {

    private val pkg get() = BuildConfig.APPLICATION_ID
    private val signaturePermission get() = "$pkg.permission.RECEIVE_OTP"

    // Actions the companion attacker also references (mirrored from Dvma.kt).
    private val actionLocation get() = "$pkg.action.LOCATION_UPDATE"
    private val actionPromo get() = "$pkg.action.APPLY_PROMO"
    private val actionShareSession get() = "$pkg.action.SHARE_SESSION"
    private val actionEntitlement get() = "$pkg.action.ENTITLEMENT_CHECK"
    private val actionRoleDelegate get() = "$pkg.action.ROLE_DELEGATE"

    /** Last extras applied by a receive-side receiver, keyed by action. */
    private val appliedState = mutableMapOf<String, String>()

    fun register(engine: FlutterEngine) {
        registerReceiveSideReceivers()
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result -> handle(call.method, call.arguments, result) }
    }

    private fun handle(method: String, args: Any?, result: MethodChannel.Result) {
        @Suppress("UNCHECKED_CAST")
        val map = (args as? Map<String, Any?>) ?: emptyMap()
        when (method) {
            // exported_broadcast_receiver_spoof / dynamic_broadcast_receiver_exposure:
            // read back what the exported receiver applied from the attacker's send.
            "applied" -> result.success(appliedState[map["action"] as? String])

            // implicit_intent_sensitive_data: emit an implicit intent naming only
            // an action, so every app with a matching filter receives the extras.
            "broadcastImplicitSensitive" -> {
                val extras = stringExtras(map["extras"])
                val intent = Intent(actionShareSession).apply {
                    addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                    for ((k, v) in extras) putExtra(k, v)
                }
                app.sendBroadcast(intent)
                result.success("broadcast implicit $actionShareSession")
            }
            // Secure counterpart: address the broadcast to DVMA's own package.
            "broadcastExplicitSensitive" -> {
                val extras = stringExtras(map["extras"])
                val intent = Intent(actionShareSession).apply {
                    setPackage(pkg)
                    for ((k, v) in extras) putExtra(k, v)
                }
                app.sendBroadcast(intent)
                result.success("broadcast explicit to $pkg")
            }

            // ordered_broadcast_result_injection: send an ordered broadcast with
            // a final receiver that reports the (possibly rewritten) result. A
            // higher-priority receiver in another app can setResultData() first.
            "sendOrdered" -> {
                val seed = map["seed"] as? String ?: ""
                app.sendOrderedBroadcast(
                    Intent(actionEntitlement),
                    null,
                    finalResultReceiver(actionEntitlement),
                    null,
                    0,
                    seed,
                    null,
                )
                result.success("sent ordered broadcast $actionEntitlement seed=$seed")
            }
            // Secure counterpart: guard the ordered broadcast with a signature
            // permission so an unsigned receiver never runs.
            "sendOrderedGuarded" -> {
                val seed = map["seed"] as? String ?: ""
                app.sendOrderedBroadcast(
                    Intent(actionEntitlement),
                    signaturePermission,
                    finalResultReceiver(actionEntitlement),
                    null,
                    0,
                    seed,
                    null,
                )
                result.success("sent guarded ordered broadcast $actionEntitlement seed=$seed")
            }

            // default_role_holder_confusion: emit the role-delegation broadcast
            // implicitly; whichever app claimed the filter at higher priority
            // receives the secret.
            "delegateRole" -> {
                val secret = map["secret"] as? String ?: ""
                val intent = Intent(actionRoleDelegate).apply {
                    addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                    putExtra("secret", secret)
                }
                app.sendBroadcast(intent)
                result.success("delegated role secret via $actionRoleDelegate")
            }

            // android_capability_composition_chain: fire the REAL exported
            // ChainEntryReceiver so the mutable-PI -> receiver -> service ->
            // transfer chain runs end-to-end in-process, then read back the
            // sink's recorded outcome.
            "fireChain" -> {
                val amount = map["amount"] as? String ?: "1000.00"
                val to = map["to"] as? String ?: "attacker-account"
                val intent = Intent(ACTION_CHAIN_TRIGGER).apply {
                    setClass(app, ChainEntryReceiver::class.java)
                    putExtra("amount", amount)
                    putExtra("to", to)
                }
                app.sendBroadcast(intent)
                result.success(awaitChain())
            }

            else -> result.notImplemented()
        }
    }

    // Receive-side: DVMA's own exported receivers

    private fun registerReceiveSideReceivers() {
        // exported_broadcast_receiver_spoof: an exported receiver that trusts
        // and applies whatever extras arrive (no sender/permission check).
        registerExported(actionLocation) { intent ->
            val lat = intent.getStringExtra("lat")
            val lon = intent.getStringExtra("lon")
            val label = intent.getStringExtra("label")
            appliedState[actionLocation] = "lat=$lat lon=$lon label=$label"
            Log.w(TAG, "applied location extras: ${appliedState[actionLocation]}")
        }

        // dynamic_broadcast_receiver_exposure: a runtime receiver registered
        // WITHOUT RECEIVER_NOT_EXPORTED, so it is implicitly exported and any
        // app can drive the sensitive action (apply store credit).
        registerExported(actionPromo) { intent ->
            val code = intent.getStringExtra("code")
            val credit = intent.getStringExtra("credit")
            appliedState[actionPromo] = "promo=$code credit=$credit applied"
            Log.w(TAG, "applied promo extras: ${appliedState[actionPromo]}")
        }
    }

    private fun registerExported(action: String, onReceive: (Intent) -> Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) = onReceive(intent)
        }
        val filter = IntentFilter(action)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            app.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            app.registerReceiver(receiver, filter)
        }
    }

    private fun finalResultReceiver(action: String) = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            appliedState[action] = "finalResult=$resultData"
            Log.w(TAG, "ordered final result for $action: $resultData")
        }
    }

    private fun stringExtras(raw: Any?): Map<String, String> {
        @Suppress("UNCHECKED_CAST")
        val m = (raw as? Map<String, Any?>) ?: return emptyMap()
        return m.entries.associate { it.key to (it.value?.toString() ?: "") }
    }

    /** Poll the shared [EvidenceStore] briefly for the chain sink's outcome the
     *  exported ChainEntryReceiver records on its async broadcast thread. */
    private fun awaitChain(): String {
        val key = ChainEntryReceiver.KEY
        val deadline = System.currentTimeMillis() + 2000
        while (System.currentTimeMillis() < deadline) {
            EvidenceStore.read(key)?.let { return it }
            try {
                Thread.sleep(50)
            } catch (_: InterruptedException) {
                break
            }
        }
        return EvidenceStore.read(key)
            ?: "fired exported ChainEntryReceiver ($ACTION_CHAIN_TRIGGER); sink " +
            "outcome recorded asynchronously (see logcat DVMA-EVIDENCE)"
    }

    private companion object {
        const val CHANNEL = "dvma/broadcast_ipc"
        const val TAG = EvidenceStore.TAG
        // Matches the manifest intent-filter for the exported ChainEntryReceiver.
        const val ACTION_CHAIN_TRIGGER = "com.dvma.action.CHAIN_TRIGGER"
    }
}
