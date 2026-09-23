package com.dvma

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Native surfaces for the exported-component vulnerability modules.
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * DVMA declares Activities/Services exported (or aliased) with no caller check.
 * These handlers let the module screens DRIVE those real components IN-PROCESS
 * through the app's own [Context] - the exact `startActivity`/`bindService`
 * path a separate app (see the companion attacker's ComponentInvoker) hits
 * cross-process - and read back the effect the component recorded in
 * [EvidenceStore]. Each active method starts the real declared component with
 * attacker-shaped extras and returns the recorded evidence; [applied] mirrors
 * the read-back pattern used for broadcasts.
 */
class ComponentIpc(private val app: Context) {

    private val pkg get() = BuildConfig.APPLICATION_ID

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result -> handle(call, result) }
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            // Read back what an exported component applied for a caller,
            // keyed by the module's vuln id.
            "applied" -> result.success(EvidenceStore.read(call.argument<String>("key") ?: ""))

            // exported_android_components: start the real exported AdminActivity.
            "startAdminActivity" -> result.success(
                startExported(".AdminActivity", AdminActivity.KEY),
            )

            // activity_alias_exposure: reach the NOT-exported ProtectedAdminActivity
            // through the exported <activity-alias> AdminAlias.
            "startViaAlias" -> result.success(
                startExported(".AdminAlias", ProtectedAdminActivity.KEY),
            )

            // exported_component_arbitrary_url_activity: start UrlDispatchActivity
            // with attacker-named target/activity extras.
            "startUrlDispatch" -> result.success(
                startExported(
                    ".UrlDispatchActivity",
                    UrlDispatchActivity.KEY,
                    bundleOf(
                        "target" to (call.argument<String>("target")
                            ?: "https://attacker.example/reset"),
                        "activity" to (call.argument<String>("activity")
                            ?: ".InternalAdminActivity"),
                    ),
                ),
            )

            // intent_arg_injection_rce: start LauncherActivity with cmd extra.
            "startLauncher" -> result.success(
                startExported(
                    ".LauncherActivity",
                    LauncherActivity.KEY,
                    bundleOf("cmd" to (call.argument<String>("cmd") ?: "dump_secrets")),
                ),
            )

            // confused_deputy_intent_validation: start DeputyActivity naming only
            // the privileged action string (no caller identity check).
            "startDeputy" -> result.success(
                startExported(
                    ".DeputyActivity",
                    DeputyActivity.KEY,
                    bundleOf(
                        "privileged_action" to DeputyActivity.PRIVILEGED_ACTION,
                        "setting" to (call.argument<String>("setting")
                            ?: "adb_enabled"),
                    ),
                ),
            )

            // intent_redirection: start the exported ProxyActivity with a nested
            // "forward" Intent targeting the NOT-exported InternalAdminActivity.
            "startRedirection" -> result.success(startRedirection())

            // activity_task_stack_hijacking: start the shared-taskAffinity
            // HijackTargetActivity (dumpsys-observable task insertion surface).
            "startTaskHijackTarget" -> result.success(
                startExported(".HijackTargetActivity", HijackTargetActivity.KEY),
            )

            // privileged_service_binding_exposure: bind the exported
            // PrivilegedService and invoke its Binder method, recording the
            // returned secret.
            "bindPrivilegedService" -> bindPrivilegedService(result)

            else -> result.notImplemented()
        }
    }

    /**
     * Starts one of DVMA's own exported components by explicit component name -
     * the same in-process path that also serves the exported cross-app surface -
     * then reads back the evidence the component recorded. Runs on a
     * NEW_TASK/CLEAR_TOP no-display Activity so it does not disturb the Flutter
     * host, and polls the [EvidenceStore] briefly for the recorded effect.
     */
    private fun startExported(
        relativeClass: String,
        evidenceKey: String,
        extras: Bundle? = null,
    ): String {
        val intent = Intent().apply {
            component = ComponentName(pkg, "$pkg$relativeClass")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
            extras?.let { putExtras(it) }
        }
        return runCatching {
            app.startActivity(intent)
            val recorded = awaitEvidence(evidenceKey)
            recorded ?: "started $relativeClass (exported, no caller check); " +
                "effect recorded asynchronously (see logcat DVMA-EVIDENCE)"
        }.getOrElse { e ->
            "start $relativeClass failed: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    /**
     * intent_redirection: start the exported ProxyActivity carrying a nested
     * Intent that targets the internal-only InternalAdminActivity, which the
     * proxy forwards with no validation.
     */
    private fun startRedirection(): String {
        val forward = Intent().apply {
            component = ComponentName(pkg, "$pkg.InternalAdminActivity")
        }
        val intent = Intent().apply {
            component = ComponentName(pkg, "$pkg.ProxyActivity")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
            putExtra("forward_intent", forward)
        }
        return runCatching {
            app.startActivity(intent)
            awaitEvidence(ProxyActivity.KEY)
                ?: "started ProxyActivity with nested forward Intent -> " +
                "InternalAdminActivity (redirection recorded asynchronously)"
        }.getOrElse { e ->
            "intent redirection failed: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    /**
     * privileged_service_binding_exposure: bind the real exported
     * [PrivilegedService] in-process and send its MSG_READ_SECRET message,
     * capturing the secret the service replies over the reply Messenger with no
     * caller/permission check.
     */
    private fun bindPrivilegedService(result: MethodChannel.Result) {
        val latch = Object()
        var replied: String? = null
        val main = Handler(Looper.getMainLooper())

        val replyMessenger = Messenger(object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                if (msg.what == PrivilegedService.MSG_READ_SECRET) {
                    synchronized(latch) {
                        replied = msg.data?.getString("secret")
                        latch.notifyAll()
                    }
                }
            }
        })

        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                val svc = Messenger(binder)
                val req = Message.obtain(null, PrivilegedService.MSG_READ_SECRET).apply {
                    replyTo = replyMessenger
                }
                runCatching { svc.send(req) }
            }

            override fun onServiceDisconnected(name: ComponentName?) {}
        }

        val svcIntent = Intent(app, PrivilegedService::class.java)
        val bound = runCatching {
            app.bindService(svcIntent, conn, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (!bound) {
            result.success("bind failed: could not bind exported PrivilegedService")
            return
        }

        // Wait briefly on a worker thread for the reply, then unbind + report.
        Thread {
            synchronized(latch) {
                if (replied == null) runCatching { latch.wait(1500) }
            }
            runCatching { app.unbindService(conn) }
            val secret = EvidenceStore.read(PrivilegedService.KEY)
            val evidence = buildString {
                append("bound exported PrivilegedService in-process (no identity/permission ")
                append("check) and invoked MSG_READ_SECRET; ")
                append("reply secret=${replied ?: "(async)"}; ")
                append(secret ?: "service recorded the served secret")
            }
            main.post { result.success(evidence) }
        }.start()
    }

    /** Poll the shared [EvidenceStore] briefly for an entry the started
     *  component records on its own Activity thread. */
    private fun awaitEvidence(key: String): String? {
        val deadline = System.currentTimeMillis() + 1200
        while (System.currentTimeMillis() < deadline) {
            EvidenceStore.read(key)?.let { return it }
            try {
                Thread.sleep(40)
            } catch (_: InterruptedException) {
                break
            }
        }
        return EvidenceStore.read(key)
    }

    private fun bundleOf(vararg pairs: Pair<String, String>): Bundle =
        Bundle().apply { for ((k, v) in pairs) putString(k, v) }

    private companion object {
        const val CHANNEL = "dvma/component_ipc"
    }
}
