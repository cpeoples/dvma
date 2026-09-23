package com.dvma

import android.content.ClipData
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Native surface for the exported-ContentProvider vulnerability modules.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * DVMA declares a real, exported [VulnerableProvider]. This MethodChannel
 * (`dvma/provider_ipc`) lets the Flutter module screens drive that provider
 * IN-PROCESS through the app's own [ContentResolver] - exercising the exact
 * code path drozer / `adb shell content` / the companion app would hit
 * cross-process - and read back the effect the provider recorded in
 * [EvidenceStore]. Every method also records its own effect so the evidence
 * panel and logcat (`DVMA-EVIDENCE`) show the real op.
 *
 * Methods:
 *  - applied(key)          read back an [EvidenceStore] entry (mirrors ComponentIpc)
 *  - sqlInject(selection)  real SQLi query() through the ContentResolver
 *  - openTraversal(name)   real openFile() `../` traversal, read the bytes back
 *  - grantUri(uri)         real Intent FLAG_GRANT_READ_URI_PERMISSION + ClipData grant
 */
class ProviderIpc(private val context: Context) {

    private val authority: String
        get() = "${BuildConfig.APPLICATION_ID}.provider.vuln"

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "applied" ->
                        result.success(EvidenceStore.read(call.argument<String>("key") ?: ""))

                    "sqlInject" -> result.success(
                        sqlInject(call.argument<String>("selection") ?: ""),
                    )

                    "callLog" -> result.success(callLog())

                    "openTraversal" -> result.success(
                        openTraversal(call.argument<String>("name") ?: ""),
                    )

                    "grantUri" -> result.success(
                        grantUri(call.argument<String>("uri")),
                    )

                    else -> result.notImplemented()
                }
            }
    }

    // content_provider_sql_injection (CWE-89)

    /**
     * Runs a REAL query against [VulnerableProvider] through the app's
     * ContentResolver, passing the attacker selection unbound so the provider
     * concatenates it into SQL. Returns the rows the injection leaked.
     */
    private fun sqlInject(selection: String): String {
        val resolver: ContentResolver = context.contentResolver
        val uri = Uri.parse("content://$authority/users")
        val rows = StringBuilder()
        try {
            // VULN: the selection is caller-controlled and passed unbound.
            resolver.query(uri, null, selection, null, null)?.use { c ->
                while (c.moveToNext()) {
                    val parts = (0 until c.columnCount).joinToString(", ") { i ->
                        "${c.getColumnName(i)}=${c.getString(i)}"
                    }
                    rows.append(parts).append('\n')
                }
            }
        } catch (t: Throwable) {
            rows.append("query error: ${t.message}")
        }
        val leaked = rows.toString().trim()
        val evidence = "sql-injection leaked rows via ContentResolver.query :: $leaked"
        EvidenceStore.record(VulnerableProvider.KEY_SQLI, evidence)
        Log.w(TAG, evidence)
        return leaked
    }

    // incoming_call_metadata_missing_authorization (CWE-862 / CWE-200)

    /**
     * Reads `content://<authority>/calls` through the app's own ContentResolver
     * - the provider returns the call-log row with NO permission check, the same
     * unguarded path `adb shell content query --uri .../calls` hits.
     */
    private fun callLog(): String {
        val resolver = context.contentResolver
        val uri = Uri.parse("content://$authority/calls")
        val rows = StringBuilder()
        try {
            resolver.query(uri, null, null, null, null)?.use { c ->
                while (c.moveToNext()) {
                    rows.append(
                        (0 until c.columnCount).joinToString(", ") { i ->
                            "${c.getColumnName(i)}=${c.getString(i)}"
                        },
                    ).append('\n')
                }
            }
        } catch (t: Throwable) {
            rows.append("query error: ${t.message}")
        }
        val leaked = rows.toString().trim()
        val evidence =
            "read incoming-call metadata with no permission check :: $leaked"
        EvidenceStore.record(VulnerableProvider.KEY_CALL_METADATA, evidence)
        Log.w(TAG, evidence)
        return leaked
    }

    // *_path_traversal / content_uri_resolver_confused_deputy (CWE-22/441)

    /**
     * Opens `content://<authority>/files/<name>` through the app's own
     * ContentResolver (confused-deputy: the resolver runs with the app's
     * identity) and reads the bytes the traversal returned. A `../session.token`
     * name escapes the export dir and reads an app-private file off disk.
     */
    private fun openTraversal(name: String): String {
        val resolver = context.contentResolver
        val uri = Uri.parse("content://$authority/files/$name")
        val bytes = try {
            resolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (t: Throwable) {
            "open error: ${t.message}".toByteArray()
        }
        val contents = bytes?.toString(Charsets.UTF_8)?.take(500) ?: "(null)"
        val evidence =
            "content-uri-resolver-confused-deputy read $uri :: $contents"
        EvidenceStore.record(VulnerableProvider.KEY_TRAVERSAL, evidence)
        EvidenceStore.record(KEY_CONFUSED_DEPUTY, evidence)
        EvidenceStore.record(KEY_FILEPROVIDER, evidence)
        Log.w(TAG, evidence)
        return contents
    }

    // grant_uri_permission_abuse / clipdata_uri_grant_leakage /
    // persistable_uri_grant_abuse / file_descriptor_capability_leakage
    // (CWE-266 / CWE-668 / CWE-927 / CWE-402)

    /**
     * Builds a REAL Intent carrying FLAG_GRANT_READ_URI_PERMISSION for a
     * private provider URI, attaches the same private URI to the Intent's
     * ClipData (the grant silently rides on every ClipData URI), and calls
     * [ContentResolver.takePersistableUriPermission] where the platform allows,
     * recording the leaked grant. This performs the provider-side / grantor-side
     * operations in-process; a full cross-app grant additionally requires the
     * companion app to receive the Intent (see companion/dvma-attacker).
     */
    private fun grantUri(uriArg: String?): String {
        val uri: Uri = Uri.parse(
            uriArg ?: "content://$authority/files/session.token",
        )
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
            Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
        // VULN: an implicit Intent whose ClipData also carries the private URI;
        // the read grant propagates to EVERY ClipData URI, not just the data
        // field, so any resolver that catches this Intent inherits read access.
        val intent = Intent(Intent.ACTION_SEND).apply {
            data = uri
            addFlags(flags)
            clipData = ClipData.newRawUri("shared", uri)
        }
        val sb = StringBuilder()
        sb.append("granted FLAG_GRANT_READ|PERSISTABLE_URI_PERMISSION on $uri; ")
        sb.append("clipData carries the same private URI (grant rides on it); ")

        // grant_uri_permission_abuse: explicitly grant the private URI to a
        // target package via the ContentResolver (the real grantor-side op).
        val target = "${BuildConfig.APPLICATION_ID}.attacker"
        try {
            context.grantUriPermission(
                target,
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
            )
            sb.append("grantUriPermission(read) -> $target; ")
        } catch (t: Throwable) {
            sb.append("grantUriPermission failed: ${t.message}; ")
        }

        // persistable_uri_grant_abuse: take a persistable permission where the
        // platform lets a grantor persist it, converting a one-shot grant into
        // a durable capability.
        try {
            context.contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
            )
            sb.append("takePersistableUriPermission(read) -> durable grant; ")
        } catch (t: Throwable) {
            sb.append("takePersistable not applicable in-process: ${t.message}; ")
        }

        val evidence = sb.toString().trim()
        // Record for every uri-grant module that reads this back.
        EvidenceStore.record(KEY_GRANT_ABUSE, evidence)
        EvidenceStore.record(KEY_CLIPDATA, evidence)
        EvidenceStore.record(KEY_PERSISTABLE, evidence)
        EvidenceStore.record(KEY_FD_LEAK, evidence)
        Log.w(TAG, evidence)
        return evidence
    }

    private companion object {
        const val CHANNEL = "dvma/provider_ipc"
        const val TAG = EvidenceStore.TAG

        const val KEY_FILEPROVIDER = "fileprovider_path_traversal"
        const val KEY_CONFUSED_DEPUTY = "content_uri_resolver_confused_deputy"
        const val KEY_GRANT_ABUSE = "grant_uri_permission_abuse"
        const val KEY_CLIPDATA = "clipdata_uri_grant_leakage"
        const val KEY_PERSISTABLE = "persistable_uri_grant_abuse"
        const val KEY_FD_LEAK = "file_descriptor_capability_leakage"
    }
}
