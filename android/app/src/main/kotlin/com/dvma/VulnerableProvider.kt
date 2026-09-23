package com.dvma

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

/**
 * VulnerableProvider - an intentionally-insecure, EXPORTED ContentProvider.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * This is a REAL Android ContentProvider (authority
 * `${applicationId}.provider.vuln`) so it is genuinely reachable by
 * `adb shell content query/read`, drozer, and a co-resident companion app -
 * not a pure-Dart in-memory simulation. It intentionally implements several
 * documented CWEs:
 *
 *  1. content_provider_sql_injection (CWE-89): [query] builds SQL by STRING
 *     CONCATENATION of the caller-supplied selection over a real
 *     [SQLiteDatabase], so a `UNION SELECT secret` / tautology selection
 *     exfiltrates the secret column. The same unhardened concatenation lets a
 *     caller use a balanced sub-query as a boolean oracle
 *     (contacts_provider_blind_sqli_oracle, CVE-2026-28576 class).
 *  2. incoming_call_metadata_missing_authorization (CWE-862 / CWE-200): the
 *     `calls` path returns a seeded call-log row (number + metadata) with NO
 *     permission check, so any caller reads it with no grant (CVE-2026-0057
 *     class).
 *  3. fileprovider_path_traversal / contentprovider_filename_path_traversal /
 *     content_uri_resolver_confused_deputy (CWE-22 / CWE-441): [openFile]
 *     joins the caller-supplied path segment under an export dir WITHOUT
 *     canonical confinement, so a `../` path escapes and returns a REAL
 *     [ParcelFileDescriptor] to arbitrary app-private files (e.g. the seeded
 *     session token / secrets file outside the export dir).
 *
 * Every effect is mirrored to [EvidenceStore] (read back by Flutter over the
 * `dvma/provider_ipc` channel) and to logcat under `DVMA-EVIDENCE`, matching
 * the read-back pattern the exported-Activity/Service modules already use.
 */
class VulnerableProvider : ContentProvider() {

    private lateinit var helper: DbHelper

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        helper = DbHelper(ctx.applicationContext)
        // Seed the traversal fixtures on the real filesystem so a `../` request
        // resolves to genuine files off the export dir.
        seedTraversalFixtures(ctx.applicationContext)
        return true
    }

    // content_provider_sql_injection (CWE-89)

    /**
     * VULN: builds the WHERE clause by concatenating the caller-supplied
     * [selection] straight into the SQL string instead of binding it with
     * `selectionArgs`. A caller (drozer / `adb shell content query`) supplying
     * a `UNION SELECT secret --` or `' OR '1'='1` selection exfiltrates the
     * secret column that a normal query would never expose.
     *
     * Example:
     *   adb shell content query --uri content://com.dvma.provider.vuln/users \
     *     --where "name='x' UNION SELECT id, secret FROM users --"
     */
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        // incoming_call_metadata_missing_authorization (CWE-862 / CWE-200):
        // the `calls` path returns call metadata with NO permission check.
        if (uriMatcher.match(uri) == MATCH_CALLS) return queryCalls()

        val db = helper.readableDatabase
        // VULN: rawQuery with the selection concatenated into the SQL text.
        val where = if (selection.isNullOrEmpty()) "1=1" else selection
        val sql = "SELECT id, name FROM users WHERE $where"
        val evidence = "content_provider_sql_injection query :: $sql"
        EvidenceStore.record(KEY_SQLI, evidence)
        Log.w(TAG, evidence)
        return try {
            // No selectionArgs binding - the injection lives in `sql`.
            db.rawQuery(sql, null)
        } catch (t: Throwable) {
            // Surface the failed SQL so the injection is still observable.
            val err = "content_provider_sql_injection error :: ${t.message} :: $sql"
            EvidenceStore.record(KEY_SQLI, err)
            Log.w(TAG, err)
            MatrixCursor(arrayOf("id", "name")).apply {
                addRow(arrayOf<Any?>(-1, "SQL error: ${t.message}"))
            }
        }
    }

    // incoming_call_metadata_missing_authorization (CWE-862 / CWE-200)

    /**
     * VULN: returns a seeded incoming-call row (number + metadata) with NO
     * caller permission check, so a permission-less app reads private call
     * metadata with no user interaction:
     *
     *   adb shell content query --uri content://com.dvma.provider.vuln/calls
     *
     * A hardened provider would enforce READ_CALL_LOG / a signature permission
     * before returning any row.
     */
    private fun queryCalls(): Cursor {
        val cursor = MatrixCursor(arrayOf("number", "contact", "timestamp", "direction"))
        cursor.addRow(
            arrayOf<Any?>(
                "+1-202-555-0173",
                "Dr. Reyes (cardiology)",
                "2026-09-12T13:41:07Z",
                "INCOMING",
            ),
        )
        val evidence =
            "incoming_call_metadata_missing_authorization query /calls :: " +
                "returned call metadata with NO permission check"
        EvidenceStore.record(KEY_CALL_METADATA, evidence)
        Log.w(TAG, evidence)
        return cursor
    }

    // fileprovider_path_traversal / contentprovider_filename_path_traversal /
    // content_uri_resolver_confused_deputy (CWE-22 / CWE-441)

    /**
     * VULN: resolves the URI path against the export dir with NO canonical
     * confinement, then returns a REAL read-only [ParcelFileDescriptor] for the
     * resolved file. A `content://.../files/../session.token` URI therefore
     * escapes the export dir and hands the caller an FD to an app-private file.
     *
     * Example:
     *   adb shell content read \
     *     --uri content://com.dvma.provider.vuln/files/../session.token
     */
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val ctx = context ?: return null
        val exportDir = exportDir(ctx.applicationContext)
        // Everything after the leading "/files" path prefix is the requested
        // (attacker-controlled) relative path.
        val requested = uri.path?.removePrefix("/files/")?.removePrefix("/files")
            ?: ""
        // VULN: naive join - no getCanonicalPath() confinement check.
        val target = File(exportDir, requested)
        val resolved = target.canonicalPath
        val evidence =
            "contentprovider_filename_path_traversal openFile :: requested=$requested " +
                ":: resolved=$resolved (no confinement to ${exportDir.canonicalPath})"
        EvidenceStore.record(KEY_TRAVERSAL, evidence)
        Log.w(TAG, evidence)
        return ParcelFileDescriptor.open(
            target,
            ParcelFileDescriptor.MODE_READ_ONLY,
        )
    }

    override fun getType(uri: Uri): String? = "application/octet-stream"

    // Unused write surfaces - kept minimal.
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    override fun delete(
        uri: Uri,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    /** SQLite helper seeding a `users` table whose `secret` column is sensitive. */
    private class DbHelper(context: Context) :
        SQLiteOpenHelper(context, DB_NAME, null, 1) {

        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE users (" +
                    "id INTEGER PRIMARY KEY, name TEXT, secret TEXT)",
            )
            // A secret row the provider's public projection must never expose,
            // but the concatenated SQLi path can UNION out.
            db.execSQL(
                "INSERT INTO users (id, name, secret) VALUES " +
                    "(1, 'alice', 'DVMA{alice_secret}')," +
                    "(2, 'bob', 'DVMA{bob_secret}')," +
                    "(3, 'admin', 'DVMA{admin_flag-7f3a91}')",
            )
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS users")
            onCreate(db)
        }
    }

    companion object {
        const val KEY_SQLI = "content_provider_sql_injection"
        const val KEY_TRAVERSAL = "contentprovider_filename_path_traversal"
        const val KEY_CALL_METADATA = "incoming_call_metadata_missing_authorization"
        private const val DB_NAME = "vuln_provider.db"
        private const val TAG = EvidenceStore.TAG

        private const val MATCH_USERS = 1
        private const val MATCH_CALLS = 2

        /** Routes the provider authority's paths; `calls` is the unguarded one. */
        private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            val authority = "${BuildConfig.APPLICATION_ID}.provider.vuln"
            addURI(authority, "users", MATCH_USERS)
            addURI(authority, "calls", MATCH_CALLS)
        }

        /** The over-broad export root the provider serves files under. */
        fun exportDir(context: Context): File =
            File(context.filesDir, "provider_export").apply { mkdirs() }

        /**
         * Seeds a benign shared file INSIDE the export dir plus a session
         * token / secrets file OUTSIDE it (as siblings under filesDir), so a
         * `../` traversal from the export dir lands on real app-private files.
         */
        fun seedTraversalFixtures(context: Context) {
            runCatching {
                val export = exportDir(context)
                File(export, "report.pdf").writeText("quarterly report (public)")
                // Lives OUTSIDE the export dir (one level up), reachable via `..`.
                File(context.filesDir, "session.token")
                    .writeText("auth_token=eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION")
                File(context.filesDir, "secrets.xml").writeText(
                    "<map><string name=\"auth_token\">SECRET-9f3a</string></map>",
                )
            }
        }
    }
}
