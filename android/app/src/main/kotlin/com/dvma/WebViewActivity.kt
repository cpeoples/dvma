package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.webkit.WebView

/**
 * cross_app_scripting.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity hosting a WebView that loads a URL supplied by the
 * caller in an extra, with JavaScript enabled and no scheme/origin allowlist.
 * A separate app supplies a `javascript:` (or arbitrary) URL and DVMA loads it
 * in the authenticated WebView context, so injected script runs in DVMA's
 * origin. Records the loaded URL for the external caller.
 */
class WebViewActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val url = intent.getStringExtra("url") ?: "about:blank"

        val web = WebView(this)
        @Suppress("SetJavaScriptEnabled")
        web.settings.javaScriptEnabled = true
        setContentView(web)
        // VULN: load whatever the caller named, including javascript: URLs, in
        // the trusted origin with no validation.
        web.loadUrl(url)

        val evidence = "loaded url='$url' in trusted WebView for caller=$caller (no scheme/origin allowlist)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
    }

    companion object {
        const val KEY = "cross_app_scripting"
        private const val TAG = EvidenceStore.TAG
    }
}
