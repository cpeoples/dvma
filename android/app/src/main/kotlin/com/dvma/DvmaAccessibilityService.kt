package com.dvma

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent

/**
 * accessibility_service_privilege_abuse (CWE-284 / CWE-269).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A genuine, user-enablable AccessibilityService declared in the manifest with
 * its config xml (res/xml/dvma_accessibility_config.xml). It cannot be
 * auto-enabled, so the real artifact is the declared service + the abusable
 * capability it is granted once enabled: it requests window content and gesture
 * capabilities that let a malicious service launch activities from the
 * background, suppress security prompts, or inject clicks with no per-action
 * validation. On connect and on events it logs under the evidence tag.
 */
class DvmaAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        val evidence = "DvmaAccessibilityService connected: holds canRetrieveWindowContent + " +
            "canPerformGestures; from here a background activity launch / UI suppression / gesture " +
            "injection runs with no per-action validation (a11y privilege-abuse capability granted)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Observe the focused window/package - the read side of the abusable
        // capability. Recorded so an enabled service is visible in logcat.
        val pkg = event?.packageName?.toString() ?: return
        Log.w(TAG, "a11y event type=${event.eventType} from package=$pkg (window content observable)")
    }

    override fun onInterrupt() {}

    companion object {
        const val KEY = "accessibility_service_privilege_abuse"
        private const val TAG = EvidenceStore.TAG
    }
}
