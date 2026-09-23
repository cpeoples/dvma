package com.dvma

import android.inputmethodservice.InputMethodService
import android.util.Log
import android.view.View
import android.widget.TextView

/**
 * custom_keyboard_input_interception (CWE-522 / CWE-359 / CWE-829).
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A REAL, user-enablable [InputMethodService]. A custom keyboard / IME is a
 * privileged system provider: once the user enables it in Settings and selects
 * it, it receives EVERY keystroke typed across OTHER apps - including passwords
 * and OTPs in secure fields. Combined with network egress ("Allow Full Access"
 * on iOS; unrestricted INTERNET on Android) and no isolation, such a keyboard
 * can log and exfiltrate that input.
 *
 * Enabling + selecting an IME is a user grant that a lab cannot auto-provision,
 * so this class exists to make the capability GENUINELY declared and enablable
 * (it shows up under Settings > System > Languages & input > On-screen
 * keyboards). It intentionally does not build a full keyboard UI or actually
 * exfiltrate; on start it emits a real logcat evidence line proving the IME was
 * activated and would see all input. The Dart module reports the enabled-IME
 * state from Settings.Secure and records the artifact.
 */
class DvmaKeyboardService : InputMethodService() {

    override fun onCreateInputView(): View {
        // A minimal, real input view. A malicious keyboard would render a full
        // keyboard here and capture/relay every key event it receives.
        return TextView(this).apply {
            text = "DVMA training keyboard (input-interception demo)"
            setPadding(24, 24, 24, 24)
        }
    }

    override fun onStartInput(attribute: android.view.inputmethod.EditorInfo?, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        // REAL evidence: this IME is now the active input method for a field in
        // some (possibly other) app. inputType reveals whether it is a password
        // field - exactly the secure input a rogue keyboard should never see.
        val inputType = attribute?.inputType ?: 0
        val pkg = attribute?.packageName ?: "unknown"
        Log.w(
            TAG,
            "[custom_keyboard_input_interception] IME active :: targetPackage=$pkg :: " +
                "inputType=$inputType :: a rogue keyboard would capture every keystroke here",
        )
    }

    private companion object {
        const val TAG = EvidenceStore.TAG
    }
}
