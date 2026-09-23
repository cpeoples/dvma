package com.dvma

/**
 * dynamic_code_loading_rce payload class.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * This class ships inside the app's own dex. The [PlatformIpc] dynamic-code
 * demo copies the app's compiled code into an app-WRITABLE directory and loads
 * this class from that unverified copy via a DexClassLoader, then invokes [run]
 * reflectively. It stands in for an attacker-supplied dex dropped into a
 * writable location: the vulnerable primitive (loading + executing code from an
 * unverified, writable origin with no signature/allowlist check) is genuine and
 * runs at runtime.
 */
object DynamicPayload {
    /**
     * Invoked reflectively by the DexClassLoader over the app-writable copy.
     * Returns a marker proving untrusted, dynamically-loaded code executed.
     */
    @JvmStatic
    fun run(caller: String): String =
        "DVMA{dynamic_code_exec} - untrusted dex code ran for caller=$caller"
}
