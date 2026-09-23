package com.dvma.attacker

import java.io.File

/**
 * Tiny store for what the attacker app harvested, so the capture is observable
 * two ways: logcat (tag DVMA-ATTACKER) and an adb-pullable file in this app's
 * external files dir. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 */
object AttackerCapture {
    @Volatile
    var last: String = "(nothing captured yet)"
        private set

    /** Set by [AttackerActivity] so we can also drop a pullable artifact file. */
    @Volatile
    var externalDir: File? = null

    fun record(line: String) {
        last = line
        val dir = externalDir ?: return
        runCatching {
            val f = File(dir, "attacker_captures.txt")
            f.appendText("${System.currentTimeMillis()}\t$line\n")
        }
    }
}
