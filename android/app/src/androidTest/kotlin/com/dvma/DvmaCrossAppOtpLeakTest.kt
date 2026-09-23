/*
 * DvmaCrossAppOtpLeakTest.kt
 *
 * CI-grade regression for the cross_app_otp_credential_leak vertical
 * (cross-app / second-app).
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * What this proves: the vulnerability is genuinely cross-app. DVMA broadcasts
 * an OTP over an unprotected implicit broadcast, and a SEPARATE, unprivileged app
 * (com.dvma.attacker - its own package/UID/signing key) harvests it. A single
 * app cannot demonstrate this against itself, so this test drives BOTH apps:
 *
 *   1. drive DVMA to the module and tap "Broadcast OTP (unprotected)"
 *      -> DVMA's native MethodChannel really calls context.sendBroadcast(),
 *   2. launch com.dvma.attacker and read its on-screen "Latest capture" text
 *      -> ASSERT it harvested the OTP (proof the leak crossed the boundary),
 *   3. drive DVMA and tap "Broadcast OTP (permission-scoped)"
 *      -> ASSERT the attacker did NOT capture a new OTP (signature-permission
 *         gate = the fix).
 *
 * UiAutomator (not Espresso) is used because it can drive across app
 * boundaries and reads the accessibility tree where DVMA's
 * Semantics(identifier:) ids surface as resource-ids. The attacker app is a
 * plain-View app, so its TextView is read directly.
 *
 * Prerequisites:
 *   * Build + install BOTH apps first (the harness/demo script do this):
 *       flutter build apk --debug --dart-define-from-file=config/flavors/full.json
 *       adb install -r build/app/outputs/flutter-apk/app-debug.apk
 *       (cd companion/dvma-attacker && ./gradlew :app:assembleDebug)
 *       adb install -r companion/dvma-attacker/app/build/outputs/apk/debug/app-debug.apk
 *   * Run opt-in (same flag as the walk-all suite):
 *       cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true \
 *         -Pandroid.testInstrumentationRunnerArguments.class=\
 *           com.dvma.DvmaCrossAppOtpLeakTest
 *
 * If the attacker app is not installed the test is SKIPPED (assumeTrue), not
 * failed, so the default suite stays green on machines without it.
 */

package com.dvma

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.regex.Pattern

@RunWith(AndroidJUnit4::class)
class DvmaCrossAppOtpLeakTest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        assumeTrue(
            "com.dvma.attacker not installed - skipping cross-app test. " +
                "Install it: (cd companion/dvma-attacker && ./gradlew :app:assembleDebug) " +
                "&& adb install -r companion/dvma-attacker/app/build/outputs/apk/debug/app-debug.apk",
            isInstalled(ATTACKER_PKG),
        )
    }

    @Test
    fun attackerHarvestsUnprotectedOtpButNotThePermissionScopedOne() {
        // The attacker's foreground service must be live so its runtime receiver
        // is registered before DVMA fires the broadcast.
        startAttackerService()

        // --- VULN: unprotected broadcast -> attacker must harvest it ----------
        openModuleAndTap(ACTION_UNPROTECTED)
        val harvested = readAttackerCapture()
        val otp = OTP_RE.matcher(harvested).let { if (it.find()) it.group(1) else null }
        assertNotNull(
            "Attacker did not harvest an OTP after the unprotected broadcast. " +
                "Latest capture was: \"$harvested\"",
            otp,
        )
        assertTrue(
            "Attacker capture missing the auth deep link. Was: \"$harvested\"",
            harvested.contains("myauth://login"),
        )

        // --- FIX: permission-scoped broadcast -> attacker must NOT harvest ----
        openModuleAndTap(ACTION_SECURE)
        val afterSecure = readAttackerCapture()
        val secureOtp = OTP_RE.matcher(afterSecure).let { if (it.find()) it.group(1) else null }
        assertTrue(
            "Attacker unexpectedly harvested a NEW OTP on the permission-scoped " +
                "(secure) path. Before=\"$otp\" after=\"$secureOtp\"",
            secureOtp == null || secureOtp == otp,
        )
    }

    // --- Driving DVMA ---------------------------------------------------------

    /** Launch DVMA, navigate to the cross-app OTP module, tap [actionId]. */
    private fun openModuleAndTap(actionId: String) {
        // Explicitly bring DVMA to the front (the attacker task may be resident),
        // and wait for DVMA's home to actually render before touching it.
        device.executeShellCommand(
            "am start -n $DVMA_PKG/.MainActivity",
        )
        device.wait(Until.hasObject(By.pkg(DVMA_PKG).depth(0)), LAUNCH_TIMEOUT)
        // Ensure we're on the home index (a prior iteration may have left a
        // module screen on top): press back until the disclaimer banner shows.
        var guard = 0
        while (device.findObject(By.res(DISCLAIMER_ID)) == null && guard++ < 4) {
            device.pressBack()
            device.wait(Until.hasObject(By.res(DISCLAIMER_ID)), 3_000L)
        }
        device.wait(Until.hasObject(By.res(DISCLAIMER_ID)), UI_TIMEOUT)

        // The module is a medium-difficulty row inside a collapsed category, so
        // reach it via the search field (typing auto-expands matching
        // categories) rather than scrolling.
        if (device.findObject(By.res(ROW_ID)) == null) {
            val search = device.wait(Until.findObject(By.res(SEARCH_ID)), UI_TIMEOUT)
                ?: error("search field $SEARCH_ID not found")
            search.click()
            device.waitForIdle()
            device.executeShellCommand("input text cross-app")
            device.wait(Until.hasObject(By.res(ROW_ID)), UI_TIMEOUT)
        }

        val row = device.findObject(By.res(ROW_ID)) ?: error("row $ROW_ID not found")
        row.click()
        assertNotNull(
            "module screen $SCREEN_ID not visible",
            device.wait(Until.findObject(By.res(SCREEN_ID)), UI_TIMEOUT),
        )

        val button = device.wait(Until.findObject(By.res(actionId)), UI_TIMEOUT)
            ?: error("action button $actionId not found")
        button.click()
        device.waitForIdle()
        Thread.sleep(BROADCAST_SETTLE_MS)
    }

    // --- Driving the attacker app --------------------------------------------

    private fun startAttackerService() {
        // Launch the attacker's activity explicitly via shell (am start), which
        // is not subject to app package-visibility. onCreate starts
        // OtpHarvestService, whose runtime receiver harvests the broadcast.
        device.executeShellCommand("am start -n $ATTACKER_PKG/.AttackerActivity")
        device.wait(Until.hasObject(By.pkg(ATTACKER_PKG).depth(0)), LAUNCH_TIMEOUT)
        Thread.sleep(SERVICE_START_MS)
    }

    /**
     * Bring the attacker to the front and read its "Latest capture:" readout.
     * The attacker refreshes that TextView every second, so a short retry loop
     * lets a just-fired broadcast surface.
     */
    private fun readAttackerCapture(): String {
        device.executeShellCommand("am start -n $ATTACKER_PKG/.AttackerActivity")
        device.wait(Until.hasObject(By.pkg(ATTACKER_PKG).depth(0)), LAUNCH_TIMEOUT)
        var text = ""
        var tries = 0
        while (tries++ < CAPTURE_TRIES) {
            val tv = device.wait(
                Until.findObject(By.pkg(ATTACKER_PKG).clazz("android.widget.TextView")),
                UI_TIMEOUT,
            )
            text = tv?.text ?: ""
            // The readout contains a "Latest capture:" section; return once a
            // HARVESTED line (or a definitive "nothing") is present.
            if (text.contains("HARVESTED") || text.contains("nothing captured")) break
            Thread.sleep(1_000L)
        }
        return text
    }

    // --- Helpers --------------------------------------------------------------

    private fun isInstalled(pkg: String): Boolean {
        // Use the INSTRUMENTATION (test-app) context, and consult the launcher
        // intent, to avoid Android 11+ package-visibility hiding the attacker
        // from DVMA's own context. As a final fallback, ask the platform via
        // `pm list packages` through UiAutomator.
        val ctx = InstrumentationRegistry.getInstrumentation().context
        val pm = ctx.packageManager
        if (runCatching { pm.getLaunchIntentForPackage(pkg) }.getOrNull() != null) return true
        if (runCatching { pm.getPackageInfo(pkg, 0) }.isSuccess) return true
        return runCatching {
            device.executeShellCommand("pm list packages $pkg").contains("package:$pkg")
        }.getOrDefault(false)
    }

    private companion object {
        // Derived from the app under test (single source of truth). Not `const`
        // because BuildConfig.APPLICATION_ID is a static field, not a literal.
        val DVMA_PKG: String = BuildConfig.APPLICATION_ID
        const val ATTACKER_PKG = "com.dvma.attacker"

        // Stable ids mirror lib/core/test_ids.dart + the module's action labels.
        const val DISCLAIMER_ID = "dvma_disclaimer_banner"
        const val SEARCH_ID = "dvma_search_field"
        const val ROW_ID = "vuln_row_cross_app_otp_credential_leak"
        const val SCREEN_ID = "demo_screen_cross_app_otp_credential_leak"
        const val ACTION_UNPROTECTED = "demo_action_broadcast_otp_unprotected"
        const val ACTION_SECURE = "demo_action_broadcast_otp_permission_scoped"

        val OTP_RE: Pattern = Pattern.compile("otp=(\\d+)")

        const val LAUNCH_TIMEOUT = 30_000L
        const val UI_TIMEOUT = 15_000L
        const val SERVICE_START_MS = 3_000L
        const val BROADCAST_SETTLE_MS = 2_000L
        const val CAPTURE_TRIES = 6
    }
}
