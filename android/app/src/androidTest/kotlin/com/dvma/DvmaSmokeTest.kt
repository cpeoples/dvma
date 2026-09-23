/*
 * DvmaSmokeTest.kt
 *
 * Android-native smoke test for DVMA (Damn Vulnerable Mobile App) using
 * UiAutomator. Authorized security-training use only.
 *
 * Why UiAutomator, not Espresso view matchers: DVMA is a Flutter app, which
 * renders its entire UI to a single native FlutterView/SurfaceView canvas, so
 * classic Espresso matchers (onView(withId(...)), withText(...)) cannot see
 * individual Flutter widgets. DVMA instruments every automatable widget in
 * `lib/core/test_ids.dart` via `testId(id, child)`, which attaches a
 * `Semantics(identifier: id)` node. On Android that identifier surfaces through
 * the accessibility tree as the element's resource-id (and/or
 * content-description), which UiAutomator reads, so it can find these elements
 * by `By.res("<id>")` / `By.desc("<id>")`. Espresso's runner/rules still
 * bootstrap the instrumentation and launch the app; we query with UiAutomator.
 *
 * Run it (opt-in with -PdvmaAndroidTest=true; see automation/README.md):
 *   flutter build apk --debug --dart-define-from-file=config/flavors/full.json
 *   cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true
 */

package com.dvma

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DvmaSmokeTest {

    private lateinit var device: UiDevice

    /** applicationId of the DVMA build under test (android/app/build.gradle.kts). */
    private val pkg: String = BuildConfig.APPLICATION_ID

    // Stable ids mirror lib/core/test_ids.dart / automation/vuln_manifest.json.
    private val searchFieldId = "dvma_search_field"
    private val disclaimerBannerId = "dvma_disclaimer_banner"

    @Before
    fun launchApp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

        // Start from the home screen, then launch DVMA from scratch.
        device.pressHome()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val intent = context.packageManager.getLaunchIntentForPackage(pkg)?.apply {
            addFlags(android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        assertNotNull("No launch intent for package $pkg - is DVMA installed?", intent)
        context.startActivity(intent)

        // Wait for DVMA to be in the foreground.
        device.wait(Until.hasObject(By.pkg(pkg).depth(0)), LAUNCH_TIMEOUT)
    }

    @Test
    fun homeRendersAndSearchWorks() {
        // The intentionally-vulnerable disclaimer banner marks a booted home screen.
        val banner = device.wait(Until.findObject(By.res(disclaimerBannerId)), UI_TIMEOUT)
        assertNotNull("Disclaimer banner ($disclaimerBannerId) not found", banner)

        // The search field must be present and editable.
        val search = device.wait(Until.findObject(By.res(searchFieldId)), UI_TIMEOUT)
        assertNotNull("Search field ($searchFieldId) not found", search)

        // Type a query and confirm the app stays alive (home still rendered).
        search.click()
        search.text = "storage"
        device.waitForIdle()

        val stillHome = device.wait(Until.hasObject(By.res(disclaimerBannerId)), UI_TIMEOUT)
        assertTrue("Home index disappeared after searching", stillHome)
    }

    private companion object {
        const val LAUNCH_TIMEOUT = 30_000L
        const val UI_TIMEOUT = 15_000L
    }
}
