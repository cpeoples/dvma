import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Opt-in Espresso/UiAutomator instrumentation suite (automation/espresso/).
// Off by default so normal `flutter build`/`flutter run` never compile or ship
// the androidTest sources. Enable with `-PdvmaAndroidTest=true`, e.g.:
//   ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true
val dvmaAndroidTest = (project.findProperty("dvmaAndroidTest") as String?) == "true"

// SINGLE SOURCE OF TRUTH for the app package. Read from config/app.json at the
// repo root so the id is authored in exactly one human-facing place. Gradle
// derives applicationId + namespace from it; BuildConfig.APPLICATION_ID and the
// manifest ${applicationId} placeholders then flow to all runtime code, and
// `dart run tool/sync_app_id.dart` propagates the same value to Dart flavors,
// iOS, and the companion attacker app.
val dvmaAppId: String = run {
    val appJson = rootProject.projectDir.parentFile.resolve("config/app.json")
    val text = appJson.readText()
    Regex("\"app_id\"\\s*:\\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1)
        ?: error("config/app.json is missing an \"app_id\" entry")
}

// Optional release signing config, read from android/key.properties (gitignored;
// see key.properties.example). Absent on dev machines and PR CI, where the
// release build falls back to the debug key so `flutter run --release` still
// works. Present on tagged-release CI, which materializes key.properties from
// repo secrets before building. Loaded here so the buildTypes block below can
// pick it only when real credentials exist.
val keyProps = Properties().apply {
    val f = rootProject.file("app/key.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
val hasReleaseSigning = keyProps.getProperty("storeFile") != null

android {
    namespace = dvmaAppId
    // compileSdk is centralized in android/gradle.properties (dvma.compileSdk) so
    // the API level lives in exactly one place. We pin it rather than inherit
    // flutter.compileSdkVersion because several AndroidX deps pulled in by our
    // plugins require compiling against API 33+.
    compileSdk = (project.findProperty("dvma.compileSdk") as String).toInt()
    ndkVersion = flutter.ndkVersion

    // Generate BuildConfig so runtime code can read BuildConfig.APPLICATION_ID
    // instead of hardcoding the package. The applicationId below derives from
    // config/app.json (the single source of truth); Kotlin derives the OTP
    // action/permission from it, the manifest uses ${applicationId}, and Dart
    // receives it via the DVMA_APP_ID --dart-define (synced from config/app.json).
    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Real vulnerable NDK library for native_code_memory_bugs (src/main/cpp).
    // FOR AUTHORIZED SECURITY-TRAINING USE ONLY - compiles a genuine C stack
    // buffer overflow into libdvma_native.so for ghidra/gdb/frida analysis.
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    defaultConfig {
        // Derived from config/app.json - the single source of truth. Do not
        // hardcode; edit config/app.json and re-run tool/sync_app_id.dart.
        applicationId = dvmaAppId
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        if (dvmaAndroidTest) {
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    // Only feed the opt-in Espresso/UiAutomator sources to the compiler when
    // the suite is enabled; otherwise the androidTest dir is ignored entirely.
    sourceSets {
        getByName("androidTest") {
            kotlin.setSrcDirs(
                if (dvmaAndroidTest) {
                    listOf("src/androidTest/kotlin")
                } else {
                    emptyList()
                }
            )
        }
    }

    signingConfigs {
        // Only define the release signing config when real credentials exist
        // (android/key.properties present), so a missing file never fails
        // configuration on dev machines or PR CI - the release build just falls
        // back to the debug key there.
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(keyProps.getProperty("storeFile"))
                storePassword = keyProps.getProperty("storePassword")
                keyAlias = keyProps.getProperty("keyAlias")
                keyPassword = keyProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Use the real release key when key.properties is present (tagged-
            // release CI or a configured dev machine); otherwise fall back to the
            // debug key so `flutter run --release` still works locally/on PR CI.
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }

            // INTENTIONALLY VULNERABLE (FOR AUTHORIZED SECURITY-TRAINING ONLY):
            // ship the release build debuggable, unshrunk and unobfuscated so
            // static analysers see the real findings on the produced APK:
            //   * isDebuggable=true      -> debuggable_release_build (CWE-489)
            //   * isMinifyEnabled=false  -> no_obfuscation (CWE-656, MASWE-0059)
            //   * proguard/R8 disabled   -> symbols/strings survive for jadx.
            // A hardened release would be non-debuggable with R8 + ProGuard on.
            // NOTE: signing is orthogonal to this - a signed build is still
            // debuggable/unobfuscated so those two modules stay real.
            isDebuggable = true
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

// Espresso/UiAutomator instrumentation deps - only pulled in when the opt-in
// suite is enabled (`-PdvmaAndroidTest=true`). See automation/README.md.
// Versions are aligned with the androidx.test versions Flutter already pins on
// the runtime classpath (AGP consistent resolution rejects mismatches).
if (dvmaAndroidTest) {
    dependencies {
        androidTestImplementation("androidx.test.ext:junit:1.7.0")
        androidTestImplementation("androidx.test:runner:1.7.0")
        androidTestImplementation("androidx.test:rules:1.7.0")
        androidTestImplementation("androidx.test.uiautomator:uiautomator:2.4.0")
        androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    }
}

flutter {
    source = "../.."
}
