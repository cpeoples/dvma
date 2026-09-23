pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }

    // Plugin versions come from the repo-root catalog (gradle/libs.versions.toml)
    // so the Android toolchain lives in one place shared with the companion app.
    // Settings-level plugin blocks can't use catalog type-safe accessors, so read
    // the [versions] entries and apply them via resolutionStrategy.
    val catalog = file("../gradle/libs.versions.toml").readText()
    fun version(key: String): String =
        Regex("""^\s*$key\s*=\s*"([^"]+)"""", RegexOption.MULTILINE)
            .find(catalog)
            ?.groupValues
            ?.get(1)
            ?: error("gradle/libs.versions.toml is missing [versions].$key")
    val agpVersion = version("agp")
    val kotlinVersion = version("kotlin")
    resolutionStrategy {
        eachPlugin {
            when (requested.id.id) {
                "com.android.application" -> useVersion(agpVersion)
                "org.jetbrains.kotlin.android" -> useVersion(kotlinVersion)
            }
        }
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") apply false
    id("org.jetbrains.kotlin.android") apply false
}

include(":app")

// Share the repo-root version catalog (gradle/libs.versions.toml) with the
// companion app so Android dep versions live in one place.
dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}
