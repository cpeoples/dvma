pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version providers
            .fileContents(
                layout.settingsDirectory.file("../../gradle/libs.versions.toml"),
            ).asText
            .map { toml ->
                Regex("""^\s*agp\s*=\s*"([^"]+)"""", RegexOption.MULTILINE)
                    .find(toml)
                    ?.groupValues
                    ?.get(1)
                    ?: error("gradle/libs.versions.toml is missing [versions].agp")
            }.get()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
    // Share the repo-root version catalog with the main app so the companion's
    // toolchain and deps never drift from android/.
    versionCatalogs {
        create("libs") {
            from(files("../../gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "dvma-attacker"
include(":app")
