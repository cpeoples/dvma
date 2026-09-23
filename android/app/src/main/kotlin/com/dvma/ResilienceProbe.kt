package com.dvma

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest

/**
 * Real native resilience probes for the resilience vulnerability modules.
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Unlike a pure-Dart simulation (which has nothing real to bypass), each method
 * here performs a *genuine* on-device check - reads the filesystem, /proc maps,
 * Build fields, the debugger flag, and the app's signing certificate. The
 * findings are returned to Dart as a short human-readable string and mirrored
 * to logcat under [TAG] so the capture harness can pull them.
 *
 * The training point: the check is REAL, but the app still gates on a
 * client-side, bypassable boolean in the Dart layer. Defeating that boolean is
 * therefore a real bypass exercise against a real signal - not a fake toggle.
 */
class ResilienceProbe(private val app: Context) {

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                val finding = when (call.method) {
                    "rootCheck" -> rootCheck()
                    "fridaCheck" -> fridaCheck()
                    "emulatorCheck" -> emulatorCheck()
                    "debuggerCheck" -> debuggerCheck()
                    "tamperCheck" -> tamperCheck()
                    "installedPackages" -> installedPackages()
                    "virtualizationCheck" -> virtualizationCheck()
                    else -> null
                }
                if (finding == null) {
                    result.notImplemented()
                } else {
                    Log.w(TAG, "[${call.method}] $finding")
                    result.success(finding)
                }
            }
    }

    /**
     * root_jailbreak_detection_bypass: look for su binaries on the common root
     * paths, the "test-keys" marker in [Build.TAGS], and well-known root/su
     * manager packages actually installed. All real reads of device state.
     */
    private fun rootCheck(): String {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/xbin/mu",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/app/Superuser.apk",
        )
        val foundSu = suPaths.filter { runCatching { File(it).exists() }.getOrDefault(false) }

        val tags = Build.TAGS ?: ""
        val testKeys = tags.contains("test-keys")

        val rootPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.zachspong.temprootremovejb",
            "com.saurik.substrate",
        )
        val installedRootPkgs = rootPackages.filter { isPackageInstalled(it) }

        val compromised = foundSu.isNotEmpty() || testKeys || installedRootPkgs.isNotEmpty()
        return buildString {
            append("compromised=$compromised; ")
            append("suBinaries=${if (foundSu.isEmpty()) "none" else foundSu.joinToString(",")}; ")
            append("buildTags=$tags (testKeys=$testKeys); ")
            append("rootPackages=${if (installedRootPkgs.isEmpty()) "none" else installedRootPkgs.joinToString(",")}")
        }
    }

    /**
     * frida_detection_bypass: read this process's own memory map and look for
     * frida's injected libraries, then cheaply probe the default frida-server
     * port on localhost. Both are real signals a running frida leaves behind.
     */
    private fun fridaCheck(): String {
        val mapMarkers = listOf("frida-gadget", "frida-agent", "libfrida", "frida", "gum-js-loop", "gmain")
        val hitLibs = mutableSetOf<String>()
        runCatching {
            File("/proc/self/maps").useLines { lines ->
                for (line in lines) {
                    for (m in mapMarkers) {
                        if (line.contains(m, ignoreCase = true)) hitLibs.add(m)
                    }
                }
            }
        }

        val fridaPort = 27042
        val portOpen = runCatching {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", fridaPort), 120)
                true
            }
        }.getOrDefault(false)

        val detected = hitLibs.isNotEmpty() || portOpen
        return buildString {
            append("detected=$detected; ")
            append("mapMatches=${if (hitLibs.isEmpty()) "none" else hitLibs.joinToString(",")}; ")
            append("port$fridaPort=${if (portOpen) "open" else "closed"}")
        }
    }

    /**
     * emulator_detection_bypass: inspect real Build fields for the generic /
     * goldfish / ranchu / sdk / emulator markers that stock emulator images set.
     */
    private fun emulatorCheck(): String {
        val fingerprint = Build.FINGERPRINT ?: ""
        val model = Build.MODEL ?: ""
        val manufacturer = Build.MANUFACTURER ?: ""
        val product = Build.PRODUCT ?: ""
        val hardware = Build.HARDWARE ?: ""
        val brand = Build.BRAND ?: ""
        val device = Build.DEVICE ?: ""

        val markers = mutableListOf<String>()
        if (fingerprint.startsWith("generic") || fingerprint.contains("vbox") ||
            fingerprint.contains("test-keys") || fingerprint.contains("emulator")
        ) markers.add("fingerprint=$fingerprint")
        if (model.contains("google_sdk") || model.contains("Emulator") ||
            model.contains("Android SDK built for") || model.contains("sdk_gphone")
        ) markers.add("model=$model")
        if (manufacturer.contains("Genymotion") || manufacturer.contains("unknown")) {
            markers.add("manufacturer=$manufacturer")
        }
        if (product.contains("sdk") || product.contains("google_sdk") ||
            product.contains("emulator") || product.contains("vbox") ||
            product.contains("ranchu")
        ) markers.add("product=$product")
        if (hardware.contains("goldfish") || hardware.contains("ranchu") ||
            hardware.contains("vbox")
        ) markers.add("hardware=$hardware")
        if (brand.startsWith("generic") || device.startsWith("generic") ||
            device.contains("emulator")
        ) markers.add("brand/device=$brand/$device")

        val isEmulator = markers.isNotEmpty()
        return buildString {
            append("emulator=$isEmulator; ")
            append("fingerprint=$fingerprint; model=$model; manufacturer=$manufacturer; ")
            append("product=$product; hardware=$hardware; ")
            append("markers=${if (markers.isEmpty()) "none" else markers.joinToString(" | ")}")
        }
    }

    /**
     * anti_debugging_bypass: query the two real debugger signals Android
     * exposes - [Debug.isDebuggerConnected] and the FLAG_DEBUGGABLE app flag.
     */
    private fun debuggerCheck(): String {
        val debuggerConnected = Debug.isDebuggerConnected()
        val waitingForDebugger = Debug.waitingForDebugger()
        val debuggable = (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

        val detected = debuggerConnected || waitingForDebugger || debuggable
        return buildString {
            append("detected=$detected; ")
            append("debuggerConnected=$debuggerConnected; ")
            append("waitingForDebugger=$waitingForDebugger; ")
            append("flagDebuggable=$debuggable")
        }
    }

    /**
     * anti_tampering_integrity_bypass: read the app's *actual* signing
     * certificate from the PackageManager and return its SHA-256 digest - the
     * real integrity anchor a genuine check would pin against.
     */
    private fun tamperCheck(): String {
        return runCatching {
            val pm = app.packageManager
            val pkg = app.packageName
            val signatures: Array<android.content.pm.Signature> =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    @Suppress("DEPRECATION")
                    val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                    val sc = info.signingInfo
                    if (sc == null) emptyArray()
                    else if (sc.hasMultipleSigners()) sc.apkContentsSigners
                    else sc.signingCertificateHistory
                } else {
                    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
                    pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()
                }
            if (signatures.isEmpty()) {
                "package=$pkg; signingSha256=unavailable (no signatures)"
            } else {
                val digests = signatures.map { sha256Hex(it.toByteArray()) }
                "package=$pkg; signerCount=${signatures.size}; signingSha256=${digests.joinToString(",")}"
            }
        }.getOrElse { e ->
            "package=${app.packageName}; signingSha256=error (${e.javaClass.simpleName}: ${e.message})"
        }
    }

    /**
     * malware_detection_absent: enumerate REAL installed packages and screen
     * them against a known-hostile catalog (accessibility abusers, overlay /
     * tapjacking kits, known trojans). This is the environment scan the app
     * *could* run - the module's point is that it never gates on it.
     */
    private fun installedPackages(): String {
        val hostileCatalog = listOf(
            "com.evil.a11ygrabber",
            "com.evil.overlaykit",
            "com.cerberus.bot",
            "com.anubis.dropper",
            "com.metasploit.stage",
        )
        val installed = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                app.packageManager.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(0),
                )
            } else {
                @Suppress("DEPRECATION")
                app.packageManager.getInstalledPackages(0)
            }.map { it.packageName }
        }.getOrDefault(emptyList())

        val flagged = hostileCatalog.filter { installed.contains(it) }
        return buildString {
            append("installedCount=${installed.size}; ")
            append("hostilePresent=${if (flagged.isEmpty()) "none" else flagged.joinToString(",")}; ")
            append("catalogScreened=${hostileCatalog.size}")
        }
    }

    /**
     * virtualization_detection_absent: read REAL indicators that the app is
     * running inside an app-virtualization / cloning container - a work-profile
     * / dual-app user id != 0, and duplicate app-data paths under /data/data
     * or /data/user for this package. Real reads of the running environment.
     */
    private fun virtualizationCheck(): String {
        val userId = android.os.Process.myUserHandle().hashCode()
        val pkg = app.packageName
        val dataPaths = listOf(
            "/data/data/$pkg",
            "/data/user/0/$pkg",
            "/data/user_de/0/$pkg",
        )
        val presentPaths = dataPaths.filter {
            runCatching { File(it).exists() }.getOrDefault(false)
        }
        val appDataDir = runCatching { app.applicationInfo.dataDir }.getOrDefault("")
        val nonStandardPath = appDataDir.isNotEmpty() &&
            !appDataDir.startsWith("/data/data/") &&
            !appDataDir.startsWith("/data/user/")

        val cloned = userId != 0 || nonStandardPath
        return buildString {
            append("clonedContainer=$cloned; ")
            append("userId=$userId; ")
            append("appDataDir=$appDataDir (nonStandard=$nonStandardPath); ")
            append("dataPathsPresent=${presentPaths.joinToString(",")}")
        }
    }

    private fun isPackageInstalled(pkg: String): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            app.packageManager.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            app.packageManager.getPackageInfo(pkg, 0)
        }
        true
    }.getOrDefault(false)

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val CHANNEL = "dvma/resilience"
        const val TAG = EvidenceStore.TAG
    }
}
