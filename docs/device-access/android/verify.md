Modules mark their artifact *adb-pullable on a debuggable build, or via root on
any build*, the two tiers:

- **`adb` on a debuggable build (no root).** Flutter debug/profile builds are
  `debuggable`, so `run-as` grants access to the app's private data dir:

  ```bash
  adb shell run-as com.dvma ls files                 # app-private files
  adb shell run-as com.dvma cat shared_prefs/FlutterSharedPreferences.xml
  # World-readable external files need no run-as:
  adb pull /sdcard/Android/data/com.dvma/files ./android-artifacts
  ```

  `run-as` only works while the build is debuggable, a release APK refuses it,
  which is exactly why the next tier exists.

- **Rooted device (any build).** Root reaches the sandbox regardless of the
  debuggable flag and unlocks `frida`/`objection` (the analogue of the iOS
  jailbreak). Set it up via [Root with Magisk](/device-access/android/root-magisk/) above, then:

  ```bash
  adb shell su -c 'cat /data/data/com.dvma/shared_prefs/FlutterSharedPreferences.xml'
  adb shell su -c 'cp -r /data/data/com.dvma /sdcard/dvma-dump' && adb pull /sdcard/dvma-dump
  # Runtime instrumentation once rooted:
  frida -U -f com.dvma            # or: objection -g com.dvma explore
  ```
