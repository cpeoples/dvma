DVMA builds on GitHub Actions in two distinct modes, deliberately separated so
ordinary development never touches signing secrets and never produces a
"release" by accident:

| Mode | Trigger | Signing | Output |
| --- | --- | --- | --- |
| **CI (catch breakage)** | every push + PR to `main` | none - unsigned / `--no-codesign` | pass/fail only, no artifact |
| **Release (installable)** | pushing a `v*` tag | Android keystore + Apple cert/profile (repo secrets) | signed APK/AAB/IPA attached to the GitHub Release |

The CI mode is wired today (`.github/workflows/ci.yml`). The release mode is
documented here but **not enabled until the signing secrets below exist** - see
"Why release is gated".

## CI mode - build both platforms with no secrets

The point of CI is to prove the code **compiles and passes tests** on every
change. It never needs a certificate:

- **Android:** `flutter build apk --debug` - an unsigned debug APK. Compiles the
  full app + Kotlin; catches tree-shake/resource/Gradle regressions.
- **iOS:** `flutter build ios --no-codesign` - compiles the full app + Swift +
  CocoaPods and **skips only the signing step**. This is the answer to "how do
  I build iOS without a provisioning profile": you don't need one to *build*,
  only to *install*.

> **A `--no-codesign` build is NOT installable.** It has no embedded
> provisioning profile or entitlements, so it can't run on a real device and
> should **not** be re-signed with `applesign` after the fact (the entitlements
> are missing, so a resign is fragile). If you want an installable build, use
> the release path below, or build a properly-signed `.ipa` locally and let a
> tester resign it with Sideloadly/AltStore.

### Runners & Docker

- **No Docker images are required.** The `subosito/flutter-action` step
  provisions Flutter directly on GitHub's hosted runners, so there is nothing to
  containerise for CI.
- **Android** builds on `ubuntu-latest`. (You *can* Dockerise an Android+Flutter
  build locally with e.g. `ghcr.io/cirruslabs/flutter:<version>`, but it is not
  needed for Actions.)
- **iOS builds must run on `macos-latest`.** Xcode/CocoaPods signing requires
  macOS, and Apple's licence forbids macOS in Docker/Linux - so iOS **cannot**
  be containerised. macOS runners are slower/costlier, so the iOS jobs are
  scoped to PRs (and on-demand for the heavier ones) rather than every push.

## Release mode - signed, installable artifacts on a tag

Triggered by pushing a version tag (`git tag v1.0.0 && git push --tags`). It
builds real signed artifacts and attaches them to the GitHub Release. It never
runs on ordinary pushes, so you cannot "burn a release" by mistake.

### Android release signing - fully self-serve

Android signing needs no third-party account. Create a release keystore once:

```sh
keytool -genkey -v -keystore dvma-release.jks \
  -keyalg RSA -keysize 2048 -validity 10000 -alias dvma
```

Then add these repo secrets. Fastest is the GitHub CLI from your machine (run
from the repo root, after creating the keystore above):

```sh
gh secret set ANDROID_KEYSTORE_BASE64 < <(base64 -i dvma-release.jks)
gh secret set ANDROID_KEYSTORE_PASSWORD --body 'YOUR_STORE_PASSWORD'
gh secret set ANDROID_KEY_ALIAS        --body 'dvma'
gh secret set ANDROID_KEY_PASSWORD     --body 'YOUR_KEY_PASSWORD'
```

Or paste them under **Settings → Secrets and variables → Actions**:

| Secret | What it is |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | `base64 -i dvma-release.jks` (the keystore itself) |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password you set above |
| `ANDROID_KEY_ALIAS` | `dvma` (the alias above) |
| `ANDROID_KEY_PASSWORD` | key password you set above |

The Gradle signing config is **already wired**: `android/app/build.gradle.kts`
reads a gitignored `android/key.properties` (see `key.properties.example`) and
signs the `release` build with it when present, falling back to the debug key
otherwise. `release.yml` writes `key.properties` + the keystore from the secrets
above before building, then scrubs them. (The signed build stays **debuggable /
unobfuscated** on purpose - that's the `debuggable_release_build` /
`no_obfuscation` modules; signing is orthogonal.)

### iOS release signing - needs an Apple Developer account

To build a **signed, installable `.ipa`** in CI you hand Actions the same four
things Xcode uses locally. All go in repo secrets:

| Secret | What it is | How to get it |
| --- | --- | --- |
| `IOS_CERT_P12_BASE64` | Signing certificate **+ private key** as a base64 `.p12` | Keychain Access → export identity as `.p12` → `base64 -i cert.p12` |
| `IOS_CERT_PASSWORD` | password chosen during `.p12` export | you choose it |
| `IOS_PROVISIONING_PROFILE_BASE64` | `.mobileprovision` for bundle id `com.dvma`, base64 | Apple Developer portal → Profiles → download → `base64 -i profile.mobileprovision` |
| `IOS_TEAM_ID` | your 10-char Apple Team ID | `security find-identity -v -p codesigning`, or the Membership page in the Developer portal |
| `IOS_KEYCHAIN_PASSWORD` | arbitrary password for the CI temp keychain | make one up |

Load them the same way as Android:

```sh
gh secret set IOS_CERT_P12_BASE64 < <(base64 -i cert.p12)
gh secret set IOS_CERT_PASSWORD --body 'YOUR_P12_PASSWORD'
gh secret set IOS_PROVISIONING_PROFILE_BASE64 < <(base64 -i profile.mobileprovision)
gh secret set IOS_TEAM_ID --body 'YOUR_TEAM_ID'
gh secret set IOS_KEYCHAIN_PASSWORD --body 'ANY_TEMP_PASSWORD'
# optional: choose the export method (defaults to "development")
gh variable set IOS_EXPORT_METHOD --body 'ad-hoc'
```

The team id is **never committed**. At release time the workflow generates
`ios/ExportOptions.plist` from `IOS_TEAM_ID` (and the optional `IOS_EXPORT_METHOD`
repo variable), then scrubs it - the committed
`ios/ExportOptions.plist.example` is a placeholder template, and the real
`ios/ExportOptions.plist` is gitignored (copy the example and fill in your team
to build a signed IPA locally).

**Which profile you use decides who can install the build - and it's why a free
account isn't enough for a real Releases `.ipa`:**

- **Development** - what a **free** Apple account gives you. Installs **only on
  UDIDs registered to your account** (you + a handful of test devices), each
  cert is valid ~7 days for free accounts, and there's a hard cap on devices and
  certificates. Fine for local testing; **not** a distributable release.
- **Ad Hoc** - installs on registered UDIDs, cert valid ~1 year; the usual
  choice for a Releases-page IPA. **Requires a paid Apple Developer account
  ($99/yr)** - the Ad Hoc/Distribution certificate type simply isn't issued to
  free accounts.
- **App Store** - for App Store upload only; not side-loadable.

So: you *can* build a **development-signed** IPA with the free profile, but it
only runs on devices you pre-registered and expires quickly. A broadly
installable release needs the paid account. That's an Apple account-tier limit,
not a CI limitation.

### The re-sign path - install the *unsigned* CI IPA on your own device

You don't actually need CI to sign at all if you just want to run DVMA on **your
own** device. The release/CI signing above only exists to attach a
ready-to-install artifact to the GitHub Release. Anyone - including **free**
Apple accounts - can take a bare/unsigned `Runner.ipa` and **re-sign it locally**
against their own identity, then sideload it. That's the same flow DVMA and the
jailbreak tools already use (see
[Install DVMA](/device-access/ios/install/)):

```sh
# free "Apple Development" identity is enough to run it on your own device
npx applesign -a -v \
  -i "Apple Development: you@example.com (XXXXXXXXXX)" \
  -m /path/to/your.mobileprovision \
  -b com.dvma \
  -o Runner-signed.ipa Runner.ipa
# then install with a jailbroken device (SSH/appinst), or ideviceinstaller/
# Sideloadly/TrollStore per the device-access docs.
```

Because of this, the iOS release job is a **convenience**, not a requirement: it
can even publish an **unsigned** IPA that each user re-signs for their own device
with a free account. The paid account only matters when you want a *single*
artifact that installs broadly without every user re-signing. Re-signing
inherits all the same free-tier limits (registered UDIDs only, ~7-day cert
expiry, App-Management/`applesign` `EPERM` quirks), all documented in the
device-access install guide.

### What's on this machine today (discovered locally)

- **Android:** only Flutter's auto-created `~/.android/debug.keystore`. **No
  release keystore yet** - run the `keytool` command above to create one.
- **iOS:** one signing identity, an `Apple Development` cert on your own Apple
  team - a **Development** cert. No provisioning profiles are installed
  locally. With this free/Development setup you can produce a *development*-signed
  IPA (installs on registered UDIDs only); a broadly side-loadable Releases IPA
  needs a **paid account** for an Ad Hoc/Distribution cert + profile.

## Does tagging a version build + sign the APK/IPA?

**Yes for Android, automatically.** `.github/workflows/release.yml` triggers on a
`v*` tag:

```sh
git tag v1.0.0 && git push origin v1.0.0
```

It builds + signs the **APK and AAB** from the `ANDROID_*` secrets and attaches
them to the GitHub Release. The **iOS job always runs**: with the `IOS_*` secrets
(incl. `IOS_TEAM_ID`) + a paid Apple account it builds + signs a `.ipa` (the
workflow generates `ios/ExportOptions.plist` from `IOS_TEAM_ID`); **without** those
secrets it instead publishes an **unsigned `Runner-unsigned.ipa`** that each user
re-signs for their own device with a free account (see "The re-sign path" above).

## Docker images - none required

CI/release use GitHub's **hosted runners** with `subosito/flutter-action`, so
there's nothing to containerize:

- **Android** runs on `ubuntu-latest` (Java 17 via `setup-java`, Flutter via the
  action). You *can* run an equivalent build locally in a Docker image like
  `ghcr.io/cirruslabs/flutter:<version>`, but it's not needed for Actions.
- **iOS** runs on `macos-latest` and **cannot be containerized** - Xcode/CodeSign
  need macOS, which Apple's license forbids in Docker/Linux.

## Why release is gated

The release workflow's iOS job **branches on the Apple secrets** rather than
skipping: with the `IOS_*` secrets present it produces a **signed** `.ipa`;
without them it still builds and publishes an **unsigned** `Runner-unsigned.ipa`
for users to re-sign locally, so tagging always yields an installable artifact
and never hard-fails. Android is fully live once the four `ANDROID_*` secrets
exist. To enable **signed** iOS: (1) obtain a paid Apple account + Ad
Hoc/Distribution cert + profile, (2) add the four `IOS_*` secrets (incl.
`IOS_TEAM_ID`), which lets the workflow generate `ios/ExportOptions.plist` from
the secret at build time.
