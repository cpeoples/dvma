DVMA targets the **latest stable Flutter** (developed against 3.47.x, Dart
3.13+). You only need the Android SDK / Xcode to build device binaries, you can
run `flutter analyze`/`flutter test` and the web preview without them.

<details open>
<summary><strong><i class="fa-brands fa-apple"></i> macOS</strong></summary>

```sh
# First, on a fresh Mac: install the Xcode Command Line Tools (git, clang, etc.
# Homebrew needs these). Skip if `git --version` already works.
xcode-select --install

# Recommended: Homebrew
brew install --cask flutter

# Android builds: install Android Studio (bundles the SDK + emulator)
brew install --cask android-studio
# then open Android Studio once to finish SDK setup, or:
flutter doctor --android-licenses

# iOS builds: install the full Xcode app from the App Store (the CLT above are
# NOT enough for device/simulator builds), then point the toolchain at it:
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -runFirstLaunch
sudo gem install cocoapods   # or: brew install cocoapods

flutter doctor   # verify your toolchain
```

</details>

<details>
<summary><strong><i class="fa-brands fa-linux"></i> Linux</strong></summary>

```sh
# Option A: Snap (Ubuntu/Debian)
sudo snap install flutter --classic

# Option B: manual tarball
# Download from https://docs.flutter.dev/get-started/install/linux and:
tar xf flutter_linux_*-stable.tar.xz -C ~/development
export PATH="$HOME/development/flutter/bin:$PATH"   # add to ~/.bashrc/.zshrc

# Common build deps
sudo apt-get install -y curl git unzip xz-utils zip libglu1-mesa

# Android: install Android Studio (or cmdline-tools), then:
flutter doctor --android-licenses
flutter doctor
```

_iOS binaries cannot be built on Linux (Apple toolchain is macOS-only)._
</details>

<details>
<summary><strong><i class="fa-brands fa-windows"></i> Windows</strong></summary>

```powershell
# Option A: winget
winget install --id=Flutter.Flutter -e

# Option B: manual zip
# Download from https://docs.flutter.dev/get-started/install/windows,
# unzip to e.g. C:\src\flutter, then add C:\src\flutter\bin to PATH.

# Android: install Android Studio, then:
flutter doctor --android-licenses
flutter doctor
```

_iOS binaries cannot be built on Windows._
</details>

After install, from the repo root:

```sh
flutter pub get
dart run tool/generate.dart   # (re)generate the registry + module router
```
