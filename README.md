# App Network Watcher

A local desktop debugger for HTTP traffic from an Android app during testing. It runs on your computer, you connect your own device, and each call shows up as it happens.

Apache-2.0. There is no account, no telemetry of captured bodies, and no feature gate.

## Run

```
cargo run -p watcher-desktop --bin app-network-watcher
```

The window opens on the debugger. Manual proxy mode listens for a client pointed at `127.0.0.1:<port>`. The default port is 8080.

```
curl -x http://127.0.0.1:8080 http://example.com/
```

The CA is created under the app data directory (`~/Library/Application Support/app-network-watcher` on macOS, or `WATCHER_DATA_DIR`). It is not installed into the operating system trust store.

## Android

`android/` is the companion. It was not built or run here: this machine has no Android SDK and no device. After you install the Android SDK:

```
cd android
# create a Gradle wrapper with the SDK you trust, then
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

In the desktop app, attach the device, press Connect Android, and approve the VPN and certificate prompts on the device. Interception is reported active only after both approvals. The status line says when the VPN and CA are active.

Android 7 and newer ignore a user CA unless the app trusts it.

- To capture debug and release builds of an app you ship, add the base-config snippet from the left rail. It trusts user CAs for every build type. Also set `android:networkSecurityConfig` on the application.
- The debug-overrides snippet trusts the user CA only in debug builds.
- For an emulator, or a device that is already rooted, the system-store button copies the CA after you tick the confirmation. `adb root` has to already succeed. The app does not try to root a phone.
- Apps that pin certificates fail in the table. Nothing in this project bypasses pinning.

The VPN redirects TCP 80, 443, 8000, 8001, 8080, 8888, and 9000. Other TCP and UDP are forwarded. IPv6 and ICMP are not captured. See `protocol.md`.

## Mac disk image

`packaging/make-dmg.sh` writes an Apple Silicon disk image under `dist/`. That image is not committed. It does not run on Intel Macs.

## Tests

```
cargo test --workspace
```
