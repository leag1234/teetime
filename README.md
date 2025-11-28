# TeeTime

TeeTime is an on-device diagnostics app that inspects hardware-backed key support, verified boot state, Play Integrity verdicts, and Firebase initialization on AOSP-like builds. Each probe can be triggered independently so you can focus on the signal you care about, or you can run everything in a single sweep for a full device snapshot.

## Features
- **Device information** – Manufacturer, model, Android release, and SDK level.
- **TEE / KeyStore probe** – Generates temporary RSA, EC, and AES keys to report security levels, hardware enforcement, and configuration flags.
- **Boot / verified boot status** – Requests key attestation and surfaces bootloader lock state, patch levels, and verified boot hash.
- **Play Integrity check** – Requests a local verdict and reports integrity levels, device recognition results, and request metadata.
- **Firebase initialization** – Verifies that the Firebase runtime can be bootstrapped (useful when hardening builds or validating property lockdowns).

All results are rendered in a scrollable console view. Each section can be re-run without restarting the app.

## Project layout
- `app/` – Android client application (Kotlin).
- `backend/php/` – Minimal PHP service that validates Play Integrity tokens server-side.

## Prerequisites
- Android Studio Ladybug+ or the command-line `Android SDK` (compile/target SDK 34).
- JDK 17 (`./gradlew` picks up `JAVA_HOME`).
- A device or emulator running Android 7.0+ (API 24+) for attestation; Play Integrity requires Google Play services.

## Configuration
### Play Integrity
1. In Play Console, enable the **Play Integrity API** for this app and note the **Cloud project number** (12-digit).
2. Add the number to `gradle.properties` (or pass it with `-PplayIntegrityProjectNumber=...`):
   ```properties
   playIntegrityProjectNumber=123456789012
   ```
3. Rebuild the APK. Without a real project number the Play Integrity section reports an error or skips execution.
4. For trusted verdicts, deploy the bundled PHP verifier (`backend/php`) or your own server to validate the JWS token.

### Firebase check
No `google-services.json` is required. The app tries to initialise `FirebaseApp` using default parameters. Success indicates Firebase can start on the device build; failure usually points to missing Google services or restricted system properties.

## Build & run
```bash
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Using the app
1. Launch **TEE Checker** on the device.
2. Tap an individual button to run that diagnostic, or tap **Run all diagnostics** to execute every probe sequentially.
3. Review results in the console area; each section is titled and can be re-run as needed.
4. Use `adb logcat -d | grep TEE_CHECK` if you prefer to collect the output remotely.

## Backend verifier (optional)
The PHP sample in `backend/php` exposes a `/` endpoint that accepts a Play Integrity token, verifies the JWS signature, checks the nonce, and returns a trusted verdict summary. See the dedicated README in that directory for deployment and usage instructions.

## Contributing
Pull requests are welcome. Please keep Kotlin styling consistent (`ktlint` friendly) and run the core diagnostics on-device before submitting changes that touch sensitive code paths (attestation, Integrity, Firebase).
