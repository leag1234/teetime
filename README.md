# teetime
TEE and other props checker in AOSP-like ROMs

## Play Integrity configuration

The Play Integrity check uses the cloud project number injected via the Gradle property `playIntegrityProjectNumber`. Add the value to your `gradle.properties` (or pass with `-P`) before building:

```
playIntegrityProjectNumber=123456789012
```

Without this value, the Play Integrity section is skipped at runtime.
