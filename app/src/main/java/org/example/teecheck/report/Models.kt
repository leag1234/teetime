package org.example.teecheck.report

import org.json.JSONArray
import org.json.JSONObject

data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val sdkInt: Int
)

data class KeySecurity(
    val label: String,
    val note: String,
    val rawLevel: Int?,
    val hardwareBacked: Boolean
)

data class KeyReport(
    val algorithm: String,
    val security: KeySecurity,
    val keySize: Int?,
    val origin: String?,
    val purposes: List<String>,
    val digests: List<String>,
    val blockModes: List<String>,
    val encryptionPaddings: List<String>,
    val signaturePaddings: List<String>,
    val userAuthRequired: Boolean,
    val userAuthHwEnforced: Boolean?,
    val userAuthTimeoutSeconds: Int?,
    val trustedUserPresenceRequired: Boolean?,
    val userConfirmationRequired: Boolean?,
    val authValidWhileOnBody: Boolean?,
    val invalidatedByBiometricEnrollment: Boolean?
)

data class BootStateSummary(
    val attestationVersion: Int,
    val attestationSecurityLevel: String,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: String,
    val osPatchLevel: String?,
    val vendorPatchLevel: String?,
    val bootPatchLevel: String?,
    val deviceLocked: Boolean?,
    val verifiedBootState: String?,
    val verifiedBootStateDescription: String?,
    val verifiedBootHash: String?,
    val bootKeyFingerprint: String?,
    val attestationChallengeSha256: String?
)

data class DeviceReport(
    val device: DeviceInfo,
    val bootState: BootStateSummary?,
    val keys: List<KeyReport>
) {
    fun toJson(pretty: Boolean = true): String {
        val json = JSONObject()
            .put("device", JSONObject().apply {
                put("manufacturer", device.manufacturer)
                put("model", device.model)
                put("android_version", device.androidVersion)
                put("sdk_int", device.sdkInt)
            })
            .put("keys", JSONArray().apply {
                keys.forEach { add(it.toJson()) }
            })

        bootState?.let { state ->
            json.put("boot_state", state.toJson())
        }

        return if (pretty) json.toString(2) else json.toString()
    }
}

private fun JSONArray.add(value: JSONObject) = put(value)

private fun KeyReport.toJson(): JSONObject {
    return JSONObject().apply {
        put("algo", algorithm)
        put("security_level", security.label)
        put("security_note", security.note)
        security.rawLevel?.let { put("security_level_raw", it) }
        put("hardware_backed", security.hardwareBacked)
        keySize?.let { put("key_size", it) }
        origin?.let { put("origin", it) }
        put("purposes", JSONArray(purposes))
        put("digests", JSONArray(digests))
        put("block_modes", JSONArray(blockModes))
        put("encryption_paddings", JSONArray(encryptionPaddings))
        put("signature_paddings", JSONArray(signaturePaddings))
        put("user_auth_required", userAuthRequired)
        userAuthHwEnforced?.let { put("user_auth_hw_enforced", it) }
        userAuthTimeoutSeconds?.let { put("user_auth_timeout_sec", it) }
        trustedUserPresenceRequired?.let { put("trusted_user_presence_required", it) }
        userConfirmationRequired?.let { put("user_confirmation_required", it) }
        authValidWhileOnBody?.let { put("auth_valid_while_on_body", it) }
        invalidatedByBiometricEnrollment?.let { put("invalidated_by_biometric_enrollment", it) }
    }
}

private fun BootStateSummary.toJson(): JSONObject {
    return JSONObject().apply {
        put("attestation_version", attestationVersion)
        put("attestation_security_level", attestationSecurityLevel)
        put("keymaster_version", keymasterVersion)
        put("keymaster_security_level", keymasterSecurityLevel)
        osPatchLevel?.let { put("os_patch_level", it) }
        vendorPatchLevel?.let { put("vendor_patch_level", it) }
        bootPatchLevel?.let { put("boot_patch_level", it) }
        deviceLocked?.let { put("bootloader_locked", it) }
        verifiedBootState?.let { put("verified_boot_state", it) }
        verifiedBootStateDescription?.let { put("verified_boot_description", it) }
        verifiedBootHash?.let { put("verified_boot_hash", it) }
        bootKeyFingerprint?.let { put("boot_key_fingerprint", it) }
        attestationChallengeSha256?.let { put("attestation_challenge_sha256", it) }
    }
}
