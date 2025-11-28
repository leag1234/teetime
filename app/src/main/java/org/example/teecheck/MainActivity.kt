package org.example.teecheck

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Locale
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.example.teecheck.attestation.AttestationParser
import org.example.teecheck.attestation.BootStateReport
import org.example.teecheck.attestation.VerifiedBootState
import org.example.teecheck.databinding.ActivityMainBinding
import org.example.teecheck.integrity.PlayIntegrityChecker
import org.example.teecheck.integrity.PlayIntegrityResult
import org.example.teecheck.report.BootStateSummary
import org.example.teecheck.report.DeviceInfo
import org.example.teecheck.report.DeviceReport
import org.example.teecheck.report.KeyReport
import org.example.teecheck.report.KeySecurity
import org.example.teecheck.report.PlayIntegritySummary

private const val LOG_TAG = "TEE_CHECK"

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.outputText.text = getString(R.string.initial_message)

        lifecycleScope.launch {
            val output = withContext(Dispatchers.IO) { buildReport() }
            binding.outputText.text = output.displayText
            Log.i(LOG_TAG, "\n${output.displayText}")
        }
    }

    private suspend fun buildReport(): ReportOutput {
        val warnings = mutableListOf<String>()
        val keyReports = mutableListOf<KeyReport>()

        fun collectKey(label: String, builder: () -> KeyReport) {
            try {
                keyReports += builder()
            } catch (t: Throwable) {
                val reason = t.localizedMessage ?: t.javaClass.simpleName
                warnings += getString(R.string.key_generation_error, label, reason)
                Log.w(LOG_TAG, "Key assessment failed for $label", t)
            }
        }

        collectKey("RSA-2048") { assessRsaKey() }
        collectKey("EC-P256") { assessEcKey() }
        collectKey("AES-256") { assessAesKey() }

        val bootResult = runBootAttestation()
        val playIntegrityResult = runPlayIntegrityCheck()

        val deviceReport = DeviceReport(
            device = DeviceInfo(
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                androidVersion = Build.VERSION.RELEASE ?: "unknown",
                sdkInt = Build.VERSION.SDK_INT
            ),
            bootState = bootResult.summary,
            keys = keyReports,
            playIntegrity = playIntegrityResult.summary
        )

        val json = deviceReport.toJson()
        val humanReadable = formatReadableReport(
            deviceReport,
            warnings,
            bootResult.messages,
            playIntegrityResult.messages
        )
        val display = buildString {
            append(humanReadable)
            appendLine()
            appendLine()
            appendLine(getString(R.string.json_header))
            append(json)
        }

        return ReportOutput(display, json)
    }

    private fun assessRsaKey(): KeyReport {
        val alias = "teecheck_rsa_${System.currentTimeMillis()}"
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .build()
            )
        }

        val keyInfo = try {
            generator.generateKeyPair()
            loadPrivateKeyInfo(alias)
        } finally {
            deleteEntry(alias)
        }

        return buildKeyReport("RSA-2048", keyInfo)
    }

    private fun assessEcKey(): KeyReport {
        val alias = "teecheck_ec_${System.currentTimeMillis()}"
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384)
                    .setIsStrongBoxBacked(false)
                    .build()
            )
        }

        val keyInfo = try {
            generator.generateKeyPair()
            loadPrivateKeyInfo(alias)
        } finally {
            deleteEntry(alias)
        }

        return buildKeyReport("EC-P256", keyInfo)
    }

    private fun assessAesKey(): KeyReport {
        val alias = "teecheck_aes_${System.currentTimeMillis()}"
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
        }

        val keyInfo = try {
            generator.generateKey()
            loadSecretKeyInfo(alias)
        } finally {
            deleteEntry(alias)
        }

        return buildKeyReport("AES-256-GCM", keyInfo)
    }

    private fun loadPrivateKeyInfo(alias: String): KeyInfo {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
        return factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    }

    private fun loadSecretKeyInfo(alias: String): KeyInfo {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
        val factory = SecretKeyFactory.getInstance(entry.secretKey.algorithm, "AndroidKeyStore")
        return factory.getKeySpec(entry.secretKey, KeyInfo::class.java) as KeyInfo
    }

    private fun buildKeyReport(algorithm: String, keyInfo: KeyInfo): KeyReport {
        val security = describeSecurity(keyInfo)
        val purposes = decodePurposes(keyInfo.purposes)
        val digests = keyInfo.digests?.toList().orEmpty()
        val blockModes = keyInfo.blockModes?.toList().orEmpty()
        val encryptionPaddings = keyInfo.encryptionPaddings?.toList().orEmpty()
        val signaturePaddings = keyInfo.signaturePaddings?.toList().orEmpty()

        val trustedUserPresence = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            keyInfo.isTrustedUserPresenceRequired
        } else null

        val userConfirmationRequired = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyInfo.isUserConfirmationRequired
        } else null

        val authValidWhileOnBody = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            keyInfo.isUserAuthenticationValidWhileOnBody
        } else null

        val invalidatedByBiometric = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            keyInfo.isInvalidatedByBiometricEnrollment
        } else null

        return KeyReport(
            algorithm = algorithm,
            security = security,
            keySize = keyInfo.keySize,
            origin = decodeOrigin(keyInfo.origin),
            purposes = purposes,
            digests = digests,
            blockModes = blockModes,
            encryptionPaddings = encryptionPaddings,
            signaturePaddings = signaturePaddings,
            userAuthRequired = keyInfo.isUserAuthenticationRequired,
            userAuthHwEnforced = keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware,
            userAuthTimeoutSeconds = keyInfo.userAuthenticationValidityDurationSeconds,
            trustedUserPresenceRequired = trustedUserPresence,
            userConfirmationRequired = userConfirmationRequired,
            authValidWhileOnBody = authValidWhileOnBody,
            invalidatedByBiometricEnrollment = invalidatedByBiometric
        )
    }

    private fun decodePurposes(mask: Int): List<String> {
        val mapping = listOf(
            KeyProperties.PURPOSE_ENCRYPT to "ENCRYPT",
            KeyProperties.PURPOSE_DECRYPT to "DECRYPT",
            KeyProperties.PURPOSE_SIGN to "SIGN",
            KeyProperties.PURPOSE_VERIFY to "VERIFY",
            KeyProperties.PURPOSE_WRAP_KEY to "WRAP_KEY",
            KeyProperties.PURPOSE_AGREE_KEY to "AGREE_KEY"
        )
        return mapping.mapNotNull { (flag, name) -> if (mask and flag != 0) name else null }
    }

    private fun decodeOrigin(origin: Int): String = when (origin) {
        KeyProperties.ORIGIN_GENERATED -> "GENERATED"
        KeyProperties.ORIGIN_IMPORTED -> "IMPORTED"
        KeyProperties.ORIGIN_SECURELY_IMPORTED -> "SECURELY_IMPORTED"
        KeyProperties.ORIGIN_UNKNOWN -> "UNKNOWN"
        else -> "UNKNOWN($origin)"
    }

    private fun describeSecurity(keyInfo: KeyInfo): KeySecurity {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val rawLevel = keyInfo.securityLevel
            val (label, noteRes) = when (rawLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX" to R.string.note_strongbox
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE" to R.string.note_tee
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE" to R.string.note_software
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "UNKNOWN_SECURE" to R.string.note_unknown_secure
                KeyProperties.SECURITY_LEVEL_UNKNOWN -> "UNKNOWN" to R.string.note_unknown
                else -> "UNKNOWN($rawLevel)" to R.string.note_unknown
            }
            val note = "level=$rawLevel – ${getString(noteRes)}"
            val hardwareBacked = when (rawLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX,
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> true
                else -> false
            }
            KeySecurity(label = label, note = note, rawLevel = rawLevel, hardwareBacked = hardwareBacked)
        } else {
            val insideHardware = keyInfo.isInsideSecureHardware
            val label = if (insideHardware) "HARDWARE (legacy)" else "SOFTWARE"
            val noteRes = if (insideHardware) R.string.note_legacy_hardware else R.string.note_legacy_software
            KeySecurity(label = label, note = getString(noteRes), rawLevel = null, hardwareBacked = insideHardware)
        }
    }

    private fun runBootAttestation(): BootReportResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return BootReportResult(summary = null, messages = listOf(getString(R.string.attestation_not_supported)))
        }

        val alias = "teecheck_attest_${System.currentTimeMillis()}"
        val challenge = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        val challengeFingerprint = challenge.sha256().toHexString()

        val generator = try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .setIsStrongBoxBacked(false)
                        .build()
                )
            }
        } catch (t: Throwable) {
            val reason = t.localizedMessage ?: t.javaClass.simpleName
            return BootReportResult(summary = null, messages = listOf(getString(R.string.attestation_init_error, reason)))
        }

        val report = try {
            generator.generateKeyPair()
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val chain = ks.getCertificateChain(alias)?.filterIsInstance<X509Certificate>()
            val leaf = chain?.firstOrNull()
            if (leaf == null) {
                Log.w(LOG_TAG, "Attestation certificate chain missing")
                null
            } else {
                AttestationParser.parseBootState(leaf)
            }
        } catch (t: Throwable) {
            val reason = t.localizedMessage ?: t.javaClass.simpleName
            return BootReportResult(summary = null, messages = listOf(getString(R.string.attestation_generate_error, reason)))
        } finally {
            deleteEntry(alias)
        }

        if (report == null) {
            return BootReportResult(summary = null, messages = listOf(getString(R.string.attestation_no_data)))
        }

        val summary = report.toSummary(challengeFingerprint)
        return BootReportResult(summary = summary, messages = emptyList())
    }

    private fun BootStateReport.toSummary(challengeFingerprint: String): BootStateSummary {
        return BootStateSummary(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel.name,
            keymasterVersion = keymasterVersion,
            keymasterSecurityLevel = keymasterSecurityLevel.name,
            osPatchLevel = osPatchLevel?.let { formatYearMonth(it) },
            vendorPatchLevel = vendorPatchLevel?.let { formatYearMonth(it) },
            bootPatchLevel = bootPatchLevel?.let { formatYearMonthDay(it) },
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState?.name,
            verifiedBootStateDescription = verifiedBootState?.takeUnless { it == VerifiedBootState.UNKNOWN }?.description,
            verifiedBootHash = verifiedBootHash?.takeIf { it.isNotEmpty() }?.toHexString(),
            bootKeyFingerprint = verifiedBootKey?.takeIf { it.isNotEmpty() }?.sha256()?.toHexString(),
            attestationChallengeSha256 = challengeFingerprint
        )
    }

    private fun formatReadableReport(
        deviceReport: DeviceReport,
        warnings: List<String>,
        bootMessages: List<String>,
        integrityMessages: List<String>
    ): String {
        val sb = StringBuilder()
        sb.appendLine(getString(R.string.report_title))
        sb.appendLine(getString(R.string.device_info, deviceReport.device.manufacturer, deviceReport.device.model))
        sb.appendLine(getString(R.string.android_info, deviceReport.device.androidVersion, deviceReport.device.sdkInt))
        sb.appendLine()

        if (deviceReport.keys.isNotEmpty()) {
            sb.appendLine(getString(R.string.report_header))
            sb.appendLine(getString(R.string.report_divider))
            deviceReport.keys.forEach { key ->
                sb.appendLine(formatLine(key.algorithm, key.security.label, key.security.note))
            }
        } else {
            sb.appendLine(getString(R.string.no_keys_collected))
        }

        if (warnings.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(getString(R.string.warnings_header))
            warnings.forEach { sb.appendLine("- $it") }
        }

        if (deviceReport.keys.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(getString(R.string.key_details_header))
            deviceReport.keys.forEach { key ->
                sb.appendLine(getString(R.string.key_detail_title, key.algorithm, key.security.label))
                sb.appendLine("  ${getString(R.string.key_detail_security, key.security.label, key.security.note)}")
                key.keySize?.let { size ->
                    sb.appendLine("  ${getString(R.string.key_detail_size, size)}")
                }
                key.origin?.let { origin ->
                    sb.appendLine("  ${getString(R.string.key_detail_origin, origin)}")
                }
                if (key.purposes.isNotEmpty()) {
                    sb.appendLine("  ${getString(R.string.key_detail_purposes, key.purposes.joinToString(", "))}")
                }
                if (key.digests.isNotEmpty()) {
                    sb.appendLine("  ${getString(R.string.key_detail_digests, key.digests.joinToString(", "))}")
                }
                if (key.blockModes.isNotEmpty()) {
                    sb.appendLine("  ${getString(R.string.key_detail_block_modes, key.blockModes.joinToString(", "))}")
                }
                if (key.encryptionPaddings.isNotEmpty()) {
                    sb.appendLine("  ${getString(R.string.key_detail_encryption_paddings, key.encryptionPaddings.joinToString(", "))}")
                }
                if (key.signaturePaddings.isNotEmpty()) {
                    sb.appendLine("  ${getString(R.string.key_detail_signature_paddings, key.signaturePaddings.joinToString(", "))}")
                }
                sb.appendLine(
                    "  ${getString(
                        R.string.key_detail_user_auth,
                        booleanString(key.userAuthRequired),
                        key.userAuthHwEnforced?.let { booleanString(it) } ?: getString(R.string.attestation_unknown_value)
                    )}"
                )
                key.userAuthTimeoutSeconds?.let { timeout ->
                    sb.appendLine("  ${getString(R.string.key_detail_timeout, timeout)}")
                }
                key.trustedUserPresenceRequired?.let { value ->
                    sb.appendLine("  ${getString(R.string.key_detail_trusted_presence, booleanString(value))}")
                }
                key.userConfirmationRequired?.let { value ->
                    sb.appendLine("  ${getString(R.string.key_detail_user_confirmation, booleanString(value))}")
                }
                key.authValidWhileOnBody?.let { value ->
                    sb.appendLine("  ${getString(R.string.key_detail_on_body, booleanString(value))}")
                }
                key.invalidatedByBiometricEnrollment?.let { value ->
                    sb.appendLine("  ${getString(R.string.key_detail_biometric_invalidation, booleanString(value))}")
                }
                sb.appendLine()
            }
        }

        sb.appendLine(getString(R.string.attestation_header))
        val bootState = deviceReport.bootState
        if (bootState != null) {
            sb.appendLine(getString(R.string.attestation_security_level_line, bootState.attestationSecurityLevel, bootState.keymasterSecurityLevel))
            sb.appendLine(getString(R.string.attestation_versions, bootState.attestationVersion, bootState.keymasterVersion))
            bootState.osPatchLevel?.let { sb.appendLine(getString(R.string.attestation_os_patch, it)) }
            bootState.vendorPatchLevel?.let { sb.appendLine(getString(R.string.attestation_vendor_patch, it)) }
            bootState.bootPatchLevel?.let { sb.appendLine(getString(R.string.attestation_boot_patch, it)) }
            bootState.deviceLocked?.let {
                val label = booleanString(it)
                sb.appendLine(getString(R.string.attestation_device_locked, label))
            }
            bootState.verifiedBootStateDescription?.let {
                sb.appendLine(getString(R.string.attestation_verified_boot, it))
            }
            bootState.verifiedBootHash?.let {
                sb.appendLine(getString(R.string.attestation_verified_hash, it))
            }
            bootState.bootKeyFingerprint?.let {
                sb.appendLine(getString(R.string.attestation_verified_key, it))
            }
            bootState.attestationChallengeSha256?.let {
                sb.appendLine(getString(R.string.attestation_challenge_fingerprint, it))
            }
        } else {
            if (bootMessages.isEmpty()) {
                sb.appendLine(getString(R.string.attestation_no_data))
            } else {
                bootMessages.forEach { sb.appendLine("- $it") }
            }
        }

        sb.appendLine()
        sb.appendLine(getString(R.string.play_integrity_header))
        val integrity = deviceReport.playIntegrity
        if (integrity != null) {
            sb.appendLine(getString(R.string.play_integrity_highest_level, integrity.highestIntegrityLevel))
            if (integrity.deviceRecognitionVerdicts.isNotEmpty()) {
                sb.appendLine(
                    getString(
                        R.string.play_integrity_device_verdicts,
                        integrity.deviceRecognitionVerdicts.joinToString(", ")
                    )
                )
            }
            integrity.appRecognitionVerdict?.let {
                sb.appendLine(getString(R.string.play_integrity_app_verdict, it))
            }
            val licensingVerdict = integrity.accountLicensingVerdict ?: integrity.appLicensingVerdict
            licensingVerdict?.let {
                sb.appendLine(getString(R.string.play_integrity_account_verdict, it))
            }
            integrity.requestPackageName?.let {
                sb.appendLine(getString(R.string.play_integrity_request_package, it))
            }
            integrity.requestTimestampMillis?.let {
                sb.appendLine(getString(R.string.play_integrity_request_timestamp, it))
            }
            sb.appendLine(getString(R.string.play_integrity_nonce, integrity.nonceSha256))
        } else {
            if (integrityMessages.isEmpty()) {
                sb.appendLine(getString(R.string.play_integrity_no_data))
            } else {
                integrityMessages.forEach { sb.appendLine("- $it") }
            }
        }

        return sb.toString().trimEnd()
    }

    private fun booleanString(value: Boolean): String = if (value) {
        getString(R.string.attestation_yes)
    } else {
        getString(R.string.attestation_no)
    }

    private fun formatLine(algo: String, level: String, note: String): String {
        val algoCol = algo.padEnd(12)
        val levelCol = level.padEnd(18)
        return "$algoCol | $levelCol | $note"
    }

    private fun deleteEntry(alias: String) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
    }

    private fun formatYearMonth(value: Int): String {
        val year = value / 100
        val month = value % 100
        return if (year <= 0 || month <= 0 || month > 12) {
            getString(R.string.attestation_unknown_value)
        } else {
            String.format(Locale.US, "%04d-%02d", year, month)
        }
    }

    private fun formatYearMonthDay(value: Int): String {
        val year = value / 10000
        val month = (value / 100) % 100
        val day = value % 100
        return if (year <= 0 || month <= 0 || month > 12 || day <= 0 || day > 31) {
            getString(R.string.attestation_unknown_value)
        } else {
            String.format(Locale.US, "%04d-%02d-%02d", year, month, day)
        }
    }

    private fun ByteArray.toHexString(): String = joinToString(separator = "") { String.format(Locale.US, "%02X", it) }

    private fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)

    private data class ReportOutput(val displayText: String, val json: String)

    private data class BootReportResult(
        val summary: BootStateSummary?,
        val messages: List<String>
    )

    private data class PlayIntegrityReportResult(
        val summary: PlayIntegritySummary?,
        val messages: List<String>
    )

    private suspend fun runPlayIntegrityCheck(): PlayIntegrityReportResult {
        val rawNumber = BuildConfig.PLAY_INTEGRITY_PROJECT_NUMBER
        if (rawNumber.isBlank()) {
            return PlayIntegrityReportResult(
                summary = null,
                messages = listOf(getString(R.string.play_integrity_not_configured))
            )
        }

        val projectNumber = rawNumber.toLongOrNull()
            ?: return PlayIntegrityReportResult(
                summary = null,
                messages = listOf(getString(R.string.play_integrity_bad_project_number, rawNumber))
            )

        val checker = PlayIntegrityChecker(applicationContext)
        return when (val result = checker.check(projectNumber)) {
            is PlayIntegrityResult.Success -> PlayIntegrityReportResult(result.summary, emptyList())
            is PlayIntegrityResult.Failure -> PlayIntegrityReportResult(
                summary = null,
                messages = listOf(getString(R.string.play_integrity_error, result.reason))
            )
        }
    }
}
