package foundation.e.teetime

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.firebase.FirebaseApp
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.EnumMap
import java.util.Locale
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import foundation.e.teetime.attestation.AttestationParser
import foundation.e.teetime.attestation.BootStateReport
import foundation.e.teetime.attestation.VerifiedBootState
import foundation.e.teetime.databinding.ActivityMainBinding
import foundation.e.teetime.integrity.PlayIntegrityChecker
import foundation.e.teetime.integrity.PlayIntegrityResult
import foundation.e.teetime.report.BootStateSummary
import foundation.e.teetime.report.DeviceInfo
import foundation.e.teetime.report.KeyReport
import foundation.e.teetime.report.KeySecurity
import foundation.e.teetime.report.PlayIntegritySummary

private const val LOG_TAG = "TEE_CHECK"

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val sectionViews = EnumMap<Section, SectionViews>(Section::class.java)
    private val detailVisibility = EnumMap<Section, Boolean>(Section::class.java)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupSection(
            section = Section.DEVICE,
            summary = binding.deviceSummary,
            details = binding.deviceDetails,
            runButton = binding.deviceRunButton,
            toggleButton = binding.deviceToggleButton
        ) { renderDeviceSection() }

        setupSection(
            section = Section.KEYS,
            summary = binding.keysSummary,
            details = binding.keysDetails,
            runButton = binding.keysRunButton,
            toggleButton = binding.keysToggleButton
        ) { withContext(Dispatchers.IO) { renderKeysSection(collectKeyDiagnostics()) } }

        setupSection(
            section = Section.BOOT,
            summary = binding.bootSummary,
            details = binding.bootDetails,
            runButton = binding.bootRunButton,
            toggleButton = binding.bootToggleButton
        ) { withContext(Dispatchers.IO) { renderBootSection(runBootDiagnostics()) } }

        setupSection(
            section = Section.INTEGRITY,
            summary = binding.integritySummary,
            details = binding.integrityDetails,
            runButton = binding.integrityRunButton,
            toggleButton = binding.integrityToggleButton
        ) { withContext(Dispatchers.IO) { renderIntegritySection(runPlayIntegrityDiagnostics()) } }

        setupSection(
            section = Section.FIREBASE,
            summary = binding.firebaseSummary,
            details = binding.firebaseDetails,
            runButton = binding.firebaseRunButton,
            toggleButton = binding.firebaseToggleButton
        ) { withContext(Dispatchers.IO) { renderFirebaseSection(runFirebaseDiagnostics()) } }

        binding.runAllButton.setOnClickListener {
            lifecycleScope.launch {
                executeSection(Section.DEVICE) { renderDeviceSection() }
                executeSection(Section.KEYS) { withContext(Dispatchers.IO) { renderKeysSection(collectKeyDiagnostics()) } }
                executeSection(Section.BOOT) { withContext(Dispatchers.IO) { renderBootSection(runBootDiagnostics()) } }
                executeSection(Section.INTEGRITY) { withContext(Dispatchers.IO) { renderIntegritySection(runPlayIntegrityDiagnostics()) } }
                executeSection(Section.FIREBASE) { withContext(Dispatchers.IO) { renderFirebaseSection(runFirebaseDiagnostics()) } }
            }
        }
    }

    private fun setupSection(
        section: Section,
        summary: TextView,
        details: TextView,
        runButton: MaterialButton,
        toggleButton: MaterialButton,
        producer: suspend () -> SectionRender
    ) {
        sectionViews[section] = SectionViews(summary, details, toggleButton)
        detailVisibility[section] = false
        toggleButton.setOnClickListener { toggleDetails(section) }
        runButton.setOnClickListener { lifecycleScope.launch { executeSection(section, producer) } }
        applySectionRender(section, SectionRender(raw = "", summary = emptyList()))
    }

    private fun toggleDetails(section: Section) {
        val views = sectionViews[section] ?: return
        val current = detailVisibility[section] ?: false
        val newState = !current
        detailVisibility[section] = newState
        val hasDetails = views.details.text.isNotBlank() && views.details.text != getString(R.string.section_details_empty)
        views.details.isVisible = newState && hasDetails
        views.toggle.text = if (newState && hasDetails) {
            getString(R.string.hide_details)
        } else {
            getString(R.string.show_details)
        }
    }

    private suspend fun executeSection(section: Section, producer: suspend () -> SectionRender) {
        setSectionRunning(section)
        try {
            val render = producer()
            applySectionRender(section, render)
        } catch (t: Throwable) {
            val reason = t.localizedMessage ?: t.javaClass.simpleName
            Log.w(LOG_TAG, "Section ${section.name} failed", t)
            applySectionRender(
                section,
                SectionRender(
                    raw = getString(R.string.section_error, reason),
                    summary = listOf(getString(R.string.section_error, reason))
                )
            )
        }
    }

    private fun setSectionRunning(section: Section) {
        applySectionRender(
            section,
            SectionRender(
                raw = getString(R.string.section_running),
                summary = listOf(getString(R.string.section_running))
            )
        )
    }

    private fun applySectionRender(section: Section, render: SectionRender) {
        val views = sectionViews[section] ?: return
        val summaryText = if (render.summary.isEmpty()) {
            getString(R.string.section_summary_none)
        } else {
            render.summary.joinToString(separator = "\n")
        }
        views.summary.text = summaryText

        val trimmedRaw = render.raw.trimEnd()
        if (trimmedRaw.isEmpty()) {
            views.details.text = getString(R.string.section_details_empty)
            views.details.isVisible = false
            views.toggle.isEnabled = false
            detailVisibility[section] = false
        } else {
            views.details.text = trimmedRaw
            views.toggle.isEnabled = true
            val show = detailVisibility[section] == true
            views.details.isVisible = show
        }

        views.toggle.text = if (views.details.isVisible) {
            getString(R.string.hide_details)
        } else {
            getString(R.string.show_details)
        }
    }

    private suspend fun collectKeyDiagnostics(): KeyDiagnostics {
        return withContext(Dispatchers.IO) {
            val warnings = mutableListOf<KeyWarning>()
            val keyReports = mutableListOf<KeyReport>()

            fun collectKey(label: String, block: () -> KeyReport) {
                try {
                    keyReports += block()
                } catch (t: Throwable) {
                    val reason = t.localizedMessage ?: t.javaClass.simpleName
                    warnings += KeyWarning(label, reason)
                    Log.w(LOG_TAG, "Key assessment failed for $label", t)
                }
            }

            collectKey("RSA-2048") { assessRsaKey() }
            collectKey("EC-P256") { assessEcKey() }
            collectKey("AES-256") { assessAesKey() }

            KeyDiagnostics(keyReports, warnings)
        }
    }

    private fun renderDeviceSection(): SectionRender {
        val info = DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidVersion = Build.VERSION.RELEASE ?: "unknown",
            sdkInt = Build.VERSION.SDK_INT
        )

        val raw = buildString {
            appendLine(getString(R.string.device_info, info.manufacturer, info.model))
            appendLine(getString(R.string.android_info, info.androidVersion, info.sdkInt))
        }.trimEnd()

        val summary = listOf(
            getString(
                R.string.device_summary_line,
                info.manufacturer,
                info.model,
                info.androidVersion,
                info.sdkInt
            )
        )

        return SectionRender(raw, summary)
    }

    private fun renderKeysSection(result: KeyDiagnostics): SectionRender {
        val rawBuilder = StringBuilder()
        if (result.keys.isNotEmpty()) {
            rawBuilder.appendLine(getString(R.string.report_header))
            rawBuilder.appendLine(getString(R.string.report_divider))
            result.keys.forEach { key ->
                rawBuilder.appendLine(formatLine(key.algorithm, key.security.label, key.security.note))
            }

            rawBuilder.appendLine()
            rawBuilder.appendLine(getString(R.string.key_details_header))
            result.keys.forEach { key ->
                rawBuilder.appendLine(getString(R.string.key_detail_title, key.algorithm, key.security.label))
                rawBuilder.appendLine("  ${getString(R.string.key_detail_security, key.security.label, key.security.note)}")
                key.keySize?.let { size -> rawBuilder.appendLine("  ${getString(R.string.key_detail_size, size)}") }
                key.origin?.let { origin -> rawBuilder.appendLine("  ${getString(R.string.key_detail_origin, origin)}") }
                if (key.purposes.isNotEmpty()) {
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_purposes, key.purposes.joinToString(", "))}")
                }
                if (key.digests.isNotEmpty()) {
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_digests, key.digests.joinToString(", "))}")
                }
                if (key.blockModes.isNotEmpty()) {
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_block_modes, key.blockModes.joinToString(", "))}")
                }
                if (key.encryptionPaddings.isNotEmpty()) {
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_encryption_paddings, key.encryptionPaddings.joinToString(", "))}")
                }
                if (key.signaturePaddings.isNotEmpty()) {
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_signature_paddings, key.signaturePaddings.joinToString(", "))}")
                }
                rawBuilder.appendLine(
                    "  ${getString(
                        R.string.key_detail_user_auth,
                        booleanString(key.userAuthRequired),
                        key.userAuthHwEnforced?.let { booleanString(it) }
                            ?: getString(R.string.attestation_unknown_value)
                    )}"
                )
                key.userAuthTimeoutSeconds?.let { timeout ->
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_timeout, timeout)}")
                }
                key.trustedUserPresenceRequired?.let { value ->
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_trusted_presence, booleanString(value))}")
                }
                key.userConfirmationRequired?.let { value ->
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_user_confirmation, booleanString(value))}")
                }
                key.authValidWhileOnBody?.let { value ->
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_on_body, booleanString(value))}")
                }
                key.invalidatedByBiometricEnrollment?.let { value ->
                    rawBuilder.appendLine("  ${getString(R.string.key_detail_biometric_invalidation, booleanString(value))}")
                }
                rawBuilder.appendLine()
            }
        } else {
            rawBuilder.appendLine(getString(R.string.no_keys_collected))
        }

        if (result.warnings.isNotEmpty()) {
            rawBuilder.appendLine(getString(R.string.warnings_header))
            result.warnings.forEach { warning ->
                rawBuilder.appendLine("- ${getString(R.string.key_generation_error, warning.label, warning.reason)}")
            }
        }

        val raw = rawBuilder.toString().trimEnd()

        val total = result.keys.size
        val summaryLines = mutableListOf<String>()
        if (total == 0) {
            summaryLines += getString(R.string.keys_summary_none)
        } else {
            val hardwareCount = result.keys.count { it.security.hardwareBacked }
            summaryLines += when {
                hardwareCount == total -> getString(R.string.keys_summary_all_hardware)
                hardwareCount == 0 -> getString(R.string.keys_summary_no_hardware)
                else -> getString(R.string.keys_summary_partial_hardware, hardwareCount, total)
            }

            val strongboxCount = result.keys.count { it.security.rawLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX }
            summaryLines += if (strongboxCount > 0) {
                getString(R.string.keys_summary_strongbox_present)
            } else {
                getString(R.string.keys_summary_strongbox_missing)
            }
        }

        if (result.warnings.isNotEmpty()) {
            summaryLines += getString(R.string.keys_summary_warnings, result.warnings.size)
        }

        return SectionRender(raw, summaryLines)
    }

    private suspend fun runBootDiagnostics(): BootReportResult = withContext(Dispatchers.IO) {
        runBootAttestation()
    }

    private fun renderBootSection(result: BootReportResult): SectionRender {
        val sb = StringBuilder()
        val bootState = result.summary
        if (bootState != null) {
            sb.appendLine(getString(R.string.attestation_security_level_line, bootState.attestationSecurityLevel, bootState.keymasterSecurityLevel))
            sb.appendLine(getString(R.string.attestation_versions, bootState.attestationVersion, bootState.keymasterVersion))
            bootState.osPatchLevel?.let { sb.appendLine(getString(R.string.attestation_os_patch, it)) }
            bootState.vendorPatchLevel?.let { sb.appendLine(getString(R.string.attestation_vendor_patch, it)) }
            bootState.bootPatchLevel?.let { sb.appendLine(getString(R.string.attestation_boot_patch, it)) }
            bootState.deviceLocked?.let {
                sb.appendLine(getString(R.string.attestation_device_locked, booleanString(it)))
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
        }

        if (bootState == null) {
            if (result.messages.isEmpty()) {
                sb.appendLine(getString(R.string.attestation_no_data))
            } else {
                result.messages.forEach { sb.appendLine("- $it") }
            }
        }

        val raw = sb.toString().trimEnd()

        val summaryLines = mutableListOf<String>()
        if (bootState == null) {
            val reason = result.messages.firstOrNull()
            when {
                reason?.contains("failed to generate key pair", ignoreCase = true) == true ->
                    summaryLines += getString(R.string.boot_summary_attestation_failed)
                reason != null -> summaryLines += reason
                else -> summaryLines += getString(R.string.boot_summary_missing)
            }
        } else {
            when (bootState.deviceLocked) {
                true -> summaryLines += getString(R.string.boot_summary_locked)
                false -> summaryLines += getString(R.string.boot_summary_unlocked)
                null -> Unit
            }
            bootState.verifiedBootStateDescription?.let {
                summaryLines += getString(R.string.boot_summary_verified, it)
            }
            bootState.osPatchLevel?.let { summaryLines += getString(R.string.boot_summary_patch, it) }
            bootState.vendorPatchLevel?.let { summaryLines += getString(R.string.boot_summary_vendor_patch, it) }
            bootState.bootPatchLevel?.let { summaryLines += getString(R.string.boot_summary_boot_patch, it) }
        }

        return SectionRender(raw, summaryLines)
    }

    private suspend fun runPlayIntegrityDiagnostics(): PlayIntegrityReportResult = withContext(Dispatchers.IO) {
        runPlayIntegrityCheck()
    }

    private fun renderIntegritySection(result: PlayIntegrityReportResult): SectionRender {
        val integrity = result.summary
        val sb = StringBuilder()
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
        }

        if (integrity == null) {
            if (result.messages.isEmpty()) {
                sb.appendLine(getString(R.string.play_integrity_no_data))
            } else {
                result.messages.forEach { sb.appendLine("- $it") }
            }
        }

        val raw = sb.toString().trimEnd()

        val summaryLines = mutableListOf<String>()
        if (integrity != null) {
            summaryLines += getString(R.string.integrity_summary_success, integrity.highestIntegrityLevel)
            if (integrity.deviceRecognitionVerdicts.isNotEmpty()) {
                summaryLines += getString(
                    R.string.integrity_summary_device_verdicts,
                    integrity.deviceRecognitionVerdicts.joinToString(", ")
                )
            }
            integrity.appRecognitionVerdict?.let {
                summaryLines += getString(R.string.integrity_summary_app_verdict, it)
            }
            val licensingVerdict = integrity.accountLicensingVerdict ?: integrity.appLicensingVerdict
            licensingVerdict?.let {
                summaryLines += getString(R.string.integrity_summary_licensing_verdict, it)
            }
        } else {
            result.messages.firstOrNull()?.let {
                summaryLines += getString(R.string.integrity_summary_failure, it)
            }
        }

        return SectionRender(raw, summaryLines)
    }

    private suspend fun runFirebaseDiagnostics(): FirebaseResult = withContext(Dispatchers.IO) {
        try {
            val initialized = FirebaseApp.initializeApp(applicationContext)
                ?: FirebaseApp.getApps(applicationContext).firstOrNull()
            if (initialized != null) {
                FirebaseResult.Success(initialized.name)
            } else {
                FirebaseResult.Failure("FirebaseApp is null")
            }
        } catch (t: Throwable) {
            FirebaseResult.Failure(t.localizedMessage ?: t.javaClass.simpleName)
        }
    }

    private fun renderFirebaseSection(result: FirebaseResult): SectionRender {
        val raw = when (result) {
            is FirebaseResult.Success -> getString(R.string.firebase_success, result.appName)
            is FirebaseResult.Failure -> getString(R.string.firebase_error, result.reason)
        }

        val summary = when (result) {
            is FirebaseResult.Success -> listOf(getString(R.string.firebase_summary_success))
            is FirebaseResult.Failure -> listOf(getString(R.string.firebase_summary_failure))
        }

        return SectionRender(raw, summary)
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

    private suspend fun runBootAttestation(): BootReportResult {
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

    private fun formatLine(algo: String, level: String, note: String): String {
        val algoCol = algo.padEnd(12)
        val levelCol = level.padEnd(18)
        return "$algoCol | $levelCol | $note"
    }

    private fun booleanString(value: Boolean): String = if (value) {
        getString(R.string.attestation_yes)
    } else {
        getString(R.string.attestation_no)
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

    private data class BootReportResult(
        val summary: BootStateSummary?,
        val messages: List<String>
    )

    private data class PlayIntegrityReportResult(
        val summary: PlayIntegritySummary?,
        val messages: List<String>
    )

    private data class KeyDiagnostics(
        val keys: List<KeyReport>,
        val warnings: List<KeyWarning>
    )

    private data class KeyWarning(val label: String, val reason: String)

    private sealed class FirebaseResult {
        data class Success(val appName: String) : FirebaseResult()
        data class Failure(val reason: String) : FirebaseResult()
    }

    private enum class Section {
        DEVICE,
        KEYS,
        BOOT,
        INTEGRITY,
        FIREBASE
    }

    private data class SectionViews(
        val summary: TextView,
        val details: TextView,
        val toggle: MaterialButton
    )

    private data class SectionRender(val raw: String, val summary: List<String>)
}
