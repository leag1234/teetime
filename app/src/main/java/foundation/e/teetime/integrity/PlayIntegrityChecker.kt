package foundation.e.teetime.integrity

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.tasks.await
import foundation.e.teetime.report.PlayIntegritySummary
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

private const val TAG = "TEE_CHECK"

class PlayIntegrityChecker(private val context: Context) {

    private val random = SecureRandom()

    suspend fun check(projectNumber: Long): PlayIntegrityResult {
        val nonceBytes = ByteArray(32).apply { random.nextBytes(this) }
        val nonce = Base64.encodeToString(nonceBytes, Base64.URL_SAFE or Base64.NO_WRAP)
        val manager = IntegrityManagerFactory.create(context)
        return try {
            val response = manager
                .requestIntegrityToken(
                    IntegrityTokenRequest.builder()
                        .setNonce(nonce)
                        .setCloudProjectNumber(projectNumber)
                        .build()
                )
                .await()

            val payload = decodePayload(response.token())
            val summary = extractSummary(payload, nonceBytes)
            PlayIntegrityResult.Success(summary)
        } catch (exception: IntegrityServiceException) {
            val label = errorLabel(exception.errorCode)
            val reason = "$label (${exception.errorCode})"
            Log.w(TAG, "Play Integrity request failed: $reason", exception)
            PlayIntegrityResult.Failure(reason)
        } catch (throwable: Throwable) {
            val reason = throwable.localizedMessage ?: throwable.javaClass.simpleName
            Log.w(TAG, "Play Integrity request failed: $reason", throwable)
            PlayIntegrityResult.Failure(reason)
        }
    }

    private fun decodePayload(token: String): JSONObject {
        val parts = token.split('.')
        require(parts.size >= 2) { "Malformed Play Integrity token" }
        val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return JSONObject(String(payloadBytes, Charsets.UTF_8))
    }

    private fun extractSummary(payload: JSONObject, nonceBytes: ByteArray): PlayIntegritySummary {
        val external = payload.optJSONObject("tokenPayloadExternal") ?: payload
        val request = external.optJSONObject("requestDetails")
        val appIntegrity = external.optJSONObject("appIntegrity")
        val account = external.optJSONObject("accountDetails")
        val device = external.optJSONObject("deviceIntegrity")

        val deviceVerdicts = device?.optJSONArray("deviceRecognitionVerdict")?.toStringList().orEmpty()
        val highest = highestLevel(deviceVerdicts)
        val nonceHash = nonceBytes.sha256().toHexString()
        val requestPackage = request?.optStringOrNull("requestPackageName")
        val requestTimestamp = request?.optLong("timestampMillis")?.takeIf { it != 0L }
        val accountVerdict = account?.optStringOrNull("appLicensingVerdict")
        val appRecognition = appIntegrity?.optStringOrNull("appRecognitionVerdict")
        val appLicensing = appIntegrity?.optStringOrNull("appLicensingVerdict")

        return PlayIntegritySummary(
            highestIntegrityLevel = highest,
            deviceRecognitionVerdicts = deviceVerdicts,
            appRecognitionVerdict = appRecognition,
            appLicensingVerdict = appLicensing,
            accountLicensingVerdict = accountVerdict,
            requestPackageName = requestPackage,
            requestTimestampMillis = requestTimestamp,
            nonceSha256 = nonceHash
        )
    }

    private fun highestLevel(verdicts: List<String>): String {
        val order = listOf(
            "MEETS_STRONG_INTEGRITY",
            "MEETS_DEVICE_INTEGRITY",
            "MEETS_BASIC_INTEGRITY",
            "MEETS_VIRTUAL_INTEGRITY"
        )
        return order.firstOrNull { verdicts.contains(it) } ?: if (verdicts.isEmpty()) {
            "NO_VERDICT"
        } else {
            verdicts.first()
        }
    }

    private fun errorLabel(code: Int): String = "error_code_$code"

    private fun JSONArray.toStringList(): List<String> {
        val values = mutableListOf<String>()
        for (index in 0 until length()) {
            val value = optString(index)
            if (!value.isNullOrEmpty()) {
                values += value
            }
        }
        return values
    }

    private fun JSONObject.optStringOrNull(key: String): String? {
        if (!has(key)) return null
        val value = optString(key)
        return value.takeUnless { it.isNullOrEmpty() }
    }

    private fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)

    private fun ByteArray.toHexString(): String = joinToString(separator = "") {
        String.format(Locale.US, "%02X", it)
    }
}

sealed class PlayIntegrityResult {
    data class Success(val summary: PlayIntegritySummary) : PlayIntegrityResult()
    data class Failure(val reason: String) : PlayIntegrityResult()
}
