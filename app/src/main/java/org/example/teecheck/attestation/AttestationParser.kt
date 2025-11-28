package org.example.teecheck.attestation

import java.math.BigInteger
import java.security.cert.X509Certificate

private const val ATTESTATION_RECORD_OID = "1.3.6.1.4.1.11129.2.1.17"

private const val TAG_CLASS_UNIVERSAL = 0x00
private const val TAG_CLASS_CONTEXT_SPECIFIC = 0x80

private const val KM_TAG_ROOT_OF_TRUST = 704
private val KM_TAG_OS_VERSION = intArrayOf(402, 514)
private val KM_TAG_OS_PATCHLEVEL = intArrayOf(403, 515)
private val KM_TAG_BOOT_PATCHLEVEL = intArrayOf(404, 543, 547)
private val KM_TAG_VENDOR_PATCHLEVEL = intArrayOf(518, 541)

/** Holds the subset of attestation data we surface in the UI. */
data class BootStateReport(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: SecurityLevel,
    val osVersion: Int?,
    val osPatchLevel: Int?,
    val bootPatchLevel: Int?,
    val vendorPatchLevel: Int?,
    val verifiedBootKey: ByteArray?,
    val deviceLocked: Boolean?,
    val verifiedBootState: VerifiedBootState?,
    val verifiedBootHash: ByteArray?
)

enum class SecurityLevel(val rawValue: Int) {
    SOFTWARE(0),
    TRUSTED_ENVIRONMENT(1),
    STRONGBOX(2),
    UNKNOWN(-1);

    companion object {
        fun fromRaw(value: Int): SecurityLevel = values().firstOrNull { it.rawValue == value } ?: UNKNOWN
    }
}

enum class VerifiedBootState(val rawValue: Int, val description: String) {
    VERIFIED(0, "GREEN (verified)"),
    SELF_SIGNED(1, "YELLOW (self-signed key)"),
    UNVERIFIED(2, "ORANGE (unverified)"),
    FAILED(3, "RED (verification failed)"),
    UNKNOWN(-1, "Unknown");

    companion object {
        fun fromRaw(value: Int): VerifiedBootState = values().firstOrNull { it.rawValue == value } ?: UNKNOWN
    }
}

/** Parses the attestation extension and extracts verified boot information. */
object AttestationParser {
    fun parseBootState(certificate: X509Certificate): BootStateReport? {
        val extensionBytes = certificate.getExtensionValue(ATTESTATION_RECORD_OID) ?: return null
        val recordOctet = DerReader(extensionBytes).readElement() ?: return null
        if (recordOctet.tagClass != TAG_CLASS_UNIVERSAL || recordOctet.tagNumber != DerTag.OCTET_STRING) return null

        val recordReader = DerReader(recordOctet.content)
        val root = recordReader.readElement() ?: return null
        if (root.tagClass != TAG_CLASS_UNIVERSAL || root.tagNumber != DerTag.SEQUENCE) return null

        val recordElements = DerReader(root.content)
        val attestationVersion = recordElements.readElement()?.asInteger()?.toInt() ?: return null
        val attestationSecurityLevel = recordElements.readElement()?.asInteger()?.toInt()?.let(SecurityLevel::fromRaw) ?: SecurityLevel.UNKNOWN
        val keymasterVersion = recordElements.readElement()?.asInteger()?.toInt() ?: return null
        val keymasterSecurityLevel = recordElements.readElement()?.asInteger()?.toInt()?.let(SecurityLevel::fromRaw) ?: SecurityLevel.UNKNOWN
        recordElements.readElement() // attestationChallenge (ignored)
        recordElements.readElement() // uniqueId (ignored)

        val softwareEnforced = recordElements.readElement()
        val teeEnforced = recordElements.readElement()

        val teeTags = parseAuthorizationList(teeEnforced)
        val softwareTags = parseAuthorizationList(softwareEnforced)

        val bootTags = teeTags.ifEmpty { softwareTags }
        val osVersion = pickTag(teeTags, softwareTags, KM_TAG_OS_VERSION)?.asInteger()?.toInt()
        val osPatchLevel = pickTag(teeTags, softwareTags, KM_TAG_OS_PATCHLEVEL)?.asInteger()?.toInt()
        val bootPatchLevel = pickTag(bootTags, emptyMap<Int, DerElement>(), KM_TAG_BOOT_PATCHLEVEL)?.asInteger()?.toInt()
        val vendorPatchLevel = pickTag(teeTags, softwareTags, KM_TAG_VENDOR_PATCHLEVEL)?.asInteger()?.toInt()

        val rootOfTrustElement = teeTags[KM_TAG_ROOT_OF_TRUST] ?: softwareTags[KM_TAG_ROOT_OF_TRUST]
        val rootOfTrust = rootOfTrustElement?.asSequence()

        val verifiedBootKey = rootOfTrust?.getOrNull(0)?.asOctetString()
        val deviceLocked = rootOfTrust?.getOrNull(1)?.asBoolean()
        val verifiedBootState = rootOfTrust?.getOrNull(2)?.asEnumerated()?.toInt()?.let(VerifiedBootState::fromRaw)
        val verifiedBootHash = rootOfTrust?.getOrNull(3)?.asOctetString()

        return BootStateReport(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel,
            keymasterVersion = keymasterVersion,
            keymasterSecurityLevel = keymasterSecurityLevel,
            osVersion = osVersion,
            osPatchLevel = osPatchLevel,
            bootPatchLevel = bootPatchLevel,
            vendorPatchLevel = vendorPatchLevel,
            verifiedBootKey = verifiedBootKey,
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState,
            verifiedBootHash = verifiedBootHash
        )
    }
}

private data class DerElement(
    val tagClass: Int,
    val constructed: Boolean,
    val tagNumber: Int,
    val content: ByteArray
) {
    fun asInteger(): BigInteger = BigInteger(1, content)
    fun asEnumerated(): BigInteger = asInteger()
    fun asBoolean(): Boolean = content.isNotEmpty() && content[0].toInt() != 0
    fun asOctetString(): ByteArray = content
    fun asSequence(): List<DerElement> {
        if (!constructed) return emptyList()
        val reader = DerReader(content)
        val result = mutableListOf<DerElement>()
        while (true) {
            val next = reader.readElement() ?: break
            result += next
        }
        return result
    }
}

private object DerTag {
    const val BOOLEAN = 0x01
    const val INTEGER = 0x02
    const val OCTET_STRING = 0x04
    const val SEQUENCE = 0x10
    const val ENUMERATED = 0x0A
}

private class DerReader(private val data: ByteArray) {
    private var offset = 0

    fun readElement(): DerElement? {
        if (offset >= data.size) return null

        val tagByte = data[offset++].toInt() and 0xFF
        val tagClass = tagByte and 0xC0
        val constructed = (tagByte and 0x20) != 0
        var tagNumber = tagByte and 0x1F
        if (tagNumber == 0x1F) {
            tagNumber = 0
            while (true) {
                if (offset >= data.size) return null
                val b = data[offset++].toInt() and 0xFF
                tagNumber = (tagNumber shl 7) or (b and 0x7F)
                if (b and 0x80 == 0) break
            }
        }

        val length = readLength() ?: return null
        if (offset + length > data.size) return null
        val content = data.copyOfRange(offset, offset + length)
        offset += length

        return DerElement(tagClass, constructed, tagNumber, content)
    }

    private fun readLength(): Int? {
        if (offset >= data.size) return null
        val first = data[offset++].toInt() and 0xFF
        if (first and 0x80 == 0) {
            return first
        }
        val numBytes = first and 0x7F
        if (numBytes == 0 || numBytes > 4 || offset + numBytes > data.size) return null
        var length = 0
        repeat(numBytes) {
            length = (length shl 8) or (data[offset++].toInt() and 0xFF)
        }
        return length
    }
}

private fun pickTag(
    primary: Map<Int, DerElement>,
    secondary: Map<Int, DerElement>,
    candidates: IntArray
): DerElement? {
    candidates.forEach { candidate ->
        primary[candidate]?.let { return it }
        secondary[candidate]?.let { return it }
    }
    return null
}

private fun parseAuthorizationList(element: DerElement?): Map<Int, DerElement> {
    if (element == null) return emptyMap()
    val reader = DerReader(element.content)
    val result = mutableMapOf<Int, DerElement>()
    while (true) {
        val child = reader.readElement() ?: break
        if (child.tagClass == TAG_CLASS_CONTEXT_SPECIFIC) {
            val value = if (child.constructed) {
                val innerReader = DerReader(child.content)
                innerReader.readElement() ?: child
            } else {
                child
            }
            result[child.tagNumber] = value
        }
    }
    return result
}
