package com.aivpn.client

import android.util.Base64
import org.json.JSONObject

data class ParsedConnectionKey(
    val server: String,
    val serverKey: String,
    val psk: String?,
    val vpnIp: String,
    val serverVpnIp: String,
    val prefixLen: Int,
    val mtu: Int,
    /** Base64 (standard) ed25519 server signing/verifying key, or null. Enables
     * signature verification of ServerHello / MaskUpdate / bootstrap descriptors. */
    val serverSigningKey: String? = null,
    /** Base64 (standard) ed25519 mask-operator verifying key ("mop" field), or null.
     * Enables artifact-level signature verification of MaskUpdate profiles — distinct
     * from [serverSigningKey], which authenticates the transport push, not the mask
     * artifact itself. Mirrors desktop's `--mask-operator-pubkey` / `mop` sourcing. */
    val maskOperatorPubkey: String? = null,
)

object ConnectionKeyParser {

    /**
     * Parse connection key: aivpn://BASE64URL({"s":"host:port","k":"...","p":"...","i":"...","n":{...}})
     * Returns null on any parse/validation error.
     */
    fun parse(key: String): ParsedConnectionKey? {
        val raw = key.trim()
        val payload = if (raw.startsWith("aivpn://")) raw.removePrefix("aivpn://") else raw
        return try {
            val jsonBytes = Base64.decode(
                payload,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            )
            val json = JSONObject(String(jsonBytes))
            val server = json.getString("s")
            val serverKey = json.getString("k")
            val psk = json.optString("p").takeUnless { it.isNullOrBlank() }
            val serverSigningKey = json.optString("sk").takeUnless { it.isNullOrBlank() }
            val maskOperatorPubkey = json.optString("mop").takeUnless { it.isNullOrBlank() }
            val networkConfig = json.optJSONObject("n")
            val vpnIp = networkConfig?.optString("client_ip")?.takeUnless { it.isNullOrBlank() }
                ?: json.optString("i").takeUnless { it.isNullOrBlank() } ?: return null
            val serverVpnIp = networkConfig?.optString("server_vpn_ip")?.takeUnless { it.isNullOrBlank() }
                ?: "10.0.0.1"
            val prefixLen = networkConfig?.optInt("prefix_len", 24) ?: 24
            val mtu = networkConfig?.optInt("mtu", 1346) ?: 1346

            if (!isValidIpv4(vpnIp) || !isValidIpv4(serverVpnIp) || prefixLen !in 1..30 || mtu !in 576..1500) {
                return null
            }
            // The client_ip must be an ASSIGNABLE host for its prefix. A
            // format-valid but non-host address (network or broadcast address
            // of the subnet, e.g. 10.0.0.0/24 or 10.0.0.255/24) passes
            // isValidIpv4 but is rejected by the kernel at
            // VpnService.establish() with an opaque "Cannot set address",
            // looping the tunnel forever. Reject it here so a bad key never
            // reaches the builder. (Loopback/multicast are already excluded by
            // isValidIpv4.)
            if (!isAssignableHost(vpnIp, prefixLen)) {
                return null
            }

            ParsedConnectionKey(
                server, serverKey, psk, vpnIp, serverVpnIp, prefixLen, mtu,
                serverSigningKey, maskOperatorPubkey,
            )
        } catch (_: Exception) {
            null
        }
    }

    /** Extract the server host (without port) from a connection key string, or "" on failure. */
    fun serverAddrFrom(key: String): String {
        val parsed = parse(key) ?: return ""
        val server = parsed.server
        // IPv6 bracketed notation: [::1]:443 -> ::1
        if (server.startsWith("[")) {
            val end = server.indexOf(']')
            return if (end > 1) server.substring(1, end) else server
        }
        return server.substringBeforeLast(':').ifEmpty { server }
    }

    private fun isValidIpv4(value: String): Boolean {
        val octets = octetsOf(value) ?: return false
        val first = octets[0]
        // Reject address classes Android's VpnService will not accept as a TUN
        // address: unspecified (0.x), loopback (127.x), multicast (224–239),
        // and reserved/broadcast (>=240 incl. 255.255.255.255). Plain
        // "4 octets 0–255" used to pass all of these, which then failed at
        // establish() with an opaque "Cannot set address".
        if (first == 0 || first == 127 || first in 224..239 || first >= 240) return false
        return true
    }

    /** Parse "a.b.c.d" into 4 ints in 0..255, or null if malformed. */
    private fun octetsOf(value: String): IntArray? {
        val parts = value.split(".")
        if (parts.size != 4) return null
        val out = IntArray(4)
        for (i in 0 until 4) {
            val n = parts[i].toIntOrNull() ?: return null
            if (n !in 0..255) return null
            out[i] = n
        }
        return out
    }

    /**
     * True if [ip] is a usable host address within its /[prefixLen] subnet —
     * i.e. NOT the network address (all host bits 0) and NOT the broadcast
     * address (all host bits 1). Both are format-valid but unassignable and
     * make VpnService.establish() throw "Cannot set address".
     */
    private fun isAssignableHost(ip: String, prefixLen: Int): Boolean {
        val octets = octetsOf(ip) ?: return false
        if (prefixLen !in 1..30) return true // /31,/32 have no host/broadcast split; nothing to reject
        val addr = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
        val hostBits = 32 - prefixLen
        val hostMask = (1L shl hostBits) - 1 // fits in Long to avoid Int overflow at hostBits=31
        val host = addr.toLong() and hostMask
        return host != 0L && host != hostMask
    }
}
