package com.aivpn.client

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Bootstrap descriptor discovery — advanced/operator-only flow.
 *
 * A `BootstrapDescriptor` (see crates/aivpn-common/src/mask.rs) carries only signed,
 * rotating traffic-mimicry MASK material — it does NOT carry a server host, port, or
 * public key. This flow cannot "discover a server from nothing": the operator still
 * hands the user a server address, server public key, optional PSK, and the descriptor
 * signing public key through some other low-bandwidth channel (word of mouth, SMS, a QR
 * code). What this automates is fetching fresh, signed mask material for that known
 * server instead of requiring a brand-new full connection key every time a mask gets
 * DPI-fingerprinted.
 *
 * Channels implemented: CDN (direct HTTPS URL) and GitHub (releases/latest asset named
 * "bootstrap"). Telegram is best-effort via the Bot API's getUpdates long-poll (only
 * sees messages since the bot's last poll offset — a known limitation, not a bug). No
 * IPFS (excluded server-side too, see bootstrap_publish.rs).
 */
object BootstrapDiscovery {

    data class ChannelSettings(
        val cdnUrl: String = "",
        val githubRepo: String = "",
        val telegramBotToken: String = "",
        val telegramChatId: String = "",
        val signingPublicKeyBase64: String = "",
    )

    data class ChannelResult(val channel: String, val success: Boolean, val descriptorCount: Int, val error: String?)

    data class DiscoveryOutcome(val validDescriptorJsons: List<String>, val channelResults: List<ChannelResult>)

    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MAX_REDIRECTS = 5

    /**
     * Rejects non-HTTPS URLs and hosts that are (or resolve to) private, loopback,
     * link-local, ULA, or CGNAT addresses (SSRF guard).
     *
     * The literal string checks are only a cheap fast-fail: they miss decimal/octal/hex
     * IPv4 spellings ("2130706433", "0177.0.0.1"), IPv6 link-local/ULA, IPv4-mapped IPv6,
     * and any hostname that RESOLVES to a private address (DNS rebinding). So the host is
     * then resolved and every resolved address is checked; unresolvable hosts fail closed.
     * Residual: HttpURLConnection re-resolves at fetch time, so a fast-fluxing rebinder
     * can still swap records between this check and the fetch — impact stays bounded
     * because responses must carry valid ed25519-signed descriptors to be used at all.
     * Mirrors the iOS guard in BootstrapDiscovery.swift.
     */
    private fun isUrlAllowed(urlString: String): Boolean {
        if (!urlString.startsWith("https://", ignoreCase = true)) return false
        val host = try { URL(urlString).host?.lowercase() } catch (_: Exception) { null } ?: return false
        if (host == "localhost" || host == "::1") return false
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") ||
            host.startsWith("169.254.")
        ) return false
        if (host.startsWith("172.")) {
            val second = host.split(".").getOrNull(1)?.toIntOrNull()
            if (second != null && second in 16..31) return false
        }
        return hostResolvesToPublicAddressesOnly(host)
    }

    /** True only when `host` resolves to at least one address and NONE of them is private. */
    private fun hostResolvesToPublicAddressesOnly(host: String): Boolean {
        val addresses = try {
            InetAddress.getAllByName(host)
        } catch (_: Exception) {
            return false // unresolvable / malformed: fail closed
        }
        return addresses.isNotEmpty() && addresses.none { isPrivateAddress(it) }
    }

    /**
     * True when the address is loopback / RFC1918 / link-local / CGNAT / broadcast IPv4,
     * or loopback / unspecified / link-local / site-local / unique-local /
     * IPv4-mapped-private IPv6 — anything a bootstrap fetch must never be pointed at.
     * Unknown address families fail closed.
     */
    private fun isPrivateAddress(addr: InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isAnyLocalAddress ||
            addr.isLinkLocalAddress || addr.isSiteLocalAddress
        ) return true
        fun privateV4(a: Int, b: Int): Boolean = when (a) {
            0, 10, 127, 255 -> true
            169 -> b == 254
            172 -> b in 16..31
            192 -> b == 168
            100 -> b in 64..127 // CGNAT 100.64.0.0/10
            else -> false
        }
        val bytes = addr.address
        return when (bytes.size) {
            4 -> privateV4(bytes[0].toInt() and 0xFF, bytes[1].toInt() and 0xFF)
            16 -> {
                val b0 = bytes[0].toInt() and 0xFF
                val b1 = bytes[1].toInt() and 0xFF
                when {
                    // ::1 loopback / :: unspecified
                    (0..14).all { bytes[it].toInt() == 0 } && (bytes[15].toInt() and 0xFF) <= 1 -> true
                    // fe80::/10 link-local, fec0::/10 (deprecated site-local)
                    b0 == 0xfe && (b1 and 0xc0) == 0x80 -> true
                    b0 == 0xfe && (b1 and 0xc0) == 0xc0 -> true
                    // fc00::/7 unique-local
                    (b0 and 0xfe) == 0xfc -> true
                    // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d):
                    // re-check the embedded IPv4 against the same private ranges.
                    (0..9).all { bytes[it].toInt() == 0 } &&
                        (((bytes[10].toInt() and 0xFF) == 0xFF && (bytes[11].toInt() and 0xFF) == 0xFF) ||
                            (bytes[10].toInt() == 0 && bytes[11].toInt() == 0)) ->
                        privateV4(bytes[12].toInt() and 0xFF, bytes[13].toInt() and 0xFF)
                    else -> false
                }
            }
            else -> true // unknown family: fail closed
        }
    }

    private fun httpGet(urlString: String): String? {
        var current = urlString
        // Redirects are followed manually so the SSRF guard re-applies to every hop —
        // instanceFollowRedirects would silently follow to an unchecked host.
        for (hop in 0..MAX_REDIRECTS) {
            if (!isUrlAllowed(current)) return null
            val conn = URL(current).openConnection() as HttpURLConnection
            try {
                conn.connectTimeout = CONNECT_TIMEOUT_MS
                conn.readTimeout = READ_TIMEOUT_MS
                conn.instanceFollowRedirects = false
                conn.setRequestProperty("User-Agent", "aivpn-android")
                val code = conn.responseCode
                if (code in 300..399) {
                    val location = conn.getHeaderField("Location") ?: return null
                    current = URL(URL(current), location).toString()
                    continue
                }
                if (code !in 200..299) return null
                if (conn.contentLengthLong > BootstrapResponse.MAX_BYTES) return null
                return conn.inputStream.use { BootstrapResponse.read(it) }
            } catch (_: Exception) {
                return null
            } finally {
                conn.disconnect()
            }
        }
        return null // redirect chain too long
    }

    /** Splits a channel response body (JSON array or single object) into individual descriptor JSON strings. */
    private fun splitDescriptors(body: String): List<String> {
        return try {
            val trimmed = body.trim()
            if (trimmed.startsWith("[")) {
                val arr = JSONArray(trimmed)
                (0 until arr.length()).map { arr.getJSONObject(it).toString() }
            } else {
                listOf(JSONObject(trimmed).toString())
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun verifyAll(body: String, signingKey: ByteArray, nowUnixSecs: Long): List<String> {
        return splitDescriptors(body).filter { json ->
            try {
                AivpnJni.verifyBootstrapDescriptor(json, signingKey, nowUnixSecs)
            } catch (_: Throwable) {
                // Throwable, not Exception: if libaivpn_core.so failed to load this
                // call throws UnsatisfiedLinkError (an Error) — must not crash discovery.
                false
            }
        }
    }

    private fun fetchCdn(settings: ChannelSettings, signingKey: ByteArray, now: Long): Pair<List<String>, ChannelResult> {
        val body = httpGet(settings.cdnUrl)
            ?: return emptyList<String>() to ChannelResult("CDN", false, 0, "fetch failed or URL rejected")
        val valid = verifyAll(body, signingKey, now)
        return valid to ChannelResult("CDN", true, valid.size, null)
    }

    private fun fetchGithub(settings: ChannelSettings, signingKey: ByteArray, now: Long): Pair<List<String>, ChannelResult> {
        val repo = settings.githubRepo.trim()
        val releaseJson = httpGet("https://api.github.com/repos/$repo/releases/latest")
            ?: return emptyList<String>() to ChannelResult("GitHub", false, 0, "failed to fetch latest release")
        return try {
            val release = JSONObject(releaseJson)
            val assets = release.getJSONArray("assets")
            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)
                val name = asset.optString("name")
                if (!name.contains("bootstrap")) continue
                val downloadUrl = asset.optString("browser_download_url")
                if (!isUrlAllowed(downloadUrl)) continue
                val body = httpGet(downloadUrl) ?: continue
                val valid = verifyAll(body, signingKey, now)
                return valid to ChannelResult("GitHub", true, valid.size, null)
            }
            emptyList<String>() to ChannelResult("GitHub", false, 0, "no bootstrap asset found in latest release")
        } catch (e: Exception) {
            emptyList<String>() to ChannelResult("GitHub", false, 0, e.message)
        }
    }

    private fun fetchTelegram(settings: ChannelSettings, signingKey: ByteArray, now: Long): Pair<List<String>, ChannelResult> {
        val token = settings.telegramBotToken.trim()
        val wantChat = settings.telegramChatId.trim()
        val updatesJson = httpGet("https://api.telegram.org/bot$token/getUpdates?limit=50")
            ?: return emptyList<String>() to ChannelResult("Telegram", false, 0, "getUpdates failed")
        return try {
            val json = JSONObject(updatesJson)
            val updates = json.getJSONArray("result")
            for (i in updates.length() - 1 downTo 0) {
                val update = updates.getJSONObject(i)
                val message = update.optJSONObject("message") ?: update.optJSONObject("channel_post") ?: continue
                if (wantChat.isNotEmpty()) {
                    val chat = message.optJSONObject("chat")
                    val idMatches = chat?.opt("id")?.toString() == wantChat
                    val usernameMatches = chat?.optString("username")?.let { "@$it" == wantChat } ?: false
                    if (!idMatches && !usernameMatches) continue
                }
                val document = message.optJSONObject("document") ?: continue
                val fileId = document.optString("file_id")
                val fileMetaJson = httpGet("https://api.telegram.org/bot$token/getFile?file_id=$fileId") ?: continue
                val filePath = JSONObject(fileMetaJson).optJSONObject("result")?.optString("file_path") ?: continue
                val body = httpGet("https://api.telegram.org/file/bot$token/$filePath") ?: continue
                val valid = verifyAll(body, signingKey, now)
                if (valid.isNotEmpty()) {
                    return valid to ChannelResult("Telegram", true, valid.size, null)
                }
            }
            emptyList<String>() to ChannelResult(
                "Telegram", false, 0,
                "no verifiable bootstrap document found in recent updates (getUpdates only sees messages since the bot's last poll)",
            )
        } catch (e: Exception) {
            emptyList<String>() to ChannelResult("Telegram", false, 0, e.message)
        }
    }

    /** Runs every configured channel; each is independent, one failing never blocks the others. */
    fun discover(settings: ChannelSettings, nowUnixSecs: Long): DiscoveryOutcome {
        val signingKey = try {
            Base64.decode(settings.signingPublicKeyBase64.trim(), Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        }
        if (signingKey == null || signingKey.size != 32) {
            return DiscoveryOutcome(
                emptyList(),
                listOf(ChannelResult("config", false, 0, "signing public key must be 32 bytes, base64-encoded")),
            )
        }

        val allValid = mutableListOf<String>()
        val results = mutableListOf<ChannelResult>()

        if (settings.cdnUrl.isNotBlank()) {
            val (valid, result) = fetchCdn(settings, signingKey, nowUnixSecs)
            allValid += valid
            results += result
        }
        if (settings.githubRepo.isNotBlank()) {
            val (valid, result) = fetchGithub(settings, signingKey, nowUnixSecs)
            allValid += valid
            results += result
        }
        if (settings.telegramBotToken.isNotBlank()) {
            val (valid, result) = fetchTelegram(settings, signingKey, nowUnixSecs)
            allValid += valid
            results += result
        }

        return DiscoveryOutcome(allValid, results)
    }
}
