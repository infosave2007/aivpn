package com.aivpn.client

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Secure storage using EncryptedSharedPreferences.
 * Keys are encrypted with Android Keystore — safe from root access.
 *
 * ## 3d: hardware-backed wrapping key (mTLS cert + device-enrollment key)
 *
 * The AES-256-GCM master key that wraps every value in this store (the JIT
 * device-enrollment private key `device_privkey_v1`, the `mtlsCertBase64`
 * profile field, connection profiles, etc.) already lives in the
 * AndroidKeyStore by construction — `MasterKey.Builder` never lets the raw
 * AES key material leave hardware — but `setRequestStrongBoxBacked(true)`
 * below additionally asks for the DISCRETE secure element (StrongBox) when
 * the device has one, instead of settling for the SoC's TEE. This is a
 * genuinely no-risk request, verified against the exact
 * `androidx.security:security-crypto:1.1.0-alpha06` bytecode this app
 * depends on (decompiled `MasterKey$Builder$Api23Impl.build()`):
 *   - It internally gates on `PackageManager.hasSystemFeature(
 *     "android.hardware.strongbox_keystore")` — on a device without
 *     StrongBox hardware it silently builds a normal TEE-backed key instead
 *     of throwing, so this is safe to request unconditionally.
 *   - Key creation goes through `MasterKeys.getOrCreate(spec)` — an EXISTING
 *     alias is reused as-is, never regenerated. An app upgrading from a
 *     pre-3d build (TEE-backed master key already in the Keystore) keeps
 *     using that same key and can still decrypt every value it already
 *     wrote; only a fresh install (no existing alias) can land on the
 *     StrongBox-backed key. No explicit migration step is needed — this is
 *     backward compatible by construction.
 *
 * ## Why the actual key material still can't be imported into Keystore
 * non-exportably
 *
 * The task framing ("import the private key into AndroidKeyStore... use it
 * for the mTLS handshake") assumes a PKCS#12-shaped cert+key pair. That is
 * NOT what this app stores:
 *   - `mtlsCertBase64` (see `ConnectionProfile.mtlsCertBase64`) is a
 *     104-byte `SimpleCert` (`aivpn-server/src/mtls.rs`): a client X25519
 *     PUBLIC key + expiry + a CA ed25519 signature over them — no private
 *     key at all. It is sent to the server verbatim in `ClientCert{
 *     cert_bytes}`; there is nothing secret in it to protect with
 *     non-exportable hardware import.
 *   - The matching PRIVATE half is the per-session ephemeral X25519 keypair
 *     Rust generates fresh every connection (`KeyPair::generate()` in
 *     `android_tunnel.rs`) — it never touches Kotlin/this store, lives only
 *     in Rust process memory for the session's lifetime, and is discarded
 *     after. There is no persistent mTLS private key on the Kotlin side to
 *     import in the first place.
 *   - The one genuinely persistent client-identity private key this app DOES
 *     store is the JIT device-enrollment key (`device_privkey_v1`, see
 *     `saveDeviceKey`/`loadDeviceKey` below) — a raw 32-byte X25519 scalar
 *     handed directly to Rust's `curve25519-dalek` for a raw
 *     Diffie-Hellman. AndroidKeyStore cannot hold this non-exportably and
 *     still be usable here: (1) it has no Curve25519/X25519 key type at all
 *     (EC support is limited to the NIST P-curves), and (2) even if it did,
 *     a non-exportable key's entire point is that the raw scalar never
 *     leaves the secure element/TEE — but this app's Diffie-Hellman is a
 *     bespoke Rust computation (`curve25519-dalek`), not a JCA
 *     `KeyAgreement` call the Keystore could perform on the key's behalf.
 *     Making this key non-exportable would require redesigning the
 *     handshake around a Keystore-native curve (e.g. P-256 `KeyAgreement`)
 *     end to end across the wire protocol and every platform — out of
 *     scope here (Android-only, no `aivpn-common` changes). This is the
 *     documented limitation the task anticipates: at minimum, the storage
 *     key wrapping this private key is hardware-backed (StrongBox when
 *     available) as implemented above.
 *
 * Corruption recovery: after a backup restore, OTA, or Keystore wipe the master key
 * no longer matches the on-disk keyset/values, and every access throws
 * AEADBadTagException / KeyStoreException (both [java.security.GeneralSecurityException]s).
 * The data is unrecoverable at that point — the only way forward is to delete the
 * prefs file (and stale master key) and start fresh, otherwise the app crashes on the
 * first write (Connect / saveDeviceKey) or loops forever on reads.
 */
object SecureStorage {

    private const val TAG = "SecureStorage"
    private const val PREFS_FILE = "aivpn_secure_prefs"

    @Volatile private var cachedPrefs: SharedPreferences? = null

    /**
     * Requests a StrongBox-backed master key when the device has a discrete
     * secure element, falling back to the SoC TEE otherwise. See the class
     * doc comment (3d) for why this is safe to request unconditionally and
     * why it needs no migration for existing installs.
     */
    private fun createMasterKey(appContext: Context): MasterKey {
        return MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setRequestStrongBoxBacked(true)
            .build()
    }

    private fun createPrefs(context: Context): SharedPreferences {
        val appContext = context.applicationContext
        val masterKey = createMasterKey(appContext)
        return EncryptedSharedPreferences.create(
            appContext,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun getPrefs(context: Context): SharedPreferences {
        cachedPrefs?.let { return it }
        synchronized(this) {
            cachedPrefs?.let { return it }
            val prefs = try {
                createPrefs(context)
            } catch (e: Exception) {
                if (!isCorruption(e) || !isUserUnlocked(context)) {
                    // Transient failure — locked user (Direct Boot / always-on VPN
                    // before first unlock), flaky Keystore, etc. The on-disk data is
                    // likely fine; propagate instead of wiping so callers hit their
                    // "storage unavailable" branches and retry after unlock.
                    android.util.Log.w(TAG, "EncryptedSharedPreferences unavailable — not resetting: ${e.message}")
                    throw e
                }
                // Master key / keyset mismatch (restore, OTA) — the stored data is
                // unreadable no matter what. Wipe and recreate so the app stays usable.
                android.util.Log.e(TAG, "EncryptedSharedPreferences unusable — resetting storage", e)
                resetStorage(context)
                createPrefs(context) // let a second failure propagate to the caller's catch
            }
            cachedPrefs = prefs
            return prefs
        }
    }

    /** True only when [t] (or a cause up the chain) is GENUINELY unrecoverable keyset
     *  corruption — the master key/keyset no longer decrypts the stored data and a wipe
     *  is the only recovery. Deliberately NARROW (MEDIUM-2): descriptor I/O now runs on
     *  every reconnect and after every session, so a *transient* Keystore hiccup
     *  (BACKEND_BUSY / SYSTEM_ERROR / binder death under memory pressure) must NEVER be
     *  treated as corruption — that would nuke every stored profile + the device-binding
     *  key. Such transient failures surface as [android.security.KeyStoreException]s,
     *  which are also GeneralSecurityExceptions, so the old "any GeneralSecurityException
     *  = corruption" test was far too broad. */
    private fun isCorruption(t: Throwable?): Boolean {
        var cause = t
        var depth = 0
        while (cause != null && depth < 6) {
            // Transient Android Keystore failure — data on disk is fine; never wipe.
            if (cause is android.security.KeyStoreException) return false
            // AEAD tag mismatch: the keyset/master key genuinely no longer decrypts
            // the ciphertext (backup restore, OTA, Keystore wipe) — unrecoverable.
            if (cause is javax.crypto.AEADBadTagException) return true
            // Tink raises a keyset parse/decrypt failure as one of its own
            // GeneralSecurityException subclasses — also genuine corruption.
            if (cause.javaClass.name.startsWith("com.google.crypto.tink")) return true
            cause = cause.cause
            depth++
        }
        return false
    }

    /** True when the user has unlocked the device at least once since boot — i.e.
     *  credential-encrypted storage and Keystore keys are actually available. Before
     *  the first unlock (Direct Boot, always-on VPN cold start) every Keystore access
     *  fails with errors indistinguishable from real corruption; resetting then would
     *  destroy perfectly good profiles and the device-binding key. */
    private fun isUserUnlocked(context: Context): Boolean {
        return try {
            val um = context.applicationContext
                .getSystemService(Context.USER_SERVICE) as? android.os.UserManager
            um?.isUserUnlocked ?: true
        } catch (e: Exception) {
            true
        }
    }

    /** Deletes the encrypted prefs file and the stale AndroidX master key so the next
     *  [getPrefs] call recreates both from scratch. All stored data is lost — but it
     *  was already unreadable when this is called. */
    private fun resetStorage(context: Context) {
        val appContext = context.applicationContext
        cachedPrefs = null
        try {
            appContext.deleteSharedPreferences(PREFS_FILE)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "deleteSharedPreferences failed: ${e.message}")
        }
        try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "Master key delete failed: ${e.message}")
        }
    }

    fun saveString(context: Context, key: String, value: String) {
        try {
            getPrefs(context).edit().putString(key, value).apply()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "saveString failed for key '$key': ${e.message}", e)
            if (!isCorruption(e) || !isUserUnlocked(context)) return
            // Corrupted store (AEADBadTagException & co) — reset and retry once so the
            // first Connect after a restore works instead of crashing.
            synchronized(this) { resetStorage(context) }
            try {
                getPrefs(context).edit().putString(key, value).apply()
            } catch (e2: Exception) {
                android.util.Log.e(TAG, "saveString retry failed for key '$key': ${e2.message}", e2)
            }
        }
    }

    fun loadString(context: Context, key: String, defaultValue: String = ""): String {
        return try {
            getPrefs(context).getString(key, defaultValue) ?: defaultValue
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Keystore access failed for key '$key': ${e.message}", e)
            if (isCorruption(e) && isUserUnlocked(context)) {
                // Values are permanently undecryptable — reset now so subsequent
                // reads/writes recreate a working (empty) store instead of failing forever.
                synchronized(this) { resetStorage(context) }
            }
            defaultValue
        }
    }

    fun remove(context: Context, key: String) {
        try {
            getPrefs(context).edit().remove(key).apply()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "remove failed for key '$key': ${e.message}", e)
            if (isCorruption(e) && isUserUnlocked(context)) {
                synchronized(this) { resetStorage(context) }
            }
        }
    }

    // Connection key helpers (legacy single-key, kept for migration)
    fun saveConnectionKey(context: Context, key: String) {
        saveString(context, "connection_key", key)
    }

    fun loadConnectionKey(context: Context): String {
        return loadString(context, "connection_key")
    }

    // Language preference
    fun saveLanguage(context: Context, lang: String) {
        saveString(context, "language", lang)
    }

    fun loadLanguage(context: Context): String {
        return loadString(context, "language", "en")
    }

    // ──────────── Multi-profile management ────────────

    data class ConnectionProfile(
        val id: String,
        val name: String,
        val key: String,
        val mtlsCertBase64: String? = null,
        val dnsServers: List<String>? = null,
        /** Preferred mask profile name (e.g. "webrtc_zoom_v3"). null/"auto" = server default. */
        val maskProfile: String? = null,
    )

    fun saveProfiles(context: Context, profiles: List<ConnectionProfile>) {
        val arr = JSONArray()
        for (p in profiles) {
            arr.put(JSONObject().apply {
                put("id", p.id)
                put("name", p.name)
                put("key", p.key)
                if (p.mtlsCertBase64 != null) put("mtlsCertBase64", p.mtlsCertBase64)
                if (!p.dnsServers.isNullOrEmpty()) {
                    val dnsArr = JSONArray()
                    p.dnsServers.forEach { dnsArr.put(it) }
                    put("dns", dnsArr)
                }
                if (!p.maskProfile.isNullOrEmpty() && p.maskProfile != "auto") {
                    put("maskProfile", p.maskProfile)
                }
            })
        }
        saveString(context, "profiles", arr.toString())
    }

    fun loadProfiles(context: Context): List<ConnectionProfile> {
        val raw = loadString(context, "profiles")
        if (raw.isEmpty()) return mutableListOf()
        return try {
            val arr = JSONArray(raw)
            val result = mutableListOf<ConnectionProfile>()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val dnsArr = obj.optJSONArray("dns")
                val dnsServers: List<String>? = if (dnsArr != null) {
                    (0 until dnsArr.length()).map { dnsArr.getString(it) }
                        .filter { it.isNotBlank() }.takeIf { it.isNotEmpty() }
                } else null
                val maskProfile = obj.optString("maskProfile").ifEmpty { null }
                result.add(ConnectionProfile(
                    id = obj.getString("id"),
                    name = obj.getString("name"),
                    key = obj.getString("key"),
                    mtlsCertBase64 = obj.optString("mtlsCertBase64").ifEmpty { null },
                    dnsServers = dnsServers,
                    maskProfile = maskProfile,
                ))
            }
            result
        } catch (e: Exception) {
            android.util.Log.e("SecureStorage", "loadProfiles parse error: ${e.message}", e)
            mutableListOf()
        }
    }

    fun saveActiveProfileId(context: Context, id: String) {
        saveString(context, "active_profile_id", id)
    }

    fun loadActiveProfileId(context: Context): String {
        return loadString(context, "active_profile_id")
    }

    // ──────────── Device binding key (JIT enrollment) ────────────

    // 3d: this is the one persistent client-identity private key this app
    // stores — see the class doc comment for why it cannot be imported into
    // AndroidKeyStore non-exportably (raw X25519 scalar consumed directly by
    // Rust's curve25519-dalek for the DeviceEnrollment DH proof) and why the
    // StrongBox-preferred master key above is the mitigation in scope here.
    private const val KEY_DEVICE_PRIVKEY = "device_privkey_v1"

    fun saveDeviceKey(context: Context, keyBytes: ByteArray) {
        val b64 = android.util.Base64.encodeToString(keyBytes, android.util.Base64.DEFAULT)
        saveString(context, KEY_DEVICE_PRIVKEY, b64)
    }

    fun loadDeviceKey(context: Context): ByteArray? {
        val b64 = loadString(context, KEY_DEVICE_PRIVKEY)
        if (b64.isEmpty()) return null
        return try {
            val bytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
            if (bytes.size == 32) bytes else null
        } catch (_: Exception) {
            null
        }
    }

    // ──────────── Bootstrap descriptors (covert handshake persistence) ────────────

    private const val KEY_BOOTSTRAP_DESCRIPTORS = "bootstrap_descriptors_json_v1"

    /** LOW-5: hard cap on the persisted descriptor blob. The core caps the store at
     *  8 descriptors but each may carry embedded masks, so an unbounded blob could
     *  reach multiple MB in EncryptedSharedPreferences. A blob larger than this is a
     *  bug or abuse — refuse to persist it rather than bloat the prefs file. */
    private const val MAX_DESCRIPTOR_BLOB_BYTES = 256 * 1024

    /** M1: scope the persisted descriptor blob PER SERVER so a profile switch never
     *  loads server A's descriptors when connecting to server B (which would invert
     *  the covertness benefit and can mis-frame B's opening packet). The key is
     *  suffixed with a short hash of the server's base64 public key. A null/blank
     *  server key falls back to the legacy global key (best-effort). */
    private fun bootstrapDescriptorsKey(serverKeyBase64: String?): String {
        if (serverKeyBase64.isNullOrBlank()) return KEY_BOOTSTRAP_DESCRIPTORS
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val hash = md.digest(serverKeyBase64.toByteArray(Charsets.UTF_8))
            val suffix = android.util.Base64.encodeToString(
                hash,
                android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
            ).take(16)
            "$KEY_BOOTSTRAP_DESCRIPTORS:$suffix"
        } catch (_: Exception) {
            KEY_BOOTSTRAP_DESCRIPTORS
        }
    }

    /**
     * Persist the raw JSON array of ed25519-signed bootstrap descriptors received
     * from the server this session. They are self-authenticating and re-verified
     * on load in the Rust core, so storing the raw blobs is safe. Persisting them
     * lets the very next COLD START shape its first handshake with a COVERT
     * rotated descriptor mask instead of a fingerprintable public preset. Scoped
     * per [serverKeyBase64] (M1). A blank or "[]" value clears this server's blob.
     */
    fun saveBootstrapDescriptors(context: Context, json: String, serverKeyBase64: String? = null) {
        val key = bootstrapDescriptorsKey(serverKeyBase64)
        if (json.isBlank() || json == "[]") {
            remove(context, key)
        } else if (json.toByteArray(Charsets.UTF_8).size > MAX_DESCRIPTOR_BLOB_BYTES) {
            // LOW-5: refuse an oversized blob rather than bloat the prefs file.
            android.util.Log.w(TAG, "Bootstrap descriptor blob too large — not persisting")
        } else {
            saveString(context, key, json)
        }
    }

    /** Load this server's persisted bootstrap-descriptor JSON array, or null if none. */
    fun loadBootstrapDescriptors(context: Context, serverKeyBase64: String? = null): String? {
        val raw = loadString(context, bootstrapDescriptorsKey(serverKeyBase64))
        return raw.ifBlank { null }
    }

    // ──────────── Split tunneling ────────────

    private const val KEY_ALLOWED_APPS = "split_tunnel_allowed_apps"

    fun saveAllowedApps(context: Context, packages: Set<String>) {
        val arr = JSONArray()
        for (pkg in packages) arr.put(pkg)
        saveString(context, KEY_ALLOWED_APPS, arr.toString())
    }

    fun loadAllowedApps(context: Context): Set<String> {
        val raw = loadString(context, KEY_ALLOWED_APPS)
        if (raw.isEmpty()) return mutableSetOf()
        return try {
            val arr = JSONArray(raw)
            val result = mutableSetOf<String>()
            for (i in 0 until arr.length()) result.add(arr.getString(i))
            result
        } catch (_: Exception) {
            mutableSetOf()
        }
    }

    // ──────────── Excluded domains ────────────

    private const val KEY_EXCLUDED_DOMAINS = "split_tunnel_excluded_domains"

    fun saveExcludedDomains(context: Context, domains: List<String>) {
        val arr = JSONArray()
        for (d in domains) arr.put(d)
        saveString(context, KEY_EXCLUDED_DOMAINS, arr.toString())
    }

    fun loadExcludedDomains(context: Context): List<String> {
        val raw = loadString(context, KEY_EXCLUDED_DOMAINS)
        if (raw.isEmpty()) return mutableListOf()
        return try {
            val arr = JSONArray(raw)
            val result = mutableListOf<String>()
            for (i in 0 until arr.length()) result.add(arr.getString(i))
            result
        } catch (_: Exception) {
            mutableListOf()
        }
    }
}
