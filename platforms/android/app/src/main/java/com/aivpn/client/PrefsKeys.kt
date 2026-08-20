package com.aivpn.client

import android.content.Context
import android.content.SharedPreferences

object PrefsKeys {
    const val ADAPTIVE_LEVEL = "adaptive_level"
    const val PREFS_NAME = "aivpn_prefs"
    /**
     * Prefix for the per-server VPN IP the server re-homed this client to (pool
     * IP-collision resolution). Full key = this prefix + server address. When
     * present it overrides the key-embedded IP so the rebuilt TUN uses the
     * address the server's anti-spoof check actually expects.
     */
    const val PREF_VPN_IP_OVERRIDE = "vpn_ip_override_"
    /** Whether to auto-connect VPN on device boot. Stored via [BootPrefs] (device-protected). */
    const val PREF_AUTO_CONNECT = "auto_connect"
    /** Last active profile UUID, written on every explicit connect. Read by BootReceiver. */
    const val PREF_LAST_PROFILE_ID = "last_active_profile_id"
    /**
     * User intent: true from connect until an explicit manual disconnect (or revoke).
     * Stored via [BootPrefs] (device-protected) next to [PREF_LAST_PROFILE_ID].
     * Read by AivpnService.onDestroy + [VpnReconnectWorker] so a system-initiated
     * service stop (Android 12+ battery restriction, OEM power manager) can be
     * self-healed instead of silently leaving traffic on the real interface.
     */
    const val PREF_VPN_DESIRED = "vpn_desired"

    // §3 Polymorphic masks — per-session unique variant of the selected mask profile.
    /** Whether to request a polymorphic (per-session unique) variant of the selected mask. */
    const val PREF_POLYMORPHIC_ENABLED = "polymorphic_enabled"

    // §2 crowdsourced blocking feedback — opt-in, OFF by default.
    /** Whether to report blocked/working mask outcomes to the server for this region. */
    const val PREF_SHARE_MASK_FEEDBACK = "share_mask_feedback"
    /** Whether to accept server-pushed regional mask hints. */
    const val PREF_RECEIVE_MASK_HINTS = "receive_mask_hints"
    /** 2-letter ISO-3166-1 alpha-2 country code used for §2 feedback/hints. */
    const val PREF_COUNTRY_CODE = "country_code"

    // §2 crowdsourced blocking feedback — persisted outcome log + server tuning.
    // `AivpnService` owns the reconnect loop, so (unlike the desktop CLI's
    // MaskFeedbackLog file) this state lives here in plain SharedPreferences,
    // one field per concern, all on PREFS_NAME.
    /** JSON array of unreported outcome entries, e.g.
     *  `[{"mask_id":"quic_https","success":1,"fail":0}]`. Aggregated per family
     *  by the Rust core when included in the next MaskFeedback send. */
    const val PREF_FEEDBACK_OUTCOMES_JSON = "feedback_outcomes_json"
    /** Unix seconds of the last successfully sent MaskFeedback. */
    const val PREF_FEEDBACK_LAST_REPORT_UNIX = "feedback_last_report_unix"
    /** Server-pushed FeedbackConfig.report_failure_threshold (default 3 if unset). */
    const val PREF_FEEDBACK_FAILURE_THRESHOLD = "feedback_failure_threshold"
    /** Server-pushed FeedbackConfig.report_interval_secs (default 3600 if unset). */
    const val PREF_FEEDBACK_INTERVAL_SECS = "feedback_interval_secs"
    /** JSON object of mask family -> consecutive failed-attempt count, carried across
     *  reconnect iterations (mirrors desktop main.rs's `consecutive_fails` map). */
    const val PREF_FEEDBACK_CONSECUTIVE_FAILS_JSON = "feedback_consecutive_fails_json"
    /** Most recently received RegionalMaskHints, JSON-encoded
     *  (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`). */
    const val PREF_REGIONAL_HINTS_JSON = "regional_hints_json"

    // Modular transport settings seam (TransportSettingsRegistry) — an opaque
    // transport override produced by a registered provider's TransportChoice.
    // Absent (both keys removed) = use the built-in default transport.
    /** Short transport name understood by the native core, e.g. from a closed edition. */
    const val PREF_EXT_TRANSPORT_NAME = "ext_transport_name"
    /** JSON parameter object accompanying [PREF_EXT_TRANSPORT_NAME]. */
    const val PREF_EXT_TRANSPORT_PARAMS = "ext_transport_params"
}

/**
 * Boot-critical preferences ([PrefsKeys.PREF_AUTO_CONNECT], [PrefsKeys.PREF_LAST_PROFILE_ID])
 * stored in **device-protected (DE) storage**.
 *
 * On FBE devices, credential-encrypted (CE) storage — where plain SharedPreferences
 * normally live — is NOT available during Direct Boot (between reboot and the first
 * user unlock): `Context.getSharedPreferences` throws IllegalStateException there.
 * [BootReceiver] runs on ACTION_LOCKED_BOOT_COMPLETED, so everything it reads must
 * come from DE storage via [android.content.Context.createDeviceProtectedStorageContext].
 *
 * The DE prefs file uses the same name as [PrefsKeys.PREFS_NAME] but is a physically
 * separate file (different storage area); it holds ONLY the boot-critical keys.
 */
object BootPrefs {

    /** Marker: legacy CE→DE one-time migration completed. Lives in the DE file. */
    private const val PREF_DE_MIGRATION_DONE = "de_migration_done"

    fun prefs(context: Context): SharedPreferences =
        context.createDeviceProtectedStorageContext()
            .getSharedPreferences(PrefsKeys.PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * One-time migration of boot-critical prefs written by older app versions into
     * plain CE SharedPreferences. Safe to call from anywhere, any number of times:
     * silently no-ops while the device is still locked (CE unavailable) and retries
     * on the next call after unlock. Existing DE values are never overwritten.
     */
    fun migrateFromCredentialStorage(context: Context) {
        val de = prefs(context)
        if (de.getBoolean(PREF_DE_MIGRATION_DONE, false)) return
        try {
            val ce = context.getSharedPreferences(PrefsKeys.PREFS_NAME, Context.MODE_PRIVATE)
            val editor = de.edit()
            if (!de.contains(PrefsKeys.PREF_AUTO_CONNECT) && ce.contains(PrefsKeys.PREF_AUTO_CONNECT)) {
                editor.putBoolean(
                    PrefsKeys.PREF_AUTO_CONNECT,
                    ce.getBoolean(PrefsKeys.PREF_AUTO_CONNECT, false)
                )
            }
            if (!de.contains(PrefsKeys.PREF_LAST_PROFILE_ID)) {
                ce.getString(PrefsKeys.PREF_LAST_PROFILE_ID, null)
                    ?.takeIf { it.isNotBlank() }
                    ?.let { editor.putString(PrefsKeys.PREF_LAST_PROFILE_ID, it) }
            }
            editor.putBoolean(PREF_DE_MIGRATION_DONE, true).apply()
        } catch (e: Exception) {
            // CE storage locked (Direct Boot) or otherwise unavailable — retry later.
            android.util.Log.d("BootPrefs", "CE→DE migration deferred: ${e.message}")
        }
    }
}
