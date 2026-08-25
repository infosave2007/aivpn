package com.aivpn.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log

/**
 * Starts the VPN tunnel after device reboot if "auto-connect on startup" is enabled
 * and at least one connection profile exists.
 *
 * Handles both ACTION_BOOT_COMPLETED (post-unlock) and ACTION_LOCKED_BOOT_COMPLETED
 * (Direct Boot — fires before the user unlocks the device for the first time after reboot).
 * During Direct Boot, credential-encrypted (CE) storage — plain SharedPreferences AND
 * EncryptedSharedPreferences — is unavailable, so all reads here go through [BootPrefs]
 * (device-protected storage). The actual connection profiles (keys) live in CE-backed
 * EncryptedSharedPreferences, so on LOCKED_BOOT_COMPLETED we can only defer: the real
 * auto-connect happens on BOOT_COMPLETED, which fires after the first unlock.
 *
 * Note: VPN permission must have been previously granted by the user. If the permission
 * was revoked (VpnService.prepare() returns non-null), the auto-connect is skipped — the
 * user must open the app to re-grant permission.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"

        /** Single background lane for boot handling (L5) — at most one boot at a time anyway. */
        private val EXECUTOR = java.util.concurrent.Executors.newSingleThreadExecutor()
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED) return

        // L5: handleBoot() hits EncryptedSharedPreferences/Keystore (real disk +
        // Binder I/O, hundreds of ms cold) — onReceive runs on the MAIN thread,
        // where that risks an ANR during the post-boot stampede. goAsync() keeps
        // the receiver alive (~10 s budget) while the work runs on an executor.
        val pending = goAsync()
        val appContext = context.applicationContext
        EXECUTOR.execute {
            // Belt-and-braces: a crash inside a boot receiver would repeat on EVERY reboot.
            try {
                handleBoot(appContext, action)
            } catch (e: Exception) {
                Log.e(TAG, "Boot auto-connect failed: ${e.message}", e)
            } finally {
                pending.finish()
            }
        }
    }

    private fun handleBoot(context: Context, action: String) {
        // Boot-critical prefs live in device-protected storage (readable during Direct
        // Boot). Migrate legacy CE values first — a no-op while the device is locked.
        BootPrefs.migrateFromCredentialStorage(context)
        val prefs = BootPrefs.prefs(context)
        if (!prefs.getBoolean(PrefsKeys.PREF_AUTO_CONNECT, false)) return

        if (action == Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            // Direct Boot: the connection profiles are in EncryptedSharedPreferences
            // (CE storage + Keystore), unavailable until first unlock. Starting the
            // service now would only burn a foreground-service start and fail.
            // BOOT_COMPLETED fires after unlock and performs the actual auto-connect.
            Log.i(TAG, "LOCKED_BOOT_COMPLETED: deferring auto-connect until user unlock")
            return
        }

        // Post-unlock (BOOT_COMPLETED): secure storage is available — verify profiles.
        val profiles = try {
            SecureStorage.loadProfiles(context)
        } catch (e: Exception) {
            Log.w(TAG, "SecureStorage unavailable: ${e.message}")
            emptyList()
        }
        if (profiles.isEmpty()) {
            Log.i(TAG, "No profiles found — skipping auto-connect")
            return
        }

        // Resolve the profile to connect: the securely-stored active profile ID first,
        // then the DE-prefs copy of the last connected ID, then the first profile.
        // Every candidate is validated against the actual profile list so a stale ID
        // (profile deleted since last connect) cannot select the wrong server.
        val activeId = try {
            SecureStorage.loadActiveProfileId(context).takeIf { it.isNotBlank() }
        } catch (e: Exception) { null }
        val lastId = prefs.getString(PrefsKeys.PREF_LAST_PROFILE_ID, null)?.takeIf { it.isNotBlank() }
        val profileId = when {
            activeId != null && profiles.any { it.id == activeId } -> activeId
            lastId != null && profiles.any { it.id == lastId }     -> lastId
            else                                                    -> profiles.first().id
        }

        // VpnService.prepare() returns null when VPN permission is already granted.
        // A non-null result means the user needs to re-grant from the app; we cannot
        // show the system dialog from a BroadcastReceiver.
        if (VpnService.prepare(context) != null) {
            Log.w(TAG, "VPN permission not granted — skipping auto-connect on boot")
            return
        }

        launchVpnService(context, profileId)
    }

    private fun launchVpnService(context: Context, profileId: String) {
        val serviceIntent = Intent(context, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("profile_id", profileId)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                @Suppress("DEPRECATION")
                context.startService(serviceIntent)
            }
            Log.i(TAG, "Auto-connect started for profile=$profileId")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN service on boot: ${e.message}")
        }
    }
}
