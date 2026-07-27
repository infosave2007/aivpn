package com.aivpn.client

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log

/**
 * Quick Settings tile (notification shade shortcut) for toggling the VPN.
 * Requires Android 7+ (API 24). Registered in AndroidManifest.xml with the
 * BIND_QUICK_SETTINGS_TILE permission so only the system can bind to it.
 *
 * State sync: tile state is updated via AivpnService.tileCallback on every
 * connect/reconnect/terminal transition, and synced each time the shade is opened
 * (onStartListening). States: ACTIVE while a session is actually established
 * (isEstablished=true — set only after the handshake completes, unlike isRunning
 * which is true for the whole JNI attempt), ACTIVE with a "Connecting…" subtitle
 * while connecting or retrying (isServiceActive=true, isEstablished=false — kept
 * clickable so a stuck retry can be cancelled from the shade), INACTIVE while
 * disconnected.
 *
 * Connect flow: loads the active profile from SecureStorage, parses the
 * connection key, then fires AivpnService.ACTION_CONNECT. If VPN permission
 * has not been granted yet, opens MainActivity to let the user grant it.
 * On Android 12+ a ForegroundServiceStartNotAllowedException is caught and
 * also falls back to opening MainActivity.
 */
class AivpnTileService : TileService() {

    companion object {
        private const val TAG = "AivpnTileService"
    }

    override fun onStartListening() {
        super.onStartListening()
        AivpnService.tileCallback = { syncTileState() }
        syncTileState()
    }

    override fun onStopListening() {
        super.onStopListening()
        AivpnService.tileCallback = null
    }

    override fun onClick() {
        super.onClick()
        if (AivpnService.isServiceActive) {
            disconnectVpn()
        } else {
            connectVpn()
        }
    }

    // ──────────── Private helpers ────────────

    private fun syncTileState() {
        val tile = qsTile ?: return
        when {
            AivpnService.isEstablished -> {
                tile.state = Tile.STATE_ACTIVE
                tile.contentDescription = getString(R.string.status_connected, getString(R.string.app_name))
                setSubtitle(tile, null)
            }
            AivpnService.isServiceActive -> {
                // L4: NOT STATE_UNAVAILABLE — an unavailable tile is unclickable,
                // so a connect attempt stuck in the retry loop could not be
                // cancelled from the shade (the only escape was opening the app).
                // ACTIVE + "Connecting…" subtitle keeps onClick usable: the
                // isServiceActive branch there sends ACTION_DISCONNECT.
                tile.state = Tile.STATE_ACTIVE
                tile.contentDescription = getString(R.string.status_connecting)
                setSubtitle(tile, getString(R.string.status_connecting))
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                tile.contentDescription = getString(R.string.status_disconnected)
                setSubtitle(tile, null)
            }
        }
        tile.updateTile()
    }

    /** Tile.setSubtitle exists only from API 29 (Q); no-op below. */
    private fun setSubtitle(tile: Tile, text: CharSequence?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = text
        }
    }

    private fun disconnectVpn() {
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_DISCONNECT
        }
        startService(intent)
        qsTile?.let { tile ->
            tile.state = Tile.STATE_INACTIVE
            tile.updateTile()
        }
    }

    private fun connectVpn() {
        // If VPN permission has not been granted yet the service cannot start.
        // Open MainActivity so the user can grant it through the normal flow.
        val vpnPermissionIntent = android.net.VpnService.prepare(this)
        if (vpnPermissionIntent != null) {
            openMainActivity()
            return
        }

        val profileId = SecureStorage.loadActiveProfileId(this)
        val profile = SecureStorage.loadProfiles(this)
            .let { list -> list.find { it.id == profileId } ?: list.firstOrNull() }

        if (profile == null) {
            Log.w(TAG, "No profile configured — opening MainActivity")
            qsTile?.let { it.state = Tile.STATE_UNAVAILABLE; it.updateTile() }
            openMainActivity()
            return
        }

        // Pass only the profile ID via Intent; AivpnService loads the keys
        // from EncryptedSharedPreferences to avoid plaintext IPC extras.
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("profile_id", profile.id)
        }

        try {
            startForegroundService(intent)
            // Remain INACTIVE until Rust handshake completes and tileCallback fires STATE_ACTIVE.
        } catch (e: Exception) {
            // ForegroundServiceStartNotAllowedException (API 31+) or any other failure:
            // fall back to opening the main app so the user can connect from the foreground.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                e.javaClass.name == "android.app.ForegroundServiceStartNotAllowedException"
            ) {
                Log.w(TAG, "ForegroundServiceStartNotAllowedException — opening MainActivity")
            } else {
                Log.e(TAG, "startForegroundService failed: ${e.message}", e)
            }
            openMainActivity()
        }
    }

    private fun openMainActivity() {
        val main = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            val pending = android.app.PendingIntent.getActivity(
                this, 0, main, android.app.PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(main)
        }
    }
}
