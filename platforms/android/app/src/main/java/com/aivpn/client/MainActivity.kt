package com.aivpn.client

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.aivpn.client.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.UUID

/**
 * Main screen — server address, public key, connect/disconnect button,
 * connection timer, traffic stats, and EN/RU language toggle.
 *
 * v0.3.0: Uses EncryptedSharedPreferences for secure key storage.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var profilesAdapter: ProfilesAdapter
    private lateinit var viewModel: MainViewModel
    private var isConnected = false
    private var currentQualityScore: Int = 0
    private var currentRecordingService: String = ""

    private var profiles = mutableListOf<SecureStorage.ConnectionProfile>()
    private var activeProfileId: String? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, getString(R.string.error_vpn_denied), Toast.LENGTH_SHORT).show()
        }
    }

    // Android 13+ requires a runtime grant for POST_NOTIFICATIONS; without it the
    // tunnel foreground notification and connect/disconnect events are silently
    // suppressed on fresh installs. The VPN itself works either way, so a denial
    // needs no handling — we simply stay without notifications.
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* no-op: VPN functionality does not depend on the grant */ }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    // Connection timer
    private val timerHandler = Handler(Looper.getMainLooper())
    private var connectionStartTime = 0L
    private val timerRunnable = object : Runnable {
        override fun run() {
            if (isConnected && connectionStartTime > 0) {
                val elapsed = (System.currentTimeMillis() - connectionStartTime) / 1000
                val h = elapsed / 3600
                val m = (elapsed % 3600) / 60
                val s = elapsed % 60
                binding.textTimer.text = String.format("%02d:%02d:%02d", h, m, s)
                // textDuration shows the fixed session START time (see the connected
                // branch), NOT a second elapsed counter — so it no longer ticks here.
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        viewModel = ViewModelProvider(this).get(MainViewModel::class.java)
        // Restore isConnected and connectionStartTime from ViewModel so they survive rotation.
        viewModel.connectionState.observe(this) { state ->
            isConnected = state == ConnectionState.CONNECTED
        }
        viewModel.connectionStartTime.observe(this) { startTime ->
            connectionStartTime = startTime
        }

        // One-time migration of boot-critical prefs (auto-connect, last profile ID)
        // from plain CE SharedPreferences into device-protected storage, where
        // BootReceiver can read them during Direct Boot without crashing.
        BootPrefs.migrateFromCredentialStorage(this)

        // Android 13+: ask for notification permission up front so the user sees
        // the tunnel status notification and connect/disconnect events.
        requestNotificationPermissionIfNeeded()

        binding.versionFooter.text = "v${BuildConfig.VERSION_NAME} · ${getString(R.string.version_tagline)}"

        profilesAdapter = ProfilesAdapter(
            onProfileClick = { profile ->
                if (!isConnected) {
                    activeProfileId = profile.id
                    SecureStorage.saveActiveProfileId(this, profile.id)
                    binding.editConnectionKey.setText(profile.key)
                    renderProfiles()
                    // Sync button label to the newly selected profile
                    val name = profiles.find { it.id == activeProfileId }?.name
                    binding.btnConnect.text = if (name != null)
                        "${getString(R.string.btn_connect)} · $name"
                    else
                        getString(R.string.btn_connect)
                }
            },
            onEditClick   = { showProfileDialog(it) },
            onDeleteClick = { confirmDeleteProfile(it) },
        )
        binding.profileList.layoutManager = LinearLayoutManager(this)
        binding.profileList.adapter = profilesAdapter

        // Migrate legacy single connection key to profiles
        migrateLegacyKey()

        // Load profiles
        profiles = SecureStorage.loadProfiles(this).toMutableList()
        activeProfileId = SecureStorage.loadActiveProfileId(this)

        // If we have an active profile, load its key into the field
        val active = profiles.find { it.id == activeProfileId }
        if (active != null) {
            binding.editConnectionKey.setText(active.key)
        } else if (profiles.isNotEmpty()) {
            activeProfileId = profiles[0].id
            binding.editConnectionKey.setText(profiles[0].key)
            SecureStorage.saveActiveProfileId(this, profiles[0].id)
        } else {
            // Fallback: try legacy key
            binding.editConnectionKey.setText(SecureStorage.loadConnectionKey(this))
        }

        renderProfiles()

        // Update language button label
        updateLanguageButton()

        binding.btnConnect.setOnClickListener {
            if (AivpnService.isServiceActive) disconnect() else connect()
        }

        binding.btnLanguage.setOnClickListener {
            toggleLanguage()
        }

        binding.btnAddProfile.setOnClickListener {
            showProfileDialog(null)
        }

        binding.btnSplitTunnel.setOnClickListener {
            startActivity(Intent(this, SplitTunnelActivity::class.java))
        }

        // Background reliability & permissions health check — the button and its
        // status hint both open the checklist (the hint says "tap to fix").
        val openBgHealth = View.OnClickListener {
            startActivity(Intent(this, BackgroundHealthActivity::class.java))
        }
        binding.btnBgHealth.setOnClickListener(openBgHealth)
        binding.textBgHealthHint.setOnClickListener(openBgHealth)

        binding.btnOptions.setOnClickListener { showOptionsMenu(it) }

        updateSplitTunnelHint()

        // Restore connection state from the service's tri-state (single source of
        // truth). The terminal DISCONNECTED branch is essential: if the service died
        // while this Activity was not visible, the old two-branch isRunning/
        // isServiceActive check matched nothing and left the UI frozen at
        // "Connected" with a running timer and stale traffic counters.
        resyncFromService()
    }

    /** Renders the current AivpnService.uiState. Used by onCreate and onResume. */
    private fun resyncFromService() {
        when (AivpnService.uiState) {
            AivpnService.UiState.CONNECTED -> {
                isConnected = true
                updateUI(true, AivpnService.lastStatusText)
            }
            AivpnService.UiState.CONNECTING -> {
                isConnected = false
                updateUI(false, AivpnService.lastStatusText, connecting = true)
            }
            AivpnService.UiState.DISCONNECTED -> {
                isConnected = false
                updateUI(
                    false,
                    AivpnService.lastStatusText.ifEmpty { getString(R.string.status_disconnected) }
                )
            }
        }
    }

    // ──────────── Profile management ────────────

    private fun migrateLegacyKey() {
        val legacyKey = SecureStorage.loadConnectionKey(this)
        if (legacyKey.isNotEmpty()) {
            val existing = SecureStorage.loadProfiles(this)
            if (existing.none { it.key == legacyKey }) {
                val profile = SecureStorage.ConnectionProfile(
                    id = UUID.randomUUID().toString(),
                    name = extractServerName(legacyKey),
                    key = legacyKey
                )
                val updated = existing.toMutableList()
                updated.add(profile)
                SecureStorage.saveProfiles(this, updated)
                SecureStorage.saveActiveProfileId(this, profile.id)
            }
            SecureStorage.remove(this, "connection_key")
        }
    }

    private fun extractServerName(connectionKey: String): String {
        val parsed = parseConnectionKey(connectionKey) ?: return "Server"
        val server = parsed.server
        // IPv6 bracketed notation: [::1]:443 -> ::1
        if (server.startsWith("[")) {
            val end = server.indexOf(']')
            return if (end > 1) server.substring(1, end) else server
        }
        return server.substringBeforeLast(':').ifEmpty { server }
    }

    private fun renderProfiles() {
        profilesAdapter.activeProfileId = activeProfileId
        profilesAdapter.editingEnabled = !isConnected
        profilesAdapter.submitList(profiles.toList())
        binding.textProfilesEmpty.visibility =
            if (profiles.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun showProfileDialog(existing: SecureStorage.ConnectionProfile?) {
        if (isConnected) return

        // Use the dialog's theme context so EditText fields inherit proper colours
        // (white text, grey hints) instead of defaulting to the dark-on-dark activity theme.
        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)

        val layout = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }

        val nameInput = EditText(dialogCtx).apply {
            hint = getString(R.string.hint_profile_name)
            setText(existing?.name ?: "")
            setSingleLine(true)
        }
        val keyInput = EditText(dialogCtx).apply {
            hint = getString(R.string.hint_profile_key)
            setText(existing?.key ?: "")
            setSingleLine(true)
            textSize = 13f
        }
        val certInput = EditText(dialogCtx).apply {
            hint = getString(R.string.mtls_cert_hint)
            setText(existing?.mtlsCertBase64 ?: "")
            setSingleLine(true)
            textSize = 12f
        }
        val certLabel = TextView(dialogCtx).apply {
            text = getString(R.string.mtls_cert)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }

        val dnsLabel = TextView(dialogCtx).apply {
            text = getString(R.string.label_dns_servers)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }
        val dnsInput = EditText(dialogCtx).apply {
            hint = getString(R.string.hint_dns_servers)
            setText(existing?.dnsServers?.joinToString(", ") ?: "")
            setSingleLine(true)
            textSize = 13f
        }

        val maskLabel = TextView(dialogCtx).apply {
            text = getString(R.string.mask_profile_label)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }
        // Build the mask list from the server-pushed catalog when available
        // (marks auto-generated masks "(авто)"); otherwise fall back to presets.
        val catalogJson = try { AivpnJni.getMaskCatalogJson() } catch (_: Throwable) { "" }
        val maskIds = mutableListOf("auto")
        val maskDisplayList = mutableListOf(getString(R.string.mask_auto))
        if (catalogJson.isNotEmpty()) {
            try {
                val arr = org.json.JSONArray(catalogJson)
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val id = o.optString("mask_id")
                    if (id.isEmpty() || id == "auto") continue
                    val label = o.optString("label", id)
                    val gen = o.optBoolean("generated", false)
                    maskIds.add(id)
                    maskDisplayList.add(if (gen) label + getString(R.string.mask_auto_marker) else label)
                }
            } catch (_: Throwable) {}
        }
        if (maskIds.size == 1) {
            for (id in MASK_OPTIONS.drop(1)) {
                maskIds.add(id)
                maskDisplayList.add(id)
            }
        }
        val maskDisplayNames = maskDisplayList.toTypedArray()
        val maskSpinner = android.widget.Spinner(dialogCtx)
        val maskAdapter = android.widget.ArrayAdapter(
            dialogCtx, android.R.layout.simple_spinner_item, maskDisplayNames
        ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        maskSpinner.adapter = maskAdapter
        val currentMask = existing?.maskProfile
        val maskIdx = if (currentMask.isNullOrEmpty() || currentMask == "auto") 0
                      else maskIds.indexOf(currentMask).let { if (it > 0) it else 0 }
        maskSpinner.setSelection(maskIdx)

        layout.addView(nameInput)
        layout.addView(keyInput)
        layout.addView(certLabel)
        layout.addView(certInput)
        layout.addView(dnsLabel)
        layout.addView(dnsInput)
        layout.addView(maskLabel)
        layout.addView(maskSpinner)

        val title = if (existing != null)
            getString(R.string.dialog_edit_profile)
        else
            getString(R.string.dialog_add_profile)

        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(title)
            .setView(layout)
            .setPositiveButton(getString(R.string.btn_save)) { _, _ ->
                val name = nameInput.text.toString().trim()
                val key = keyInput.text.toString().trim()

                if (name.isEmpty()) {
                    Toast.makeText(this, getString(R.string.error_profile_name_empty), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (key.isEmpty()) {
                    Toast.makeText(this, getString(R.string.error_profile_key_empty), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (parseConnectionKey(key) == null) {
                    Toast.makeText(this, getString(R.string.error_profile_key_invalid), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                val certRaw = certInput.text.toString().trim()
                val mtlsCert: String? = if (certRaw.isEmpty()) null else {
                    val decoded = try {
                        android.util.Base64.decode(certRaw, android.util.Base64.DEFAULT)
                    } catch (_: Exception) { null }
                    if (decoded == null || decoded.size != 104) {
                        Toast.makeText(this, getString(R.string.mtls_cert_invalid), Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    certRaw
                }

                val dnsRaw = dnsInput.text.toString().trim()
                val dnsServers: List<String>? = if (dnsRaw.isEmpty()) null else
                    dnsRaw.split(",").map { it.trim() }.filter { it.isNotBlank() }
                        .takeIf { it.isNotEmpty() }

                val selectedMaskIdx = maskSpinner.selectedItemPosition
                val maskProfileValue: String? =
                    if (selectedMaskIdx <= 0) null
                    else maskIds.getOrNull(selectedMaskIdx)

                if (existing != null) {
                    val idx = profiles.indexOfFirst { it.id == existing.id }
                    if (idx >= 0) {
                        profiles[idx] = existing.copy(
                            name = name, key = key,
                            mtlsCertBase64 = mtlsCert, dnsServers = dnsServers,
                            maskProfile = maskProfileValue,
                        )
                        // Keep the connection key field in sync when editing the active profile
                        if (existing.id == activeProfileId) {
                            binding.editConnectionKey.setText(key)
                        }
                    }
                } else {
                    val newProfile = SecureStorage.ConnectionProfile(
                        id = UUID.randomUUID().toString(),
                        name = name,
                        key = key,
                        mtlsCertBase64 = mtlsCert,
                        dnsServers = dnsServers,
                        maskProfile = maskProfileValue,
                    )
                    profiles.add(newProfile)
                    activeProfileId = newProfile.id
                    SecureStorage.saveActiveProfileId(this, newProfile.id)
                    binding.editConnectionKey.setText(key)
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private fun confirmDeleteProfile(profile: SecureStorage.ConnectionProfile) {
        if (isConnected) return
        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setMessage(getString(R.string.confirm_delete_profile, profile.name))
            .setPositiveButton(getString(R.string.btn_delete)) { _, _ ->
                profiles.removeAll { it.id == profile.id }
                // Drop the boot-time "last connected profile" mirror if it pointed at the
                // deleted profile, so BootReceiver / always-on restore can't resurrect a
                // stale ID and silently connect to a different (first-in-list) server.
                val bootPrefs = BootPrefs.prefs(this)
                if (bootPrefs.getString(PrefsKeys.PREF_LAST_PROFILE_ID, null) == profile.id) {
                    bootPrefs.edit().remove(PrefsKeys.PREF_LAST_PROFILE_ID).apply()
                }
                if (activeProfileId == profile.id) {
                    activeProfileId = profiles.firstOrNull()?.id
                    activeProfileId?.let { SecureStorage.saveActiveProfileId(this, it) }
                    binding.editConnectionKey.setText(
                        profiles.firstOrNull()?.key ?: ""
                    )
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    private fun updateSplitTunnelHint() {
        val appCount = SecureStorage.loadAllowedApps(this).size
        val siteCount = SecureStorage.loadExcludedDomains(this).size
        binding.textSplitTunnelHint.text = when {
            appCount > 0 && siteCount > 0 -> getString(R.string.split_tunnel_hint_combined,
                getString(R.string.split_tunnel_hint_apps, appCount),
                getString(R.string.split_tunnel_hint_sites, siteCount))
            appCount > 0 -> getString(R.string.split_tunnel_vpn_count, appCount)
            siteCount > 0 -> getString(R.string.split_tunnel_bypass_count, siteCount)
            else -> getString(R.string.split_tunnel_desc)
        }
    }

    override fun onResume() {
        super.onResume()
        // Register callbacks when activity becomes visible.
        // Using onResume/onPause instead of onCreate/onDestroy prevents the race condition
        // where a destroyed (rotated) Activity nullifies callbacks registered by the new one.
        AivpnService.statusCallback = { connected, statusText ->
            runOnUiThread {
                isConnected = connected
                updateUI(connected, statusText)
            }
        }

        AivpnService.trafficCallback = { uploadBytes, downloadBytes ->
            val quality = AivpnJni.getQualityScore()
            runOnUiThread {
                binding.textUpload.text = formatBytes(uploadBytes)
                binding.textDownload.text = formatBytes(downloadBytes)
                currentQualityScore = quality
            }
        }

        AivpnService.recordingCallback = { feedbackJson ->
            runOnUiThread { handleRecordingFeedback(feedbackJson) }
        }

        // L3: the core hands each recording-feedback message out exactly once;
        // one polled while this Activity was paused was buffered by the service
        // instead of dropped. Deliver it now (take-once).
        AivpnService.pendingRecordingFeedback?.let { buffered ->
            AivpnService.pendingRecordingFeedback = null
            handleRecordingFeedback(buffered)
        }

        // Restore UI state from the service tri-state (e.g. after returning from
        // the VPN permission dialog, screen rotation — or after the service DIED
        // while this Activity was paused, which the old two-branch check missed,
        // freezing the UI at "Connected").
        resyncFromService()

        updateSplitTunnelHint()
        updateBackgroundHealthHint()
    }

    /**
     * One-line "Background: protected / at risk" status under the Background
     * Health button. Re-evaluated on every resume so returning from a system
     * settings screen refreshes it immediately.
     */
    private fun updateBackgroundHealthHint() {
        val atRisk = BackgroundHealth.atRisk(this)
        binding.textBgHealthHint.text = getString(
            if (atRisk) R.string.bg_health_hint_risk else R.string.bg_health_hint_ok
        )
        binding.textBgHealthHint.setTextColor(
            getColor(if (atRisk) R.color.accent_lemon else R.color.text_secondary)
        )
    }

    override fun onPause() {
        super.onPause()
        // Always unregister callbacks when leaving the foreground. onResume()
        // re-registers them and resyncs from AivpnService.uiState (including the
        // dead-service case), so no updates are missed. Clearing unconditionally prevents a stale
        // lambda from holding a reference to a destroyed Activity (e.g. on rotation
        // where isFinishing == false), which would cause NPE when the service fires
        // a status/traffic callback between the old onDestroy and the new onResume.
        AivpnService.statusCallback = null
        AivpnService.trafficCallback = null
        AivpnService.recordingCallback = null
    }

    /** Delegates to the shared parser in ConnectionKeyParser. */
    private fun parseConnectionKey(key: String): ParsedConnectionKey? = ConnectionKeyParser.parse(key)

    private fun connect() {
        val connectionKey = binding.editConnectionKey.text.toString().trim()
        if (connectionKey.isEmpty()) {
            Toast.makeText(this, getString(R.string.error_fill_fields), Toast.LENGTH_SHORT).show()
            return
        }

        val parsed = parseConnectionKey(connectionKey)
        if (parsed == null) {
            Toast.makeText(this, getString(R.string.error_invalid_connection_key), Toast.LENGTH_SHORT).show()
            return
        }

        // Sync active profile with the entered key, or create a new profile if it's unknown
        val existing = profiles.find { it.key == connectionKey }
        if (existing != null) {
            if (activeProfileId != existing.id) {
                activeProfileId = existing.id
                SecureStorage.saveActiveProfileId(this, existing.id)
                renderProfiles()
            }
        } else {
            val profile = SecureStorage.ConnectionProfile(
                id = UUID.randomUUID().toString(),
                name = extractServerName(connectionKey),
                key = connectionKey
            )
            profiles.add(profile)
            activeProfileId = profile.id
            SecureStorage.saveProfiles(this, profiles)
            SecureStorage.saveActiveProfileId(this, profile.id)
            renderProfiles()
        }

        // Request VPN permission from the system
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun disconnect() {
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun startVpnService() {
        // Pass only the profile ID via Intent so that the server key and PSK are
        // read from EncryptedSharedPreferences inside AivpnService rather than
        // travelling through IPC as plaintext Intent extras.
        val profileId = activeProfileId ?: return
        // Mirror the active profile ID in device-protected SharedPreferences so
        // BootReceiver can read it during Direct Boot (CE storage is locked there —
        // plain CE prefs would throw IllegalStateException, not help).
        BootPrefs.prefs(this)
            .edit().putString(PrefsKeys.PREF_LAST_PROFILE_ID, profileId).apply()
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("profile_id", profileId)
        }
        startForegroundService(intent)
        // Show a "connecting" state (Disconnect button, grey dot, no timer) — NOT the
        // green connected state. The real connected UI arrives via statusCallback when
        // Rust fires onTunnelReady after the handshake, which is also the moment
        // connectionStartTime gets stamped.
        updateUI(false, getString(R.string.status_connecting), connecting = true)
    }

    private fun updateUI(connected: Boolean, statusText: String, connecting: Boolean = false) {
        isConnected = connected
        val serviceActive = connected || connecting || AivpnService.isServiceActive
        // When not connected, append the active profile name so the user can see
        // which profile will be used without having to look at the profile list.
        binding.btnConnect.text = if (serviceActive) {
            getString(R.string.btn_disconnect)
        } else {
            val activeName = profiles.find { it.id == activeProfileId }?.name
            if (activeName != null) "${getString(R.string.btn_connect)} · $activeName"
            else getString(R.string.btn_connect)
        }
        binding.btnConnect.setBackgroundColor(
            getColor(if (serviceActive) R.color.disconnect else R.color.accent)
        )
        binding.textStatus.text = statusText
        binding.statusDot.setBackgroundResource(
            if (connected) R.drawable.dot_green else R.drawable.dot_grey
        )

        // Show/hide stats and timer
        val statsVisibility = if (connected) View.VISIBLE else View.GONE
        binding.textTimer.visibility = statsVisibility
        binding.statsRow.visibility = statsVisibility

        // FEC badge: visible when connected with adaptive level >= 2
        binding.textFecBadge.visibility =
            if (connected && adaptiveLevel() >= 2) View.VISIBLE else View.GONE

        // Lock/unlock input fields while connected
        binding.editConnectionKey.isEnabled = !serviceActive
        binding.btnAddProfile.isEnabled = !serviceActive
        renderProfiles()

        // Timer management — the service's connectedAtMillis is the single source
        // of truth: stamped per session in onTunnelReady, it survives Activity
        // recreation (no more "timer restarts at app open" over a live tunnel)
        // and restamps on every silent reconnect (timer and the per-session
        // traffic counters now reset together instead of drifting apart).
        if (connected) {
            val serviceStart = AivpnService.connectedAtMillis
            val isFreshSession = serviceStart != connectionStartTime
            viewModel.setConnected(statusText, serviceStart)
            // L2: LiveData observers registered in onCreate only become ACTIVE at
            // onStart, so during onCreate's resyncFromService() the setConnected()
            // above is NOT delivered synchronously — connectionStartTime stayed 0,
            // the timerRunnable posted below bailed on its `> 0` guard, and the
            // timer/start-time fields stayed blank until onResume re-synced. Sync
            // directly; the observer still restores it on rotation.
            if (serviceStart > 0) {
                connectionStartTime = serviceStart
            }
            if (isFreshSession) {
                binding.textUpload.text = "0 B"
                binding.textDownload.text = "0 B"
            }
            // Stats-card third field: the wall-clock time the tunnel connected
            // (fixed), complementing the big elapsed counter above. connectionStartTime
            // is already synced from the ViewModel at this point.
            if (connectionStartTime > 0) {
                binding.textDuration.text = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
                    .format(java.util.Date(connectionStartTime))
            }
            timerHandler.removeCallbacks(timerRunnable)
            timerHandler.post(timerRunnable)
        } else {
            if (connecting) {
                viewModel.setConnecting(statusText)
            } else {
                viewModel.setDisconnected(statusText)  // resets connectionStartTime in ViewModel
            }
            timerHandler.removeCallbacks(timerRunnable)
            binding.textTimer.text = "00:00:00"
            binding.textDuration.text = "--:--"
            // RX/TX counters intentionally kept — show last known values during reconnect
        }
    }

    private fun toggleLanguage() {
        val currentLang = SecureStorage.loadLanguage(this)
        val newLang = if (currentLang == "en") "ru" else "en"

        SecureStorage.saveLanguage(this, newLang)

        val localeList = LocaleListCompat.forLanguageTags(newLang)
        AppCompatDelegate.setApplicationLocales(localeList)
        // Force immediate recreation on all API levels so descriptions update
        recreate()
    }

    private fun updateLanguageButton() {
        // Apply saved language on startup
        val savedLang = SecureStorage.loadLanguage(this)
        if (savedLang != null && savedLang != "en") {
            val localeList = LocaleListCompat.forLanguageTags(savedLang)
            AppCompatDelegate.setApplicationLocales(localeList)
        }

        val currentLang = (savedLang ?: "en").uppercase()
        binding.btnLanguage.text = if (currentLang == "EN") "EN → RU" else "RU → EN"
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            else -> String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    private fun showOptionsMenu(@Suppress("UNUSED_PARAMETER") anchor: View) {
        val currentLevel = adaptiveLevel()
        val levelNames = arrayOf(
            getString(R.string.adaptive_off),
            getString(R.string.adaptive_light),
            getString(R.string.adaptive_aggressive),
            getString(R.string.adaptive_satellite)
        )

        val autoConnect = BootPrefs.prefs(this)
            .getBoolean(PrefsKeys.PREF_AUTO_CONNECT, false)
        val autoConnectLabel = getString(R.string.auto_connect_on_startup) +
            ": " + if (autoConnect) getString(R.string.auto_connect_state_on)
                   else getString(R.string.auto_connect_state_off)

        // In-app admin entry: visible for Admin (full read/write) and Viewer
        // (read-only list inside AdminActivity), hidden entirely for role
        // User(0) or when the role can't be determined (e.g. .so not loaded).
        val mgmtRole = try {
            if (AivpnJni.isAvailable) AivpnJni.getRole() else -1
        } catch (_: Throwable) {
            -1
        }

        data class Item(val title: String, val desc: String, val id: Int)
        val items = mutableListOf(
            Item(getString(R.string.adaptive_mode) + ": " + levelNames[currentLevel],
                 getString(R.string.desc_adaptive_mode), MENU_ADAPTIVE),
            Item(autoConnectLabel,                   getString(R.string.desc_auto_connect),  MENU_AUTO_CONNECT),
            Item(getString(R.string.diagnostics),    getString(R.string.desc_diagnostics),   MENU_DIAGNOSTICS),
            Item(getString(R.string.recording),      getString(R.string.desc_recording),     MENU_RECORDING),
            Item(getString(R.string.export_logs),    getString(R.string.desc_export_logs),   MENU_EXPORT_LOGS),
            Item(getString(R.string.os_kill_switch), getString(R.string.desc_kill_switch),   MENU_OS_KILL_SWITCH),
            Item(getString(R.string.bootstrap_discovery), getString(R.string.desc_bootstrap_discovery), MENU_BOOTSTRAP_DISCOVERY),
            Item(getString(R.string.mask_privacy), getString(R.string.desc_mask_privacy), MENU_MASK_PRIVACY),
        )
        if (mgmtRole == 1 || mgmtRole == 2) {
            items.add(Item(getString(R.string.admin_menu_title), getString(R.string.desc_admin_menu), MENU_ADMIN))
        }

        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)
        val container = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }
        val scrollView = android.widget.ScrollView(dialogCtx).also { it.addView(container) }
        val dialog = AlertDialog.Builder(this).setView(scrollView).create()

        val primaryColor   = getColor(R.color.text_primary)
        val secondaryColor = getColor(R.color.text_secondary)
        val greyColor      = getColor(R.color.grey)

        items.forEachIndexed { index, item ->
            val row = LinearLayout(dialogCtx).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(24.dp, 14.dp, 24.dp, 14.dp)
                isClickable = true
                isFocusable = true
                val ta = dialogCtx.obtainStyledAttributes(intArrayOf(android.R.attr.selectableItemBackground))
                background = ta.getDrawable(0)
                ta.recycle()
            }
            row.addView(TextView(dialogCtx).apply {
                text = item.title
                textSize = 15f
                setTextColor(primaryColor)
                setTypeface(null, android.graphics.Typeface.BOLD)
            })
            row.addView(TextView(dialogCtx).apply {
                text = item.desc
                textSize = 12f
                setTextColor(secondaryColor)
                setPadding(0, 4.dp, 0, 0)
            })
            row.setOnClickListener { dialog.dismiss(); onOptionsMenuItemSelected(item.id) }
            container.addView(row)
            if (index < items.size - 1) {
                container.addView(View(dialogCtx).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, 1
                    ).apply { setMargins(24.dp, 0, 24.dp, 0) }
                    setBackgroundColor(greyColor)
                })
            }
        }
        dialog.show()
    }

    private fun onOptionsMenuItemSelected(itemId: Int) {
        when (itemId) {
            MENU_ADAPTIVE -> {
                val names = arrayOf(
                    getString(R.string.adaptive_off),
                    getString(R.string.adaptive_light),
                    getString(R.string.adaptive_aggressive),
                    getString(R.string.adaptive_satellite)
                )
                var selectedLevel = adaptiveLevel()
                AlertDialog.Builder(this)
                    .setTitle(getString(R.string.adaptive_mode))
                    .setSingleChoiceItems(names, selectedLevel) { _, which ->
                        selectedLevel = which
                    }
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
                            .edit().putInt(PrefsKeys.ADAPTIVE_LEVEL, selectedLevel).apply()
                    }
                    .setNegativeButton(getString(R.string.btn_cancel), null)
                    .show()
            }
            MENU_AUTO_CONNECT -> {
                // Device-protected storage: BootReceiver must be able to read this
                // during Direct Boot, where plain (CE) SharedPreferences throw.
                val prefs = BootPrefs.prefs(this)
                val current = prefs.getBoolean(PrefsKeys.PREF_AUTO_CONNECT, false)
                prefs.edit().putBoolean(PrefsKeys.PREF_AUTO_CONNECT, !current).apply()
                val msg = if (!current) getString(R.string.auto_connect_enabled)
                          else getString(R.string.auto_connect_disabled)
                android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_SHORT).show()
            }
            MENU_DIAGNOSTICS   -> showDiagnosticsDialog()
            MENU_RECORDING     -> showRecordingDialog()
            MENU_EXPORT_LOGS   -> exportLogs()
            MENU_OS_KILL_SWITCH -> startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
            MENU_BOOTSTRAP_DISCOVERY -> showBootstrapDiscoveryDialog()
            MENU_MASK_PRIVACY -> showMaskPrivacyDialog()
            MENU_ADMIN -> startActivity(Intent(this, AdminActivity::class.java))
        }
    }

    /**
     * §3 Polymorphic masks + §2 crowdsourced blocking feedback settings. Both are
     * opt-in and OFF by default, persisted in plain SharedPreferences (not tied to
     * any single connection profile), and forwarded to the Rust core via
     * [AivpnJni.runTunnel] on the next connect.
     */
    private fun showMaskPrivacyDialog() {
        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)
        val prefs = getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)

        val layout = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }

        val polymorphicCheck = android.widget.CheckBox(dialogCtx).apply {
            text = getString(R.string.mask_polymorphic)
            isChecked = prefs.getBoolean(PrefsKeys.PREF_POLYMORPHIC_ENABLED, false)
        }
        val polymorphicDesc = TextView(dialogCtx).apply {
            text = getString(R.string.desc_mask_polymorphic)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 0, 0, 8.dp)
        }

        val shareFeedbackCheck = android.widget.CheckBox(dialogCtx).apply {
            text = getString(R.string.mask_share_feedback)
            isChecked = prefs.getBoolean(PrefsKeys.PREF_SHARE_MASK_FEEDBACK, false)
        }
        val receiveHintsCheck = android.widget.CheckBox(dialogCtx).apply {
            text = getString(R.string.mask_receive_hints)
            isChecked = prefs.getBoolean(PrefsKeys.PREF_RECEIVE_MASK_HINTS, false)
        }

        val countryLabel = TextView(dialogCtx).apply {
            text = getString(R.string.mask_country_code_label)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }
        val countryInput = EditText(dialogCtx).apply {
            hint = getString(R.string.mask_country_code_hint)
            setText(prefs.getString(PrefsKeys.PREF_COUNTRY_CODE, "") ?: "")
            setSingleLine(true)
            filters = arrayOf(android.text.InputFilter.LengthFilter(2))
        }

        layout.addView(polymorphicCheck)
        layout.addView(polymorphicDesc)
        layout.addView(shareFeedbackCheck)
        layout.addView(receiveHintsCheck)
        layout.addView(countryLabel)
        layout.addView(countryInput)

        val dialog = AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(getString(R.string.mask_privacy))
            .setView(layout)
            // Set with a null listener here and override the button's onClickListener
            // AFTER show() below (standard Android pattern) so an invalid country code
            // can Toast and keep the dialog open — with the DialogInterface positive-
            // button listener, returning from the lambda without calling dismiss()
            // still lets AlertDialog auto-dismiss afterwards, silently discarding the
            // checkbox choices the user already made in this dialog.
            .setPositiveButton(getString(R.string.btn_save), null)
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val country = countryInput.text.toString().trim()
                val validCountry = country.length == 2 && country.all(Char::isLetter)
                if (country.isNotEmpty() && !validCountry) {
                    Toast.makeText(this, getString(R.string.mask_country_code_invalid), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                prefs.edit()
                    .putBoolean(PrefsKeys.PREF_POLYMORPHIC_ENABLED, polymorphicCheck.isChecked)
                    .putBoolean(PrefsKeys.PREF_SHARE_MASK_FEEDBACK, shareFeedbackCheck.isChecked)
                    .putBoolean(PrefsKeys.PREF_RECEIVE_MASK_HINTS, receiveHintsCheck.isChecked)
                    .putString(PrefsKeys.PREF_COUNTRY_CODE, if (validCountry) country.uppercase() else null)
                    .apply()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    // Clamped to the 4 defined levels: a server adaptive hint (or a corrupted pref)
    // outside 0..3 would otherwise crash levelNames[currentLevel] lookups.
    private fun adaptiveLevel(): Int =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getInt(PrefsKeys.ADAPTIVE_LEVEL, 0)
            .coerceIn(0, 3)

    private fun exportLogs() {
        val toast = Toast.makeText(this, getString(R.string.export_logs_collecting), Toast.LENGTH_SHORT)
        toast.show()
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val pid = android.os.Process.myPid().toString()
                val proc = Runtime.getRuntime().exec(
                    arrayOf("logcat", "-d", "-t", "1000", "-v", "time", "--pid=$pid")
                )
                val logs = proc.inputStream.bufferedReader().readText()
                proc.destroy()
                if (logs.isBlank()) {
                    withContext(Dispatchers.Main) {
                        toast.cancel()
                        Toast.makeText(this@MainActivity, getString(R.string.export_logs_empty), Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }
                val logFile = java.io.File(cacheDir, "aivpn-debug.txt")
                logFile.writeText(logs)
                withContext(Dispatchers.Main) {
                    toast.cancel()
                    val uri = androidx.core.content.FileProvider.getUriForFile(
                        this@MainActivity,
                        "${packageName}.provider",
                        logFile
                    )
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_SUBJECT, "AIVPN Debug Logs")
                        putExtra(Intent.EXTRA_STREAM, uri)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    startActivity(Intent.createChooser(intent, getString(R.string.export_logs)))
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    toast.cancel()
                    Toast.makeText(this@MainActivity, getString(R.string.export_logs_error), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Advanced/operator-only flow: lets the user paste a server address/public key
     * (handed to them out-of-band) plus one or more signed bootstrap descriptor
     * channels, then fetches and verifies fresh mask material for that server. This
     * does not "discover a server from nothing" — see BootstrapDiscovery.kt for why.
     */
    private fun showBootstrapDiscoveryDialog() {
        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)
        val container = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }

        fun labeledInput(hint: String): EditText {
            container.addView(TextView(dialogCtx).apply {
                text = hint
                textSize = 12f
                setPadding(0, 12.dp, 0, 4.dp)
            })
            val input = EditText(dialogCtx).apply {
                setSingleLine(true)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            container.addView(input)
            return input
        }

        container.addView(TextView(dialogCtx).apply {
            text = getString(R.string.bootstrap_discovery_hint)
            textSize = 12f
            setPadding(0, 0, 0, 4.dp)
        })

        val serverAddrInput = labeledInput(getString(R.string.bootstrap_server_address))
        val serverKeyInput = labeledInput(getString(R.string.bootstrap_server_pubkey))
        val pskInput = labeledInput(getString(R.string.bootstrap_server_psk))
        val signingKeyInput = labeledInput(getString(R.string.bootstrap_signing_key))
        val cdnInput = labeledInput(getString(R.string.bootstrap_cdn_url))
        val githubInput = labeledInput(getString(R.string.bootstrap_github_repo))
        val telegramBotInput = labeledInput(getString(R.string.bootstrap_telegram_bot))
        val telegramChatInput = labeledInput(getString(R.string.bootstrap_telegram_chat))

        val scrollView = android.widget.ScrollView(dialogCtx).also { it.addView(container) }

        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(getString(R.string.bootstrap_discovery))
            .setView(scrollView)
            .setPositiveButton(getString(R.string.bootstrap_discover_button)) { _, _ ->
                runBootstrapDiscovery(
                    serverAddr = serverAddrInput.text.toString().trim(),
                    serverKeyHex = serverKeyInput.text.toString().trim(),
                    pskHex = pskInput.text.toString().trim(),
                    signingKeyB64 = signingKeyInput.text.toString().trim(),
                    cdnUrl = cdnInput.text.toString().trim(),
                    githubRepo = githubInput.text.toString().trim(),
                    telegramBot = telegramBotInput.text.toString().trim(),
                    telegramChat = telegramChatInput.text.toString().trim(),
                )
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val clean = hex.trim()
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        return try {
            ByteArray(clean.length / 2) { i ->
                clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun runBootstrapDiscovery(
        serverAddr: String,
        serverKeyHex: String,
        pskHex: String,
        signingKeyB64: String,
        cdnUrl: String,
        githubRepo: String,
        telegramBot: String,
        telegramChat: String,
    ) {
        if (serverAddr.isEmpty()) {
            Toast.makeText(this, getString(R.string.bootstrap_missing_fields), Toast.LENGTH_SHORT).show()
            return
        }
        val serverKeyBytes = hexToBytes(serverKeyHex)
        if (serverKeyBytes == null || serverKeyBytes.size != 32) {
            Toast.makeText(this, getString(R.string.bootstrap_invalid_server_key), Toast.LENGTH_SHORT).show()
            return
        }
        val pskBytes = if (pskHex.isEmpty()) null else hexToBytes(pskHex)
        if (pskHex.isNotEmpty() && (pskBytes == null || pskBytes.size != 32)) {
            Toast.makeText(this, getString(R.string.bootstrap_invalid_server_key), Toast.LENGTH_SHORT).show()
            return
        }

        val toast = Toast.makeText(this, getString(R.string.bootstrap_discovering), Toast.LENGTH_SHORT)
        toast.show()
        lifecycleScope.launch(Dispatchers.IO) {
            val settings = BootstrapDiscovery.ChannelSettings(
                cdnUrl = cdnUrl,
                githubRepo = githubRepo,
                telegramBotToken = telegramBot,
                telegramChatId = telegramChat,
                signingPublicKeyBase64 = signingKeyB64,
            )
            val outcome = BootstrapDiscovery.discover(settings, System.currentTimeMillis() / 1000)

            withContext(Dispatchers.Main) {
                toast.cancel()
                if (outcome.validDescriptorJsons.isEmpty()) {
                    val errors = outcome.channelResults.joinToString("\n") { "${it.channel}: ${it.error ?: "no descriptors"}" }
                    Toast.makeText(
                        this@MainActivity,
                        getString(R.string.bootstrap_result_failure) + "\n" + errors,
                        Toast.LENGTH_LONG,
                    ).show()
                    return@withContext
                }

                val keyBase64 = android.util.Base64.encodeToString(serverKeyBytes, android.util.Base64.DEFAULT).trim()
                val pskBase64 = pskBytes?.let { android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT).trim() }
                val json = JSONObject().apply {
                    put("s", serverAddr)
                    put("k", keyBase64)
                    if (pskBase64 != null) put("p", pskBase64)
                    // Placeholder client VPN IP — required by ConnectionKeyParser, but the
                    // server overrides it via the ServerHello network config at connect time.
                    put("i", "10.0.0.2")
                }
                val encoded = android.util.Base64.encodeToString(
                    json.toString().toByteArray(Charsets.UTF_8),
                    android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
                )
                val connectionKey = "aivpn://$encoded"
                val name = getString(R.string.bootstrap_default_key_name) + " ($serverAddr)"
                // Add via the Activity's own `profiles` list — the single source of truth
                // used everywhere else in this Activity. viewModel.saveProfile must NOT be
                // used here: the ViewModel's LiveData list is never loaded in this Activity
                // (always empty), so SecureStorage.saveProfiles would overwrite ALL stored
                // profiles with just this one — losing every existing key.
                val profile = SecureStorage.ConnectionProfile(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    key = connectionKey,
                )
                profiles.add(profile)
                activeProfileId = profile.id
                SecureStorage.saveProfiles(this@MainActivity, profiles)
                SecureStorage.saveActiveProfileId(this@MainActivity, profile.id)
                // MEDIUM-3: persist the descriptors we just fetched + verified, keyed
                // PER SERVER (M1), so the VERY FIRST connect to this server is covert —
                // the one path that could shape a truly-first-ever handshake with a
                // signed rotated descriptor mask instead of a public preset. Format
                // matches accept_persisted_descriptors: a JSON array of descriptors.
                try {
                    val descArr = org.json.JSONArray()
                    for (d in outcome.validDescriptorJsons) {
                        descArr.put(org.json.JSONObject(d))
                    }
                    SecureStorage.saveBootstrapDescriptors(
                        this@MainActivity, descArr.toString(), keyBase64)
                } catch (e: Exception) {
                    android.util.Log.w("MainActivity", "Persisting discovered descriptors failed: ${e.message}")
                }
                binding.editConnectionKey.setText(connectionKey)
                renderProfiles()

                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.bootstrap_result_success)
                        .replace("{n}", outcome.validDescriptorJsons.size.toString())
                        .replace("{name}", name),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    private fun showDiagnosticsDialog() {
        if (!isConnected) {
            Toast.makeText(this, getString(R.string.status_disconnected), Toast.LENGTH_SHORT).show()
            return
        }
        val serverAddr = profiles.find { it.id == activeProfileId }
            ?.key?.let { parseConnectionKey(it)?.server } ?: ""
        // Read the LIVE score straight from the native core, not the cached
        // currentQualityScore — that cache is only refreshed by the traffic
        // callback, so it can be a stale 0 captured right after connect (before
        // the first KeepaliveAck updated the score) if no traffic has flowed
        // since. Fall back to the cache only if the live read has no data yet.
        val liveScore = AivpnJni.getQualityScore().takeIf { it > 0 } ?: currentQualityScore
        if (liveScore > 0) currentQualityScore = liveScore
        val qualityLine = if (liveScore > 0)
            getString(R.string.quality_score_live, liveScore)
        else
            getString(R.string.quality_score_no_data)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.diagnostics))
            .setMessage(qualityLine + "\n\n" + getString(R.string.run_benchmark))
            .setPositiveButton(getString(R.string.run_benchmark)) { _, _ ->
                val runningToast = Toast.makeText(this, getString(R.string.bench_running), Toast.LENGTH_LONG)
                runningToast.show()
                lifecycleScope.launch {
                    val stats = withContext(Dispatchers.IO) { runUDPBench(serverAddr) }
                    runningToast.cancel()
                    val msg = getString(R.string.bench_result, stats.p50, stats.p95, stats.lossPct.toFloat(), stats.quality)
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle(getString(R.string.diagnostics))
                        .setMessage(msg)
                        .setPositiveButton(getString(R.string.btn_cancel), null)
                        .show()
                }
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private data class BenchStats(val p50: Int, val p95: Int, val lossPct: Double, val quality: Int)

    /** Parse host:port or [IPv6]:port. Returns null on invalid input. */
    private fun parseHostPort(addr: String): Pair<String, Int>? {
        if (addr.startsWith("[")) {
            val bracket = addr.indexOf(']')
            if (bracket < 1) return null
            val host = addr.substring(1, bracket)
            val port = if (bracket + 1 < addr.length && addr[bracket + 1] == ':')
                addr.substring(bracket + 2).toIntOrNull()?.takeIf { it in 1..65535 }
            else null
            return Pair(host, port ?: 443)
        }
        val lastColon = addr.lastIndexOf(':')
        if (lastColon < 0) return null
        val port = addr.substring(lastColon + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        return Pair(addr.substring(0, lastColon), port)
    }

    private fun runUDPBench(serverAddr: String): BenchStats {
        if (serverAddr.isEmpty()) return BenchStats(0, 0, 100.0, 0)
        val (host, port) = parseHostPort(serverAddr) ?: return BenchStats(0, 0, 100.0, 0)

        return try {
            val socket = DatagramSocket()
            // Protect the socket so bench probes bypass the VPN tunnel and reach the
            // server directly. If protection FAILS (service gone, fd limit), abort:
            // an unprotected probe would loop through the tunnel (bogus RTTs) and,
            // worse, leak a direct-to-server datagram association outside the mask.
            val protectOk = AivpnService.instance?.protect(socket) == true
            if (!protectOk) {
                android.util.Log.w("MainActivity", "bench: socket not protected — aborting benchmark")
                socket.close()
                return BenchStats(0, 0, 100.0, 0)
            }
            socket.soTimeout = 500
            // Random payload, NOT a plaintext marker: a fixed "aivpn-bench-probe-v1"
            // string is a trivial DPI signature that links this client to the VPN
            // server address. Random bytes are indistinguishable from the encrypted/
            // masked traffic already flowing to the same endpoint. The server never
            // parses the probe anyway (RTT is estimated via the timeout fallback).
            val probe = ByteArray(20).also { java.security.SecureRandom().nextBytes(it) }
            val addr = InetAddress.getByName(host)
            val deadline = System.currentTimeMillis() + 5_000L
            val rtts = mutableListOf<Double>()
            var sent = 0
            try {
                while (System.currentTimeMillis() < deadline) {
                    val t0 = System.currentTimeMillis()
                    sent++
                    socket.send(DatagramPacket(probe, probe.size, addr, port))
                    try {
                        val buf = ByteArray(256)
                        socket.receive(DatagramPacket(buf, buf.size))
                        rtts.add((System.currentTimeMillis() - t0).toDouble())
                    } catch (_: SocketTimeoutException) {
                        val elapsed = (System.currentTimeMillis() - t0).toDouble()
                        if (elapsed < 490) rtts.add(elapsed * 2)
                    }
                    Thread.sleep(100)
                }
            } finally {
                socket.close()
            }
            computeBenchStats(rtts, sent)
        } catch (_: Exception) {
            BenchStats(0, 0, 100.0, 0)
        }
    }

    private fun computeBenchStats(rtts: List<Double>, sent: Int): BenchStats {
        if (rtts.isEmpty()) return BenchStats(0, 0, 100.0, 0)
        val sorted = rtts.sorted()
        val p50 = sorted[(sorted.size * 0.50).toInt().coerceAtMost(sorted.size - 1)].toInt()
        val p95 = sorted[(sorted.size * 0.95).toInt().coerceAtMost(sorted.size - 1)].toInt()
        val lossPct = (maxOf(0, sent - rtts.size).toDouble() / sent * 100).coerceIn(0.0, 100.0)
        val quality = when {
            p50 < 50 && lossPct < 1.0  -> 95
            p50 < 100 && lossPct < 3.0 -> 80
            p50 < 200 && lossPct < 10.0 -> 60
            else -> 30
        }
        return BenchStats(p50, p95, lossPct, quality)
    }

    override fun onDestroy() {
        timerHandler.removeCallbacks(timerRunnable)
        super.onDestroy()
    }

    /**
     * Parses a JSON feedback blob from [AivpnJni.getRecordingFeedback] (polled
     * once per second by [AivpnService] and forwarded via [AivpnService.recordingCallback])
     * and surfaces the server's recording ack/complete/failed outcome to the user.
     * Must be called on the main thread.
     */
    private fun handleRecordingFeedback(feedbackJson: String) {
        val json = try {
            JSONObject(feedbackJson)
        } catch (e: org.json.JSONException) {
            return
        }
        when (json.optString("type")) {
            "ack" -> {
                val message = if (json.optString("status") == "analyzing") {
                    getString(R.string.recording_analyzing)
                } else {
                    getString(R.string.recording_started)
                }
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
            "complete" -> {
                val maskId = json.optString("mask_id")
                val confidencePct = (json.optDouble("confidence", 0.0) * 100).toInt()
                Toast.makeText(
                    this,
                    getString(R.string.recording_complete, maskId, confidencePct),
                    Toast.LENGTH_LONG
                ).show()
            }
            "failed" -> {
                Toast.makeText(
                    this,
                    getString(R.string.recording_failed, json.optString("reason")),
                    Toast.LENGTH_LONG
                ).show()
            }
            else -> {
                // "status" (capability query response) — Android never sends
                // RecordingStatusRequest today, so nothing to update here yet.
            }
        }
    }

    private fun showRecordingDialog() {
        if (!isConnected) {
            Toast.makeText(this, getString(R.string.recording_no_session), Toast.LENGTH_SHORT).show()
            return
        }
        val input = android.widget.EditText(this).apply {
            hint = getString(R.string.recording_service_hint)
            setText(currentRecordingService)
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.recording))
            .setView(input)
            .setPositiveButton(getString(R.string.recording_start)) { _, _ ->
                val name = input.text.toString().trim().ifEmpty { "unknown" }
                currentRecordingService = name
                if (AivpnJni.startRecording(name) == 1) {
                    Toast.makeText(this, getString(R.string.recording_started), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, getString(R.string.recording_no_session), Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(getString(R.string.recording_stop)) { _, _ ->
                AivpnJni.stopRecording()
                Toast.makeText(this, getString(R.string.recording_stopped), Toast.LENGTH_SHORT).show()
            }
            .setNeutralButton(getString(R.string.btn_cancel), null)
            .show()
    }

    companion object {
        private const val MENU_ADAPTIVE = 1001
        private const val MENU_DIAGNOSTICS = 1002
        private const val MENU_EXPORT_LOGS = 1003
        private const val MENU_RECORDING = 1004
        private const val MENU_OS_KILL_SWITCH = 1005
        private const val MENU_AUTO_CONNECT = 1006
        private const val MENU_BOOTSTRAP_DISCOVERY = 1007
        private const val MENU_MASK_PRIVACY = 1008
        private const val MENU_ADMIN = 1009

        val MASK_OPTIONS = arrayOf(
            "auto",
            "webrtc_zoom_v3",
            "quic_https_v2",
            "webrtc_yandex_telemost_v1",
            "webrtc_vk_teams_v1",
            "webrtc_sberjazz_v1",
        )
    }
}
