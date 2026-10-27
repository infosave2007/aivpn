package com.aivpn.client

import android.app.Activity
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import android.content.Intent
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.FrameLayout
import androidx.activity.OnBackPressedCallback
import com.google.android.material.card.MaterialCardView
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import com.google.android.material.button.MaterialButton
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.UUID

/** Главные разделы клиента; состояние соединения принадлежит VPN-сервису. */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var profilesAdapter: ProfilesAdapter
    private lateinit var viewModel: MainViewModel
    private var isConnected = false
    private var isConnecting = false
    private var currentQualityScore: Int = 0
    private var currentRecordingService: String = ""

    private var profiles = mutableListOf<SecureStorage.ConnectionProfile>()
    private var activeProfileId: String? = null
    private var activeConnectionKey: String = ""
    private var selectedSection = R.id.nav_vpn
    private var lastUploadBytes: Long? = null
    private var lastDownloadBytes: Long? = null

    /**
     * False until onCreate's asynchronous SecureStorage load (A5) has populated
     * [profiles] / [activeProfileId]. Guards every path that PERSISTS the list:
     * saving the not-yet-loaded (empty) list would overwrite every stored profile.
     */
    private var profilesLoaded = false
    private var profileLoadJob: Job? = null
    private var pendingVpnProfileId: String? = null
    private var pendingVpnPermissionGranted = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            pendingVpnPermissionGranted = true
            resumePendingVpnStart()
        } else {
            pendingVpnProfileId = null
            pendingVpnPermissionGranted = false
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
                binding.sessionStats.setElapsed(elapsed)
                // textDuration shows the fixed session START time (see the connected
                // branch), NOT a second elapsed counter — so it no longer ticks here.
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingVpnProfileId = savedInstanceState?.getString("pending_vpn_profile")
        pendingVpnPermissionGranted = savedInstanceState?.getBoolean("pending_vpn_granted") ?: false
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        initializeNavigation(savedInstanceState)

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


        binding.versionFooter.text = "v${BuildConfig.VERSION_NAME} · ${getString(R.string.version_tagline)}"

        profilesAdapter = ProfilesAdapter(
            onProfileClick = { profile ->
                if (!isConnected && !isConnecting && !AivpnService.isServiceActive) {
                    activeProfileId = profile.id
                    SecureStorage.saveActiveProfileId(this, profile.id)
                    activeConnectionKey = profile.key
                    renderProfiles()
                    resyncFromService()
                }
            },
            onEditClick   = { showProfileDialog(it) },
            onDeleteClick = { confirmDeleteProfile(it) },
        )
        binding.profileList.layoutManager = LinearLayoutManager(this)
        binding.profileList.adapter = profilesAdapter


        binding.btnConnect.setOnClickListener {
            if (isConnecting || AivpnService.isServiceActive) disconnect() else connect()
        }

        binding.btnAddProfile.setOnClickListener { showProfileDialog(null) }
        binding.btnEmptyAdd.setOnClickListener { showProfileDialog(null) }
        val installServer = View.OnClickListener { startActivity(Intent(this, InstallServerActivity::class.java)) }
        binding.btnEmptyInstall.setOnClickListener(installServer)
        binding.btnInstallServer.setOnClickListener(installServer)
        binding.activeProfileCard.setOnClickListener { showProfilePicker() }
        binding.sessionStats.setOnClickListener { showDiagnosticsDialog() }

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



        updateSplitTunnelHint()

        // Restore connection state from the service's tri-state (single source of
        // truth). The terminal DISCONNECTED branch is essential: if the service died
        // while this Activity was not visible, the old two-branch isRunning/
        // isServiceActive check matched nothing and left the UI frozen at
        // "Connected" with a running timer and stale traffic counters.
        resyncFromService()
    }

    /** Перечитываем профили после возврата из мастера, не сохраняя старую копию. */
    private fun loadProfiles() {
        profileLoadJob?.cancel()
        profilesLoaded = false
        renderProfiles()
        profileLoadJob = lifecycleScope.launch {
            data class LoadResult(
                val profiles: MutableList<SecureStorage.ConnectionProfile>,
                val activeId: String?,
                val legacyKey: String,
                val language: String?,
            )

            val loaded = try {
                withContext(Dispatchers.IO) {
                    // Migrate legacy single connection key to profiles
                    migrateLegacyKey()
                    val list = SecureStorage.loadProfiles(this@MainActivity).toMutableList()
                    LoadResult(
                        profiles = list,
                        activeId = SecureStorage.loadActiveProfileId(this@MainActivity),
                        // Only read for the no-profiles fallback below.
                        legacyKey = if (list.isEmpty()) SecureStorage.loadConnectionKey(this@MainActivity) else "",
                        language = SecureStorage.loadLanguage(this@MainActivity),
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                android.util.Log.w("MainActivity", "Не удалось загрузить профили", error)
                Toast.makeText(this@MainActivity, R.string.status_storage_unavailable, Toast.LENGTH_LONG).show()
                return@launch
            }
            val runningProfile = activeProfileId.takeIf {
                AivpnService.isServiceActive && loaded.profiles.any { profile -> profile.id == it }
            }
            profiles = loaded.profiles
            activeProfileId = runningProfile ?: loaded.activeId
            profilesLoaded = true

            // If we have an active profile, load its key into the field
            val active = profiles.find { it.id == activeProfileId }
            if (active != null) {
                activeConnectionKey = active.key
            } else if (profiles.isNotEmpty()) {
                activeProfileId = profiles[0].id
                activeConnectionKey = profiles[0].key
                withContext(Dispatchers.IO) {
                    SecureStorage.saveActiveProfileId(this@MainActivity, profiles[0].id)
                }
            } else {
                // Fallback: try legacy key
                activeConnectionKey = loaded.legacyKey
            }

            renderProfiles()

            // Update language button label
            updateLanguageButton(loaded.language)

            // The Connect label carries the active profile name, which was still
            // unknown when the resync at the end of onCreate rendered the state.
            resyncFromService()
            resumePendingVpnStart()
        }
    }

    private fun resumePendingVpnStart() {
        if (!profilesLoaded || !pendingVpnPermissionGranted) return
        val requested = pendingVpnProfileId ?: return
        pendingVpnProfileId = null
        pendingVpnPermissionGranted = false
        val profile = profiles.find { it.id == requested } ?: return
        activeProfileId = profile.id
        activeConnectionKey = profile.key
        SecureStorage.saveActiveProfileId(this, profile.id)
        startVpnService(profile.id)
    }

    /** Renders the current AivpnService.uiState. Used by onCreate and onResume. */
    private fun resyncFromService() {
        val statusText = AivpnService.localizedStatus(this)
        when (AivpnService.uiState) {
            AivpnService.UiState.CONNECTED -> {
                isConnected = true
                updateUI(true, statusText)
            }
            AivpnService.UiState.CONNECTING -> {
                isConnected = false
                updateUI(false, statusText, connecting = true)
            }
            AivpnService.UiState.DISCONNECTED -> {
                isConnected = false
                updateUI(
                    false,
                    statusText.ifEmpty { getString(R.string.status_disconnected) }
                )
            }
        }
    }

    private var updatingNavigation = false

    private fun initializeNavigation(savedInstanceState: Bundle?) {
        val sections = setOf(R.id.nav_vpn, R.id.nav_profiles, R.id.nav_settings)
        selectedSection = savedInstanceState?.getInt("selected_section")?.takeIf(sections::contains) ?: R.id.nav_vpn
        binding.mainNavigation.setOnItemSelectedListener { item ->
            if (!updatingNavigation) selectSection(item.itemId)
            true
        }
        binding.mainRail.setOnItemSelectedListener { item ->
            if (!updatingNavigation) selectSection(item.itemId)
            true
        }
        selectSection(selectedSection)
        binding.root.post { configureNavigation() }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (selectedSection != R.id.nav_vpn) selectSection(R.id.nav_vpn) else finish()
            }
        })
    }

    private fun selectSection(section: Int) {
        selectedSection = section
        binding.vpnPage.visibility = if (section == R.id.nav_vpn) View.VISIBLE else View.GONE
        binding.profilesPage.visibility = if (section == R.id.nav_profiles) View.VISIBLE else View.GONE
        binding.settingsPage.visibility = if (section == R.id.nav_settings) View.VISIBLE else View.GONE
        binding.toolbar.setTitle(when (section) {
            R.id.nav_profiles -> R.string.nav_profiles
            R.id.nav_settings -> R.string.nav_settings
            else -> R.string.app_name
        })
        updatingNavigation = true
        binding.mainNavigation.selectedItemId = section
        binding.mainRail.selectedItemId = section
        updatingNavigation = false
        if (section == R.id.nav_settings) renderSettings()
    }

    private fun configureNavigation() {
        val wide = resources.configuration.screenWidthDp >= 600
        binding.mainRail.visibility = if (wide) View.VISIBLE else View.GONE
        binding.mainNavigation.visibility = if (wide) View.GONE else View.VISIBLE
        listOf(binding.vpnPage, binding.profilesPage, binding.settingsPage).forEach { page ->
            val child = page.getChildAt(0)
            child.layoutParams = (child.layoutParams as FrameLayout.LayoutParams).apply {
                width = if (wide) minOf(560, resources.configuration.screenWidthDp - 96).dp else ViewGroup.LayoutParams.MATCH_PARENT
                gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            }
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        configureNavigation()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt("selected_section", selectedSection)
        outState.putString("pending_vpn_profile", pendingVpnProfileId)
        outState.putBoolean("pending_vpn_granted", pendingVpnPermissionGranted)
        super.onSaveInstanceState(outState)
    }

    private fun showProfilePicker() {
        if (!profilesLoaded) return
        if (isConnected || isConnecting || AivpnService.isServiceActive) {
            MaterialAlertDialogBuilder(this).setMessage(R.string.ui_profile_locked)
                .setPositiveButton(android.R.string.ok, null).show()
            return
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.ui_choose_profile)
            .setSingleChoiceItems(profiles.map { it.name }.toTypedArray(), profiles.indexOfFirst { it.id == activeProfileId }) { dialog, which ->
                if (!isConnected && !isConnecting && !AivpnService.isServiceActive) {
                    val chosen = profiles.getOrNull(which) ?: return@setSingleChoiceItems
                    activeProfileId = chosen.id
                    activeConnectionKey = chosen.key
                    SecureStorage.saveActiveProfileId(this, chosen.id)
                    renderProfiles()
                    resyncFromService()
                }
                dialog.dismiss()
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }

    private fun renderSettings() {
        val container = binding.settingsContainer
        container.removeAllViews()
        fun group(title: Int, rows: LinearLayout.() -> Unit) {
            container.addView(TextView(this).apply {
                setText(title)
                textSize = 12f
                setTextColor(UiAppearance.color(this@MainActivity, com.google.android.material.R.attr.colorPrimary))
                setPadding(4.dp, 20.dp, 4.dp, 8.dp)
                androidx.core.view.ViewCompat.setAccessibilityHeading(this, true)
            })
            val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            val card = MaterialCardView(this).apply {
                layoutParams = LinearLayout.LayoutParams(-1, -2)
                addView(content)
            }
            content.rows()
            container.addView(card)
        }
        fun LinearLayout.row(icon: Int, title: Int, subtitle: String, checked: Boolean? = null, action: () -> Unit) {
            val row = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                minimumHeight = 76.dp
                setPadding(16.dp, 12.dp, 12.dp, 12.dp)
                val value = android.util.TypedValue()
                theme.resolveAttribute(android.R.attr.selectableItemBackground, value, true)
                setBackgroundResource(value.resourceId)
                isClickable = true
                isFocusable = true
                setOnClickListener { action() }
            }
            row.addView(androidx.appcompat.widget.AppCompatImageView(this@MainActivity).apply {
                setImageResource(icon)
                imageTintList = ColorStateList.valueOf(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurfaceVariant))
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }, LinearLayout.LayoutParams(24.dp, 24.dp))
            row.addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                addView(TextView(context).apply { setText(title); textSize = 16f; setTextColor(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurface)) })
                if (subtitle.isNotEmpty()) addView(TextView(context).apply {
                    text = subtitle
                    textSize = 12f
                    setTextColor(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurfaceVariant))
                    setPadding(0, 3.dp, 0, 0)
                })
            }, LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = 14.dp; marginEnd = 8.dp })
            if (checked != null) {
                row.addView(MaterialSwitch(this@MainActivity).apply {
                    isChecked = checked
                    minimumHeight = 48.dp
                    contentDescription = getString(title)
                    setOnCheckedChangeListener { _, _ -> action() }
                }, LinearLayout.LayoutParams(-2, 48.dp))
            } else {
                row.addView(androidx.appcompat.widget.AppCompatImageView(this@MainActivity).apply {
                    setImageResource(R.drawable.ic_vpn_chevron)
                    imageTintList = ColorStateList.valueOf(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurfaceVariant))
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                }, LinearLayout.LayoutParams(24.dp, 24.dp))
            }
            if (childCount > 0) addView(View(this@MainActivity).apply {
                setBackgroundColor(UiAppearance.color(context, com.google.android.material.R.attr.colorSurface))
            }, LinearLayout.LayoutParams(-1, 1.dp))
            addView(row)
        }
        group(R.string.ui_connection_group) {
            row(R.drawable.ic_vpn_power, R.string.ui_auto_connect, getString(R.string.ui_auto_connect_detail),
                BootPrefs.prefs(this@MainActivity).getBoolean(PrefsKeys.PREF_AUTO_CONNECT, false)) { onOptionsMenuItemSelected(MENU_AUTO_CONNECT) }
            row(R.drawable.ic_vpn_route, R.string.btn_split_tunnel, binding.textSplitTunnelHint.text.toString()) { startActivity(Intent(this@MainActivity, SplitTunnelActivity::class.java)) }
            row(R.drawable.ic_vpn_battery, R.string.ui_background, backgroundHealthMessage() ?: getString(R.string.ui_background_ok)) { startActivity(Intent(this@MainActivity, BackgroundHealthActivity::class.java)) }
            row(R.drawable.ic_vpn_shield, R.string.ui_block_without_vpn, getString(R.string.ui_android_vpn_settings)) { onOptionsMenuItemSelected(MENU_OS_KILL_SWITCH) }
        }
        group(R.string.ui_masks_group) {
            val mask = profiles.find { it.id == activeProfileId }?.maskProfile?.takeUnless { it == "auto" }
            row(R.drawable.ic_vpn_shield, R.string.mask_profile_label, mask ?: getString(R.string.ui_mask_default)) {
                val active = profiles.find { it.id == activeProfileId }
                if (active != null) showProfileDialog(active) else selectSection(R.id.nav_profiles)
            }
            val levels = intArrayOf(R.string.adaptive_off, R.string.adaptive_light, R.string.adaptive_aggressive, R.string.adaptive_satellite)
            row(R.drawable.ic_vpn_settings, R.string.adaptive_mode, getString(levels[adaptiveLevel()])) { onOptionsMenuItemSelected(MENU_ADAPTIVE) }
            val privacy = getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            val privacyEnabled = listOf(PrefsKeys.PREF_POLYMORPHIC_ENABLED, PrefsKeys.PREF_SHARE_MASK_FEEDBACK, PrefsKeys.PREF_RECEIVE_MASK_HINTS).any { privacy.getBoolean(it, false) }
            row(R.drawable.ic_vpn_shield_check, R.string.mask_privacy, getString(if (privacyEnabled) R.string.auto_connect_state_on else R.string.auto_connect_state_off)) { onOptionsMenuItemSelected(MENU_MASK_PRIVACY) }
            if (loadTransportDescriptor(this@MainActivity) != null) row(R.drawable.ic_vpn_route, R.string.transport_settings_title, "") { onOptionsMenuItemSelected(MENU_TRANSPORT_SETTINGS) }
        }
        group(R.string.ui_application_group) {
            row(R.drawable.ic_vpn_settings, R.string.ui_appearance, UiAppearance.themeSummary(this@MainActivity)) { UiAppearance.showThemeDialog(this@MainActivity) }
            val language = AppCompatDelegate.getApplicationLocales().toLanguageTags()
            row(R.drawable.ic_vpn_info, R.string.label_language, when (language) { "ru" -> "Русский"; "en" -> "English"; else -> getString(R.string.ui_language_system) }) { showLanguageDialog() }
            row(R.drawable.ic_vpn_info, R.string.diagnostics, getString(R.string.ui_diagnostics_detail)) { showDiagnosticsDialog() }
            row(R.drawable.ic_vpn_settings, R.string.ui_tools, getString(R.string.ui_tools_group)) { showToolsDialog() }
        }
        val role = runCatching { if (AivpnJni.isAvailable) AivpnJni.getRole() else -1 }.getOrDefault(-1)
        if (role == 1 || role == 2) group(R.string.ui_management_group) {
            row(R.drawable.ic_vpn_server, R.string.admin_menu_title, getString(R.string.desc_admin_menu)) { onOptionsMenuItemSelected(MENU_ADMIN) }
        }
    }

    private fun showToolsDialog() {
        val labels = intArrayOf(R.string.recording, R.string.ui_bootstrap, R.string.export_logs, R.string.install_menu_title)
        val actions = intArrayOf(MENU_RECORDING, MENU_BOOTSTRAP_DISCOVERY, MENU_EXPORT_LOGS, MENU_INSTALL_SERVER)
        MaterialAlertDialogBuilder(this).setTitle(R.string.ui_tools)
            .setItems(labels.map { getString(it) }.toTypedArray()) { _, which -> onOptionsMenuItemSelected(actions[which]) }
            .setNegativeButton(R.string.btn_cancel, null).show()
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
        val active = profiles.find { it.id == activeProfileId }
        val busy = isConnected || isConnecting || AivpnService.isServiceActive
        profilesAdapter.editingEnabled = profilesLoaded && !busy
        profilesAdapter.activeProfileId = activeProfileId
        profilesAdapter.submitList(profiles.toList())
        binding.textProfilesEmpty.visibility = if (profilesLoaded && profiles.isEmpty()) View.VISIBLE else View.GONE
        binding.profilesLockedHint.visibility = if (busy) View.VISIBLE else View.GONE
        binding.profilesLoading.visibility = if (profilesLoaded) View.GONE else View.VISIBLE
        binding.emptyGroup.visibility = if (profilesLoaded && profiles.isEmpty() && !busy) View.VISIBLE else View.GONE
        binding.vpnHero.visibility = if (busy || (profilesLoaded && profiles.isNotEmpty())) View.VISIBLE else View.GONE
        binding.activeProfileCard.visibility = if (active != null) View.VISIBLE else View.GONE
        binding.profileHeading.visibility = binding.activeProfileCard.visibility
        binding.activeProfileName.text = active?.name ?: getString(R.string.ui_no_profile)
        binding.activeProfileServer.text = active?.let { ConnectionKeyParser.parse(it.key)?.server }.orEmpty()
        binding.btnAddProfile.isEnabled = profilesLoaded && !busy
        binding.btnEmptyAdd.isEnabled = profilesLoaded && !busy
        binding.btnConnect.isEnabled = busy || (profilesLoaded && active != null)
    }

    private fun showProfileDialog(existing: SecureStorage.ConnectionProfile?) {
        if (!profilesLoaded || isConnected || isConnecting || AivpnService.isServiceActive) return
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 8.dp, 24.dp, 8.dp)
        }
        fun field(parent: LinearLayout, hintId: Int, value: String, secret: Boolean = false, inputId: Int = View.NO_ID): Pair<TextInputLayout, TextInputEditText> {
            val box = TextInputLayout(this).apply {
                hint = getString(hintId)
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = 12.dp }
                if (secret) endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
            }
            val input = TextInputEditText(box.context).apply {
                id = inputId
                inputType = InputType.TYPE_CLASS_TEXT or if (secret) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_NORMAL
                setSingleLine(true)
                textSize = 16f
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                setText(value)
            }
            box.addView(input, LinearLayout.LayoutParams(-1, -2))
            parent.addView(box)
            return box to input
        }
        val (nameBox, nameInput) = field(layout, R.string.ui_profile_name, existing?.name.orEmpty(), inputId = R.id.profileNameInput)
        val (keyBox, keyInput) = field(layout, R.string.ui_profile_key, existing?.key.orEmpty(), secret = true, inputId = R.id.profileKeyInput)
        layout.addView(MaterialButton(this, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
            setText(R.string.ui_paste_key)
            minimumHeight = 48.dp
            setOnClickListener {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val value = clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this@MainActivity)
                if (value.isNullOrBlank()) Toast.makeText(this@MainActivity, R.string.ui_clipboard_empty, Toast.LENGTH_SHORT).show()
                else keyInput.setText(value)
            }
        })
        layout.addView(TextView(this).apply {
            setText(R.string.ui_key_privacy)
            textSize = 12f
            setTextColor(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurfaceVariant))
        })
        val advanced = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
        layout.addView(MaterialButton(this, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
            setText(R.string.ui_advanced)
            minimumHeight = 48.dp
            setOnClickListener { advanced.visibility = if (advanced.visibility == View.VISIBLE) View.GONE else View.VISIBLE }
        })
        layout.addView(advanced)
        val (certBox, certInput) = field(advanced, R.string.ui_certificate_optional, existing?.mtlsCertBase64.orEmpty(), secret = true)
        val (_, dnsInput) = field(advanced, R.string.label_dns_servers, existing?.dnsServers?.joinToString(", ").orEmpty())
        val maskIds = mutableListOf("auto")
        val maskLabels = mutableListOf(getString(R.string.mask_auto))
        val catalogJson = runCatching { if (AivpnJni.isAvailable) AivpnJni.getMaskCatalogJson() else "" }.getOrDefault("")
        if (catalogJson.isNotEmpty()) runCatching {
            val catalog = org.json.JSONArray(catalogJson)
            for (index in 0 until catalog.length()) {
                val item = catalog.getJSONObject(index)
                val id = item.optString("mask_id")
                if (id.isNotBlank() && id !in maskIds) {
                    maskIds.add(id)
                    maskLabels.add(item.optString("label", id) + if (item.optBoolean("generated")) getString(R.string.mask_auto_marker) else "")
                }
            }
        }
        if (maskIds.size == 1) MASK_OPTIONS.drop(1).forEach { maskIds.add(it); maskLabels.add(it) }
        existing?.maskProfile?.takeIf { it.isNotBlank() && it !in maskIds }?.let { maskIds.add(it); maskLabels.add(it) }
        var selectedMask = maskIds.indexOf(existing?.maskProfile ?: "auto").coerceAtLeast(0)
        val maskBox = TextInputLayout(this).apply {
            hint = getString(R.string.mask_profile_label)
            endIconMode = TextInputLayout.END_ICON_DROPDOWN_MENU
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = 12.dp }
        }
        val maskInput = MaterialAutoCompleteTextView(maskBox.context).apply {
            inputType = InputType.TYPE_NULL
            setSimpleItems(maskLabels.toTypedArray())
            setText(maskLabels[selectedMask], false)
            setOnItemClickListener { _, _, position, _ -> selectedMask = position }
        }
        maskBox.addView(maskInput, LinearLayout.LayoutParams(-1, -2))
        advanced.addView(maskBox)
        val scroll = androidx.core.widget.NestedScrollView(this).apply { addView(layout); isFillViewport = false }
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(if (existing == null) R.string.dialog_add_profile else R.string.dialog_edit_profile)
            .setView(scroll)
            .setPositiveButton(R.string.btn_save, null)
            .setNegativeButton(R.string.btn_cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.window?.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
            val config = resources.configuration
            if (config.screenWidthDp <= 360 || config.screenHeightDp <= 600 || config.fontScale > 1.2f) {
                dialog.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener save@{
                if (!profilesLoaded || isConnected || isConnecting || AivpnService.isServiceActive) {
                    Toast.makeText(this, R.string.ui_profile_locked, Toast.LENGTH_SHORT).show()
                    return@save
                }
                nameBox.error = null
                keyBox.error = null
                certBox.error = null
                val name = nameInput.text.toString().trim()
                val key = keyInput.text.toString().trim()
                if (name.isEmpty()) { nameBox.error = getString(R.string.error_profile_name_empty); nameInput.requestFocus(); return@save }
                if (parseConnectionKey(key) == null) { keyBox.error = getString(R.string.error_profile_key_invalid); keyInput.requestFocus(); return@save }
                val certRaw = certInput.text.toString().trim()
                val mtlsCert = certRaw.takeIf { it.isNotEmpty() }
                if (mtlsCert != null && runCatching { android.util.Base64.decode(mtlsCert, android.util.Base64.DEFAULT).size }.getOrNull() != 104) {
                    advanced.visibility = View.VISIBLE
                    certBox.error = getString(R.string.mtls_cert_invalid)
                    certInput.requestFocus()
                    return@save
                }
                val dnsServers = dnsInput.text.toString().split(',').map(String::trim).filter(String::isNotEmpty).takeIf { it.isNotEmpty() }
                val mask = maskIds.getOrNull(selectedMask)?.takeUnless { it == "auto" }
                if (existing != null) {
                    val index = profiles.indexOfFirst { it.id == existing.id }
                    if (index < 0) return@save
                    profiles[index] = existing.copy(name = name, key = key, mtlsCertBase64 = mtlsCert, dnsServers = dnsServers, maskProfile = mask)
                    if (activeProfileId == existing.id) activeConnectionKey = key
                } else {
                    val profile = SecureStorage.ConnectionProfile(id = UUID.randomUUID().toString(), name = name, key = key,
                        mtlsCertBase64 = mtlsCert, dnsServers = dnsServers, maskProfile = mask)
                    profiles.add(profile)
                    activeProfileId = profile.id
                    activeConnectionKey = key
                    SecureStorage.saveActiveProfileId(this, profile.id)
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
                resyncFromService()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun confirmDeleteProfile(profile: SecureStorage.ConnectionProfile) {
        if (isConnected || isConnecting || AivpnService.isServiceActive) return
        MaterialAlertDialogBuilder(this, R.style.Theme_AIVPN_Dialog)
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
                    activeConnectionKey = profiles.firstOrNull()?.key ?: ""
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    private fun updateSplitTunnelHint() {
        // A5: same Keystore-backed store as the onCreate load — and this one runs
        // again on EVERY onResume, so it must not block the main thread either.
        // Purely a label, so applying it a frame late is invisible.
        lifecycleScope.launch {
            val counts = withContext(Dispatchers.IO) {
                SecureStorage.loadAllowedApps(this@MainActivity).size to
                    SecureStorage.loadExcludedDomains(this@MainActivity).size
            }
            val (appCount, siteCount) = counts
            binding.textSplitTunnelHint.text = when {
                appCount > 0 && siteCount > 0 -> getString(R.string.split_tunnel_hint_combined,
                    getString(R.string.split_tunnel_hint_apps, appCount),
                    getString(R.string.split_tunnel_hint_sites, siteCount))
                appCount > 0 -> getString(R.string.split_tunnel_vpn_count, appCount)
                siteCount > 0 -> getString(R.string.split_tunnel_bypass_count, siteCount)
                else -> getString(R.string.split_tunnel_none)
            }
            if (selectedSection == R.id.nav_settings) renderSettings()
        }
    }

    override fun onResume() {
        super.onResume()
        // Register callbacks when activity becomes visible.
        // Using onResume/onPause instead of onCreate/onDestroy prevents the race condition
        // where a destroyed (rotated) Activity nullifies callbacks registered by the new one.
        AivpnService.statusCallback = { _, _ ->
            runOnUiThread { resyncFromService() }
        }

        AivpnService.trafficCallback = { uploadBytes, downloadBytes ->
            val quality = if (AivpnJni.isAvailable) AivpnJni.getQualityScore() else 0
            runOnUiThread {
                lastUploadBytes = uploadBytes
                lastDownloadBytes = downloadBytes
                binding.sessionStats.setTraffic(uploadBytes, downloadBytes)
                viewModel.updateTraffic(uploadBytes, downloadBytes, quality)
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

        loadProfiles()
        updateSplitTunnelHint()
        updateBackgroundHealthHint()
    }

    /**
     * One-line "Background: protected / at risk" status under the Background
     * Health button. Re-evaluated on every resume so returning from a system
     * settings screen refreshes it immediately.
     */
    private fun updateBackgroundHealthHint() {
        val message = backgroundHealthMessage()
        binding.btnBgHealth.visibility = if (message != null) View.VISIBLE else View.GONE
        binding.textBgHealthHint.text = message.orEmpty()
        if (selectedSection == R.id.nav_settings) renderSettings()
    }

    private fun backgroundHealthMessage(): String? = when {
        !BackgroundHealth.batteryExempt(this) -> getString(R.string.ui_battery_notice)
        BackgroundHealth.backgroundRestricted(this) -> getString(R.string.ui_background_notice)
        !BackgroundHealth.notificationsEnabled(this) -> getString(R.string.ui_notification_notice)
        else -> null
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
        // The profile list is still loading (onCreate, off the main thread): the
        // in-memory list is empty, so the saveProfiles() below would wipe every
        // stored profile. A no-op is safe — the window is a few milliseconds and
        // the next tap goes through.
        if (!profilesLoaded) return

        val connectionKey = activeConnectionKey.trim()
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
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.ui_vpn_permission)
                .setMessage(R.string.ui_vpn_permission_body)
                .setPositiveButton(R.string.ui_continue) { _, _ ->
                    pendingVpnProfileId = activeProfileId
                    pendingVpnPermissionGranted = false
                    vpnPermissionLauncher.launch(intent)
                }
                .setNegativeButton(R.string.btn_cancel, null)
                .show()
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

    private fun startVpnService(requestedProfileId: String? = activeProfileId) {
        // Pass only the profile ID via Intent so that the server key and PSK are
        // read from EncryptedSharedPreferences inside AivpnService rather than
        // travelling through IPC as plaintext Intent extras.
        val profileId = requestedProfileId ?: return
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
        requestNotificationPermissionIfNeeded()
    }

    private fun updateUI(connected: Boolean, statusText: String, connecting: Boolean = false) {
        isConnected = connected
        isConnecting = connecting
        val serviceActive = connected || connecting || AivpnService.isServiceActive
        val error = !serviceActive && statusText.isNotBlank() && statusText != getString(R.string.status_disconnected)
        binding.btnConnect.text = getString(when {
            connecting -> R.string.ui_cancel_connect
            serviceActive -> R.string.btn_disconnect
            error -> R.string.ui_retry
            else -> R.string.btn_connect
        })
        binding.btnConnect.backgroundTintList = ColorStateList.valueOf(UiAppearance.color(this,
            if (serviceActive) com.google.android.material.R.attr.colorPrimaryContainer
            else com.google.android.material.R.attr.colorPrimary))
        val onButton = UiAppearance.color(this, if (serviceActive)
            com.google.android.material.R.attr.colorOnPrimaryContainer else com.google.android.material.R.attr.colorOnPrimary)
        binding.btnConnect.setTextColor(onButton)
        binding.btnConnect.iconTint = ColorStateList.valueOf(onButton)
        binding.btnConnect.setIconResource(if (connecting) R.drawable.ic_vpn_close else R.drawable.ic_vpn_power)
        binding.connectionTitle.setText(when {
            connected -> R.string.ui_vpn_connected
            connecting -> R.string.status_connecting
            error -> R.string.ui_vpn_failed
            else -> R.string.ui_vpn_disconnected
        })
        binding.textStatus.text = statusText
        binding.connectProgress.visibility = if (connecting) View.VISIBLE else View.GONE
        binding.statusIcon.visibility = if (connecting) View.INVISIBLE else View.VISIBLE
        binding.statusIcon.setImageResource(if (connected) R.drawable.ic_vpn_shield_check else if (error) R.drawable.ic_vpn_info else R.drawable.ic_vpn_shield)
        binding.statusIcon.imageTintList = ColorStateList.valueOf(if (connected) getColor(R.color.green)
            else if (error) UiAppearance.color(this, com.google.android.material.R.attr.colorError)
            else UiAppearance.color(this, com.google.android.material.R.attr.colorPrimary))
        binding.sessionStats.visibility = if (connected) View.VISIBLE else View.GONE
        renderProfiles()
        if (selectedSection == R.id.nav_settings) renderSettings()

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
                lastUploadBytes = null
                lastDownloadBytes = null
            }
            if (AivpnJni.isAvailable) {
                lastUploadBytes = AivpnJni.getUploadBytes()
                lastDownloadBytes = AivpnJni.getDownloadBytes()
            }
            binding.sessionStats.setTraffic(lastUploadBytes, lastDownloadBytes)
            timerHandler.removeCallbacks(timerRunnable)
            timerHandler.post(timerRunnable)
        } else {
            if (connecting) {
                viewModel.setConnecting(statusText)
            } else {
                viewModel.setDisconnected(statusText)  // resets connectionStartTime in ViewModel
            }
            timerHandler.removeCallbacks(timerRunnable)
            binding.sessionStats.setElapsed(0)
            // RX/TX counters intentionally kept — show last known values during reconnect
        }
    }

    private fun showLanguageDialog() {
        val labels = arrayOf(getString(R.string.ui_language_system), "Русский", "English")
        val tags = arrayOf("", "ru", "en")
        val current = AppCompatDelegate.getApplicationLocales().toLanguageTags()
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.label_language)
            .setSingleChoiceItems(labels, tags.indexOf(current).coerceAtLeast(0)) { dialog, which ->
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) { SecureStorage.saveLanguage(this@MainActivity, tags[which]) }
                    dialog.dismiss()
                    AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tags[which]))
                    recreate()
                }
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }

    private fun updateLanguageButton(savedLang: String?) {
        val language = savedLang.orEmpty()
        if (language != AppCompatDelegate.getApplicationLocales().toLanguageTags()) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(language))
        }
        if (selectedSection == R.id.nav_settings) renderSettings()
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
                MaterialAlertDialogBuilder(this)
                    .setTitle(getString(R.string.adaptive_mode))
                    .setSingleChoiceItems(names, selectedLevel) { _, which ->
                        selectedLevel = which
                    }
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
                            .edit().putInt(PrefsKeys.ADAPTIVE_LEVEL, selectedLevel).apply()
                        renderSettings()
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
                renderSettings()
            }
            MENU_DIAGNOSTICS   -> showDiagnosticsDialog()
            MENU_RECORDING     -> showRecordingDialog()
            MENU_EXPORT_LOGS   -> exportLogs()
            MENU_OS_KILL_SWITCH -> startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
            MENU_BOOTSTRAP_DISCOVERY -> showBootstrapDiscoveryDialog()
            MENU_MASK_PRIVACY -> showMaskPrivacyDialog()
            MENU_ADMIN -> startActivity(Intent(this, AdminActivity::class.java))
            MENU_INSTALL_SERVER -> startActivity(Intent(this, InstallServerActivity::class.java))
            MENU_TRANSPORT_SETTINGS -> startActivity(Intent(this, TransportSettingsActivity::class.java))
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

        val dialog = MaterialAlertDialogBuilder(this, R.style.Theme_AIVPN_Dialog)
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
                renderSettings()
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

        MaterialAlertDialogBuilder(this, R.style.Theme_AIVPN_Dialog)
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
                activeConnectionKey = connectionKey
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
        val liveScore = if (isConnected && AivpnJni.isAvailable) runCatching { AivpnJni.getQualityScore() }.getOrDefault(0) else 0
        if (liveScore > 0) currentQualityScore = liveScore
        val quality = if (isConnected && currentQualityScore > 0) getString(R.string.quality_score_live, currentQualityScore)
            else getString(R.string.quality_score_no_data)
        val details = buildList {
            add(AivpnService.localizedStatus(this@MainActivity).ifEmpty { getString(R.string.status_disconnected) })
            profiles.find { it.id == activeProfileId }?.let { add(it.name); add(ConnectionKeyParser.parse(it.key)?.server.orEmpty()) }
            if (isConnected) {
                add(getString(R.string.ui_session_elapsed, binding.sessionStats.elapsedText()))
                add(getString(R.string.ui_session_received, binding.sessionStats.receivedText()))
                add(getString(R.string.ui_session_sent, binding.sessionStats.sentText()))
                add(quality)
                if (adaptiveLevel() >= 2) add(getString(R.string.fec_badge))
            }
        }.joinToString("\n")
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.ui_session_details)
            .setMessage(details)
            .setNeutralButton(R.string.export_logs) { _, _ -> exportLogs() }
            .setNegativeButton(R.string.btn_cancel, null)
        if (isConnected && AivpnJni.isAvailable) dialog.setPositiveButton(R.string.run_benchmark) { _, _ -> runConnectionBenchmark() }
        dialog.show()
    }

    private fun runConnectionBenchmark() {
        if (!isConnected || !AivpnJni.isAvailable) return
        val toast = Toast.makeText(this, getString(R.string.bench_running), Toast.LENGTH_LONG)
        toast.show()
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { AivpnJni.runBenchmark()?.let { JSONObject(String(it, Charsets.UTF_8)) } }.getOrNull()
            }
            toast.cancel()
            val message = if (result == null || result.has("error")) {
                result?.optString("error") ?: getString(R.string.bench_failed)
            } else {
                getString(R.string.bench_result, result.optDouble("latency_p50_ms").toInt(),
                    result.optDouble("latency_p95_ms").toInt(), result.optDouble("packet_loss_pct"), result.optInt("quality_score")) +
                    "\n" + getString(R.string.bench_speed, result.optDouble("throughput_up_kbps"), result.optDouble("throughput_down_kbps"))
            }
            MaterialAlertDialogBuilder(this@MainActivity).setTitle(R.string.diagnostics)
                .setMessage(message).setPositiveButton(android.R.string.ok, null).show()
        }
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
        MaterialAlertDialogBuilder(this)
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
        private const val MENU_INSTALL_SERVER = 1010
        private const val MENU_TRANSPORT_SETTINGS = 1011

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
