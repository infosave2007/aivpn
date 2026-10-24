package com.aivpn.client

import android.app.ActivityManager
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat
import com.aivpn.client.databinding.ActivityBackgroundHealthBinding
import com.google.android.material.button.MaterialButton

/**
 * Проверки, останется ли VPN работать, когда приложение свернуто.
 * Ими пользуются [BackgroundHealthActivity] и короткая подсказка на главном экране.
 */
object BackgroundHealth {

    /** Видит ли пользователь оповещение «VPN остановлен».
     *  Учитывает POST_NOTIFICATIONS на Android 13+ и общий переключатель уведомлений. */
    fun notificationsEnabled(context: Context): Boolean =
        NotificationManagerCompat.from(context).areNotificationsEnabled()

    /** Исключение из оптимизации батареи: режим сна не останавливает службу. */
    fun batteryExempt(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /** Состояние «Ограничено» с API 28. Ниже этого API такого состояния нет. */
    fun backgroundRestricted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return try { am.isBackgroundRestricted } catch (e: Exception) { false }
    }

    /** Always-on VPN state for this app. Only queryable from the live VpnService
     *  instance on API 29+; null = cannot verify right now (service not running). */
    fun alwaysOnEnabled(): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val svc = AivpnService.instance ?: return null
        return try { svc.isAlwaysOn } catch (e: Exception) { null }
    }

    /** Системный переключатель «Блокировать соединения без VPN».
     *  null значит, что сейчас это нельзя проверить. */
    fun lockdownEnabled(): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val svc = AivpnService.instance ?: return null
        return try { svc.isLockdownEnabled } catch (e: Exception) { null }
    }

    /** Quick "is the field bug possible?" verdict for the main-screen hint:
     *  true when any locally-verifiable must-have setting is wrong. */
    fun atRisk(context: Context): Boolean =
        !notificationsEnabled(context) ||
            !batteryExempt(context) ||
            backgroundRestricted(context)
}

/**
 * Список системных разрешений, от которых зависит работа VPN в фоне.
 * У каждого пункта свой переход в нужный системный экран.
 * Состояние читается заново в [onResume], сразу после возврата из настроек.
 */
class BackgroundHealthActivity : AppCompatActivity() {

    private lateinit var binding: ActivityBackgroundHealthBinding

    private enum class Status { OK, WARN, UNKNOWN }

    /** Result callback re-renders; if the runtime request was refused (or was
     *  permanently denied so no dialog appeared), fall through to app
     *  notification settings where the user can flip the toggle manually. */
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        render()
        if (!granted) openAppNotificationSettings()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityBackgroundHealthBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.btnBack.setOnClickListener { finish() }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    // ──────────── Checklist rendering ────────────

    private fun render() {
        val notifications = BackgroundHealth.notificationsEnabled(this)
        val battery = BackgroundHealth.batteryExempt(this)
        val bgRestricted = BackgroundHealth.backgroundRestricted(this)
        val alwaysOn = BackgroundHealth.alwaysOnEnabled()
        val lockdown = BackgroundHealth.lockdownEnabled()

        // Overall verdict: any failed must-have -> at risk; all good but no
        // lockdown confirmation -> almost protected; everything green -> protected.
        val mustHaveOk = notifications && battery && !bgRestricted
        when {
            !mustHaveOk -> {
                binding.textSummary.text = getString(R.string.secondary_bg_summary_at_risk)
                binding.textSummary.setTextColor(colorAttr(com.google.android.material.R.attr.colorError, R.color.disconnect))
                binding.summaryDot.setBackgroundResource(R.drawable.dot_yellow)
            }
            lockdown != true -> {
                binding.textSummary.text = getString(R.string.secondary_bg_summary_mostly)
                binding.textSummary.setTextColor(getColor(R.color.accent_lemon))
                binding.summaryDot.setBackgroundResource(R.drawable.dot_yellow)
            }
            else -> {
                binding.textSummary.text = getString(R.string.secondary_bg_summary_protected)
                binding.textSummary.setTextColor(getColor(R.color.green))
                binding.summaryDot.setBackgroundResource(R.drawable.dot_green)
            }
        }

        val c = binding.checklistContainer
        c.removeAllViews()

        // 1. Notifications (POST_NOTIFICATIONS on 13+, app toggle everywhere)
        addRow(
            title = getString(R.string.bg_health_check_notifications),
            desc = if (notifications) getString(R.string.secondary_bg_notifications_ok)
                   else getString(R.string.secondary_bg_notifications_bad),
            status = if (notifications) Status.OK else Status.WARN,
            actionLabel = if (notifications) null else getString(R.string.bg_health_fix),
        ) { requestNotifications() }

        // 2. Исключение из оптимизации батареи
        addRow(
            title = getString(R.string.bg_health_check_battery),
            desc = if (battery) getString(R.string.secondary_bg_battery_ok)
                   else getString(R.string.secondary_bg_battery_bad),
            status = if (battery) Status.OK else Status.WARN,
            actionLabel = if (battery) null else getString(R.string.bg_health_fix),
        ) { requestBatteryExemption() }

        // 3. Background restriction (API 28+ "Restricted" state)
        addRow(
            title = getString(R.string.bg_health_check_bg_restriction),
            desc = if (bgRestricted) getString(R.string.secondary_bg_bg_bad)
                   else getString(R.string.secondary_bg_bg_ok),
            status = if (bgRestricted) Status.WARN else Status.OK,
            actionLabel = if (bgRestricted) getString(R.string.bg_health_fix) else null,
        ) { openAppDetailsSettings() }

        // 4. Постоянный VPN: система поднимает службу снова
        addRow(
            title = getString(R.string.bg_health_check_always_on),
            desc = when (alwaysOn) {
                true -> getString(R.string.secondary_bg_always_on_ok)
                false -> getString(R.string.secondary_bg_always_on_off)
                null -> getString(R.string.secondary_bg_unknown)
            },
            status = when (alwaysOn) {
                true -> Status.OK
                false -> Status.WARN
                null -> Status.UNKNOWN
            },
            actionLabel = if (alwaysOn == true) null else getString(R.string.bg_health_open),
        ) { openVpnSettings() }

        // 5. Блокировка соединений без VPN
        addRow(
            title = getString(R.string.bg_health_check_lockdown),
            desc = when (lockdown) {
                true -> getString(R.string.secondary_bg_lockdown_ok)
                false -> getString(R.string.secondary_bg_lockdown_off)
                null -> getString(R.string.secondary_bg_unknown)
            },
            status = when (lockdown) {
                true -> Status.OK
                false -> Status.WARN
                null -> Status.UNKNOWN
            },
            actionLabel = if (lockdown == true) null else getString(R.string.bg_health_open),
            divider = oemVendorLabel() != null,
        ) { openVpnSettings() }

        // 6. OEM autostart / proprietary battery manager (best effort)
        oemVendorLabel()?.let { vendor ->
            addRow(
                title = getString(R.string.bg_health_check_oem, vendor),
                desc = getString(R.string.secondary_bg_oem_desc),
                status = Status.UNKNOWN,
                actionLabel = getString(R.string.bg_health_open),
                divider = false,
            ) { openOemAutostartSettings() }
        }
    }

    private fun addRow(
        title: String,
        desc: String,
        status: Status,
        actionLabel: String?,
        divider: Boolean = true,
        action: (() -> Unit)? = null,
    ) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(16.dp, 12.dp, 16.dp, 12.dp)
        }
        row.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(12.dp, 12.dp).apply { marginEnd = 12.dp }
            setBackgroundResource(
                when (status) {
                    Status.OK -> R.drawable.dot_green
                    Status.WARN -> R.drawable.dot_yellow
                    Status.UNKNOWN -> R.drawable.dot_grey
                }
            )
        })
        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        textCol.addView(TextView(this).apply {
            text = title
            textSize = 16f
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
        })
        textCol.addView(TextView(this).apply {
            text = desc
            textSize = 14f
            setTextColor(
                if (status == Status.WARN) getColor(R.color.accent_lemon)
                else colorAttr(com.google.android.material.R.attr.colorOnSurfaceVariant, R.color.text_secondary)
            )
            setPadding(0, 4.dp, 0, 0)
        })
        row.addView(textCol)
        if (actionLabel != null && action != null) {
            row.addView(MaterialButton(
                this, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle
            ).apply {
                text = actionLabel
                textSize = 14f
                isAllCaps = false
                minWidth = 0
                minimumWidth = 0
                minHeight = 48.dp
                minimumHeight = 48.dp
                insetTop = 0
                insetBottom = 0
                setPadding(12.dp, 8.dp, 12.dp, 8.dp)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginStart = 8.dp }
                setOnClickListener { action() }
            })
        }
        binding.checklistContainer.addView(row)
        if (divider) {
            binding.checklistContainer.addView(View(this).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 1
                ).apply { setMargins(16.dp, 0, 16.dp, 0) }
                setBackgroundColor(colorAttr(com.google.android.material.R.attr.colorOutline, R.color.grey))
            })
        }
    }

    private fun colorAttr(attr: Int, fallback: Int): Int {
        val typed = android.util.TypedValue()
        return if (theme.resolveAttribute(attr, typed, true)) {
            if (typed.resourceId != 0) getColor(typed.resourceId) else typed.data
        } else {
            getColor(fallback)
        }
    }

    // ──────────── One-tap actions (deep links) ────────────

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            // Re-request first; the result callback falls back to settings when denied.
            notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        } else {
            // Permission granted but notifications toggled off (or pre-13 device).
            openAppNotificationSettings()
        }
    }

    private fun openAppNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            openAppDetailsSettings()
        }
    }

    /** Fires ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS (direct Allow/Deny dialog,
     *  requires the REQUEST_IGNORE_BATTERY_OPTIMIZATIONS manifest permission);
     *  falls back to the full battery-optimization list screen. */
    private fun requestBatteryExemption() {
        try {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (e: Exception) {
            Log.w(TAG, "Direct battery-exemption request failed: ${e.message}")
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (e2: Exception) {
                openAppDetailsSettings()
            }
        }
    }

    private fun openVpnSettings() {
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (e: ActivityNotFoundException) {
            openAppDetailsSettings()
        }
    }

    private fun openAppDetailsSettings() {
        try {
            startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to open app details settings: ${e.message}")
        }
    }

    // ──────────── OEM autostart (best effort) ────────────

    /** Human label for a known aggressive-power-manager OEM, or null. */
    private fun oemVendorLabel(): String? {
        val m = Build.MANUFACTURER.lowercase()
        return when {
            m.contains("xiaomi") || m.contains("redmi") || m.contains("poco") -> "Xiaomi/MIUI"
            m.contains("samsung") -> "Samsung"
            m.contains("huawei") || m.contains("honor") -> "Huawei"
            m.contains("oppo") || m.contains("realme") -> "Oppo"
            m.contains("vivo") -> "Vivo"
            m.contains("oneplus") -> "OnePlus"
            else -> null
        }
    }

    /** Known vendor autostart/battery-manager screens. Component names are
     *  firmware-specific and undocumented — every launch is wrapped in try/catch
     *  and the chain falls back to plain app settings. */
    private fun oemAutostartIntents(): List<Intent> {
        val m = Build.MANUFACTURER.lowercase()
        fun comp(pkg: String, cls: String) = Intent().setComponent(ComponentName(pkg, cls))
        return when {
            m.contains("xiaomi") || m.contains("redmi") || m.contains("poco") -> listOf(
                comp("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
            )
            m.contains("samsung") -> listOf(
                comp("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity"),
                comp("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity"),
            )
            m.contains("huawei") || m.contains("honor") -> listOf(
                comp("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
                comp("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
            )
            m.contains("oppo") || m.contains("realme") -> listOf(
                comp("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
                comp("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity"),
            )
            m.contains("vivo") -> listOf(
                comp("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"),
                comp("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager"),
            )
            m.contains("oneplus") -> listOf(
                comp("com.oneplus.security", "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity"),
            )
            else -> emptyList()
        }
    }

    private fun openOemAutostartSettings() {
        for (intent in oemAutostartIntents()) {
            try {
                startActivity(intent)
                return
            } catch (e: Exception) {
                // SecurityException / ActivityNotFoundException — try the next candidate.
                Log.d(TAG, "OEM autostart intent unavailable: ${intent.component} (${e.message})")
            }
        }
        openAppDetailsSettings()
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    companion object {
        private const val TAG = "BackgroundHealth"
    }
}
