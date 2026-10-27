package com.aivpn.client

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.View
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.navigation.NavigationBarView
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.Socket
import java.net.InetSocketAddress

/** Приемка оформления вместе с настоящим локальным туннелем. */
@RunWith(AndroidJUnit4::class)
class MaterialAcceptanceTest {
    @Test
    fun appearanceAndNavigationKeepAnEstablishedTunnel() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val key = args.getString("connectionKey").orEmpty()
        assumeTrue("Нужен ключ отдельного тестового сервера", key.isNotBlank())
        val context = instrumentation.targetContext
        val originalProfiles = SecureStorage.loadProfiles(context)
        val originalActive = SecureStorage.loadActiveProfileId(context)
        val originalLanguage = SecureStorage.loadLanguage(context)
        val originalApps = SecureStorage.loadAllowedApps(context)
        val originalDomains = SecureStorage.loadExcludedDomains(context)
        val originalLocales = AppCompatDelegate.getApplicationLocales()
        val appearance = context.createDeviceProtectedStorageContext().getSharedPreferences("aivpn_appearance", Context.MODE_PRIVATE)
        val originalTheme = appearance.getInt("theme", AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        val originalColors = appearance.getBoolean("dynamic_colors", false)
        val profile = SecureStorage.ConnectionProfile("material-acceptance", "Личный", key, maskProfile = "quic_https_v2")
        fun shell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(
            instrumentation.uiAutomation.executeShellCommand(command),
        ).use { it.readBytes().toString(Charsets.UTF_8).trim() }
        val originalFont = shell("settings get system font_scale").toFloatOrNull() ?: 1f
        fun waitUntil(message: String, condition: () -> Boolean) {
            val deadline = SystemClock.elapsedRealtime() + 10_000
            while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(25)
            assertTrue(message, condition())
        }
        fun capture(name: String) {
            instrumentation.waitForIdleSync()
            SystemClock.sleep(700)
            instrumentation.waitForIdleSync()
            val bitmap = instrumentation.uiAutomation.takeScreenshot()
            assertNotNull("Не удалось получить снимок Android", bitmap)
            val directory = context.getExternalFilesDir("ui-acceptance")!!
            directory.mkdirs()
            File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            bitmap.recycle()
        }
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
            SecureStorage.saveProfiles(context, originalProfiles.filter { it.id != profile.id } + profile)
            SecureStorage.saveActiveProfileId(context, profile.id)
            SecureStorage.saveLanguage(context, "ru")
            SecureStorage.saveAllowedApps(context, emptySet())
            SecureStorage.saveExcludedDomains(context, emptyList())
            appearance.edit().putInt("theme", AppCompatDelegate.MODE_NIGHT_NO).putBoolean("dynamic_colors", false).commit()
            instrumentation.runOnMainSync {
                UiAppearance.applyTheme(context)
                AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("ru"))
            }
            context.startForegroundService(Intent(context, AivpnService::class.java).setAction(AivpnService.ACTION_CONNECT).putExtra("profile_id", profile.id))
            waitUntil("Локальный VPN не подключился") { AivpnService.isEstablished }
            val connectivity = context.getSystemService(android.net.ConnectivityManager::class.java)
            waitUntil("Android не назначил VPN основной сетью") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
            }
            val connectedAt = AivpnService.connectedAtMillis
            val host = args.getString("probeHost") ?: "10.97.25.1"
            val port = args.getString("probePort")?.toInt() ?: 28080
            // Смена основной сети приходит в процесс асинхронно после создания VPN.
            // Сокет, открытый раньше этого события, остается в прежней сети.
            val trafficDeadline = SystemClock.elapsedRealtime() + 12_000
            var trafficReady = false
            var firstAttemptFailed = false
            while (!trafficReady && SystemClock.elapsedRealtime() < trafficDeadline) {
                trafficReady = try {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(host, port), 1_000)
                        socket.soTimeout = 3_000
                        socket.getOutputStream().write("GET /small HTTP/1.0\r\nHost: ui-test\r\n\r\n".toByteArray())
                        socket.getInputStream().readBytes().size > 65_536
                    }
                } catch (_: java.io.IOException) { firstAttemptFailed = true; false }
                if (!trafficReady) SystemClock.sleep(100)
            }
            assertTrue("После назначения VPN трафик не появился", trafficReady)
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putString("stream", "\nПервый сокет создан до смены основной сети: $firstAttemptFailed\n")
            })
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                val loaded = MainActivity::class.java.getDeclaredField("profilesLoaded").apply { isAccessible = true }
                fun waitForHome() {
                    waitUntil("Главный экран не восстановился") {
                        var ready = false
                        scenario.onActivity { ready = loaded.getBoolean(it) }
                        ready
                    }
                    instrumentation.waitForIdleSync()
                }
                waitForHome()
                SystemClock.sleep(1_100)
                scenario.onActivity { activity ->
                    assertTrue(activity.findViewById<View>(R.id.sessionStats).isShown)
                    assertEquals(activity.getString(R.string.btn_disconnect), activity.findViewById<android.widget.Button>(R.id.btnConnect).text)
                }
                capture("connected-light")
                appearance.edit().putInt("theme", AppCompatDelegate.MODE_NIGHT_YES).commit()
                instrumentation.runOnMainSync { UiAppearance.applyTheme(context) }
                waitForHome()
                capture("connected-dark")
                scenario.onActivity { it.findViewById<NavigationBarView>(R.id.mainNavigation).selectedItemId = R.id.nav_profiles }
                capture("profiles-dark")
                scenario.onActivity { it.findViewById<NavigationBarView>(R.id.mainNavigation).selectedItemId = R.id.nav_settings }
                capture("settings-dark")
                scenario.onActivity { it.findViewById<NavigationBarView>(R.id.mainNavigation).selectedItemId = R.id.nav_vpn }
                shell("wm size 945x2100")
                instrumentation.waitForIdleSync()
                capture("connected-360dp")
                shell("wm size 840x1890")
                shell("settings put system font_scale 1.5")
                waitForHome()
                waitUntil("Крупный шрифт не применился") {
                    var ready = false
                    scenario.onActivity { ready = it.resources.configuration.fontScale > 1.4f && it.resources.configuration.screenWidthDp <= 320 }
                    ready
                }
                capture("connected-320dp-large-text")
                shell("settings put system font_scale $originalFont")
                shell("wm size reset")
                waitForHome()
                waitUntil("Размер шрифта не восстановился") {
                    var ready = false
                    scenario.onActivity { ready = kotlin.math.abs(it.resources.configuration.fontScale - originalFont) < 0.01f }
                    ready
                }
                scenario.onActivity { it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE }
                waitUntil("Экран не повернулся") {
                    var ready = false
                    scenario.onActivity { ready = it.resources.configuration.orientation == android.content.res.Configuration.ORIENTATION_LANDSCAPE }
                    ready
                }
                capture("connected-landscape")
                scenario.onActivity { it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT }
                waitUntil("Экран не вернулся в портретный режим") {
                    var ready = false
                    scenario.onActivity { ready = it.resources.configuration.orientation == android.content.res.Configuration.ORIENTATION_PORTRAIT }
                    ready
                }
                assertTrue("Смена оформления остановила VPN", AivpnService.isEstablished)
                assertEquals("Смена оформления перезапустила сеанс", connectedAt, AivpnService.connectedAtMillis)
            }
            ActivityScenario.launch(SplitTunnelActivity::class.java).use { instrumentation.waitForIdleSync(); capture("split-tunnel") }
            ActivityScenario.launch(BackgroundHealthActivity::class.java).use { instrumentation.waitForIdleSync(); capture("background-health") }
            ActivityScenario.launch(InstallServerActivity::class.java).use { instrumentation.waitForIdleSync(); capture("install-server") }
        } finally {
            context.startService(Intent(context, AivpnService::class.java).setAction(AivpnService.ACTION_DISCONNECT))
            waitUntil("VPN не остановился после проверки") { !AivpnService.isServiceActive }
            shell("settings put system font_scale $originalFont")
            shell("wm size reset")
            SecureStorage.saveProfiles(context, originalProfiles)
            SecureStorage.saveActiveProfileId(context, originalActive)
            SecureStorage.saveLanguage(context, originalLanguage)
            SecureStorage.saveAllowedApps(context, originalApps)
            SecureStorage.saveExcludedDomains(context, originalDomains)
            appearance.edit().putInt("theme", originalTheme).putBoolean("dynamic_colors", originalColors).commit()
            instrumentation.runOnMainSync { UiAppearance.applyTheme(context); AppCompatDelegate.setApplicationLocales(originalLocales) }
        }
    }
}
