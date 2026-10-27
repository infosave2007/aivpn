package com.aivpn.client

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Нажатия в Activity проверяются вместе с состоянием настоящего VpnService. */
@RunWith(AndroidJUnit4::class)
class TunnelLifecycleTest {
    @Test
    fun unvalidatedPhysicalNetworkCanCarryTheVpn() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val capabilities = manager.allNetworks.mapNotNull { manager.getNetworkCapabilities(it) }
            .firstOrNull { !it.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) &&
                it.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !it.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED) }
        assumeTrue("Нужна физическая сеть без успешной системной проверки интернета", capabilities != null)
        val method = AivpnService::class.java.getDeclaredMethod("isUsableUnderlyingNetwork", android.net.NetworkCapabilities::class.java)
        method.isAccessible = true
        assertTrue("Проверка доступа к серверам Android не определяет доступность VPN",
            method.invoke(AivpnService(), capabilities) as Boolean)
    }

    @Test
    fun repeatedConnectionsKeepUiAndNativeStateInSync() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val originalKey = arguments.getString("connectionKey").orEmpty()
        assumeTrue("Нужен ключ отдельного тестового сервера", originalKey.isNotBlank())
        val context = instrumentation.targetContext
        val oldProfiles = SecureStorage.loadProfiles(context)
        val oldActive = SecureStorage.loadActiveProfileId(context)
        val prefs = context.getSharedPreferences(PrefsKeys.PREFS_NAME, Context.MODE_PRIVATE)
        val preferenceKeys = listOf(PrefsKeys.ADAPTIVE_LEVEL, PrefsKeys.PREF_POLYMORPHIC_ENABLED,
            PrefsKeys.PREF_SHARE_MASK_FEEDBACK, PrefsKeys.PREF_RECEIVE_MASK_HINTS, PrefsKeys.PREF_COUNTRY_CODE)
        val oldPreferences = preferenceKeys.associateWith { prefs.all[it] }
        val oldApps = SecureStorage.loadAllowedApps(context)
        val oldExclusions = SecureStorage.loadExcludedDomains(context)
        val payload = JSONObject(String(Base64.decode(originalKey.removePrefix("aivpn://"), Base64.URL_SAFE)))
        if (arguments.getString("staleNetwork") == "true") {
            payload.getJSONObject("n").put("mtu", 1200).put("prefix_len", 25)
        }
        val key = "aivpn://" + Base64.encodeToString(payload.toString().toByteArray(),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val profile = SecureStorage.ConnectionProfile(
            id = "lifecycle-test", name = "Lifecycle test", key = key,
            dnsServers = when (arguments.getString("dnsMode")) {
                "default" -> emptyList()
                "mixed" -> listOf("203.0.113.2", "2001:4860:4860::8888")
                else -> listOf(arguments.getString("probeDns") ?: "203.0.113.2")
            },
            maskProfile = arguments.getString("maskProfile") ?: "auto",
        )
        fun waitUntil(message: String, timeout: Long = 8_000, condition: () -> Boolean) {
            val deadline = SystemClock.elapsedRealtime() + timeout
            while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(20)
            assertTrue("$message; state=${AivpnService.uiState} status=${AivpnService.lastStatusText}", condition())
        }
        fun stop() {
            context.startService(Intent(context, AivpnService::class.java).setAction(AivpnService.ACTION_DISCONNECT))
            waitUntil("Служба не остановилась") { AivpnService.instance == null }
        }
        fun shell(command: String) {
                android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
        }
        val networkMode = arguments.getString("networkMode")
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            if (android.os.Build.VERSION.SDK_INT >= 33) {
                shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
            }
            stop()
            prefs.edit().putInt(PrefsKeys.ADAPTIVE_LEVEL, arguments.getString("adaptive")?.toInt() ?: 0)
                .putBoolean(PrefsKeys.PREF_POLYMORPHIC_ENABLED, arguments.getString("polymorphic") == "true")
                .putBoolean(PrefsKeys.PREF_SHARE_MASK_FEEDBACK, arguments.getString("feedback") == "true")
                .putBoolean(PrefsKeys.PREF_RECEIVE_MASK_HINTS, arguments.getString("hints") == "true")
                .putString(PrefsKeys.PREF_COUNTRY_CODE, "RU").commit()
            SecureStorage.saveAllowedApps(context,
                if (arguments.getString("splitApps") == "true") setOf(context.packageName) else emptySet())
            SecureStorage.saveExcludedDomains(context,
                if (arguments.getString("bypass") == "true") listOf("10.0.2.2", "bypass.aivpn.test") else emptyList())
            SecureStorage.saveProfiles(context, oldProfiles.filter { it.id != profile.id } + profile)
            SecureStorage.saveActiveProfileId(context, profile.id)
            ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use { activity ->
                var previousService: AivpnService? = null
                repeat(arguments.getString("cycles")?.toInt() ?: 4) { cycle ->
                    arguments.getString("cancelStartupMs")?.toLong()?.let { delay ->
                        activity.onActivity { it.findViewById<Button>(R.id.btnConnect).performClick() }
                        waitUntil("Запуск не начался") { AivpnService.isServiceActive }
                        SystemClock.sleep(delay)
                        activity.onActivity { it.findViewById<Button>(R.id.btnConnect).performClick() }
                        waitUntil("Запуск не отменился") { !AivpnService.isServiceActive }
                    }
                    activity.onActivity {
                        it.findViewById<Button>(R.id.btnConnect).performClick()
                        if (arguments.getString("checkStartupEditing") == "true") {
                            val list = it.findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.profileList)
                            assertFalse("Профиль можно менять во время подключения", (list.adapter as ProfilesAdapter).editingEnabled)
                        }
                    }
                    waitUntil("Подключение $cycle не установлено") { AivpnService.isEstablished }
                    // Полиморфный вариант запрашивается после отдельного bootstrap-handshake.
                    if (profile.maskProfile != "auto" && arguments.getString("polymorphic") != "true") {
                        assertEquals("Ручной выбор маски не применился", profile.maskProfile,
                            AivpnJni.getAttemptedMaskFamily())
                    }
                    waitUntil("Статус $cycle не обновился", 1_000) {
                        var rendered = false
                        activity.onActivity {
                            rendered = it.findViewById<TextView>(R.id.textStatus).text.toString() == AivpnService.localizedStatus(it)
                        }
                        rendered
                    }
                    if (arguments.getString("duplicateConnect") == "true") {
                        repeat(3) {
                            context.startForegroundService(Intent(context, AivpnService::class.java).apply {
                                action = AivpnService.ACTION_CONNECT
                                putExtra("profile_id", profile.id)
                            })
                        }
                    }
                    if (arguments.getString("lateCallback") == "true") {
                        previousService?.let { old ->
                            val callback = AivpnService::class.java.getDeclaredMethod(
                                "postStatusCallback", Boolean::class.javaPrimitiveType, String::class.java)
                            callback.isAccessible = true
                            callback.invoke(old, false, context.getString(R.string.status_disconnected))
                            instrumentation.waitForIdleSync()
                        }
                    }
                    if (arguments.getString("lateDestroy") == "true") {
                        previousService?.let { old ->
                            assertNotSame("Предыдущая служба еще не заменена", old, AivpnService.instance)
                            instrumentation.runOnMainSync { old.onDestroy() }
                        }
                    }
                    if (arguments.getString("lateRevoke") == "true") {
                        previousService?.let { old ->
                            assertNotSame("Предыдущая служба еще не заменена", old, AivpnService.instance)
                            instrumentation.runOnMainSync { old.onRevoke() }
                        }
                    }
                    val establishedAt = AivpnService.connectedAtMillis
                    val until = SystemClock.elapsedRealtime() + (arguments.getString("holdMs")?.toLong() ?: 3_000)
                    while (SystemClock.elapsedRealtime() < until) {
                        assertTrue("Подключение $cycle само разорвалось", AivpnService.isEstablished)
                        assertEquals("Подключение $cycle незаметно перезапустилось", establishedAt, AivpnService.connectedAtMillis)
                        activity.onActivity {
                            assertEquals("Статус $cycle расходится со службой", AivpnService.localizedStatus(it),
                                it.findViewById<TextView>(R.id.textStatus).text.toString())
                            assertEquals(it.getString(R.string.btn_disconnect), it.findViewById<Button>(R.id.btnConnect).text)
                        }
                        SystemClock.sleep(50)
                    }
                    fun http(host: String, port: Int, request: ByteArray): ByteArray {
                        return java.net.Socket().use { socket ->
                            socket.soTimeout = 15_000
                            socket.connect(java.net.InetSocketAddress(host, port), 5_000)
                            socket.getOutputStream().write(request)
                            val response = socket.getInputStream().readBytes()
                            val header = response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
                            assertTrue("HTTP через VPN не прошел", header >= 0)
                            response.copyOfRange(header + 4, response.size)
                        }
                    }
                    val probeHost = arguments.getString("probeHost") ?: "example.aivpn.test"
                    val port = arguments.getString("probePort")?.toInt() ?: 8000
                    val data = ByteArray(65_536) { it.toByte() }
                    assertArrayEquals("Загрузка повреждена", data,
                        http(probeHost, port, "GET /small HTTP/1.0\r\nHost: runtime-test\r\n\r\n".toByteArray()))
                    val header = "POST / HTTP/1.0\r\nHost: runtime-test\r\nContent-Length: ${data.size}\r\n\r\n"
                    val uploaded = http(probeHost, port, header.toByteArray() + data).toString(Charsets.US_ASCII)
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(data).joinToString("") { "%02x".format(it) }
                    assertEquals("Отправка повреждена", digest, uploaded)
                    if (arguments.getString("bypass") == "true") {
                        assertEquals("Исключение не обходит VPN", "aivpn-bypass-ok\n",
                            http("bypass.aivpn.test", 18080, "GET / HTTP/1.0\r\nHost: bypass\r\n\r\n".toByteArray())
                                .toString(Charsets.US_ASCII))
                    }
                    assertTrue("Соединение потеряно во время передачи", AivpnService.isEstablished)
                    assertEquals("Туннель перезапустился во время передачи", establishedAt, AivpnService.connectedAtMillis)
                    if (networkMode != null) {
                        shell("svc wifi disable")
                        if (networkMode == "loss") shell("svc data disable")
                        try {
                            if (networkMode == "loss") {
                                waitUntil("Потеря физической сети не отражена в состоянии VPN", 3_000) { !AivpnService.isEstablished }
                            }
                            SystemClock.sleep(arguments.getString("networkDownMs")?.toLong() ?: 3_000)
                            assertTrue("Потеря сети отменила желание держать VPN", AivpnService.isServiceActive)
                            assertTrue(BootPrefs.prefs(context).getBoolean(PrefsKeys.PREF_VPN_DESIRED, false))
                            if (networkMode == "loss") {
                                activity.onActivity {
                                    assertEquals(it.getString(R.string.ui_cancel_connect), it.findViewById<Button>(R.id.btnConnect).text)
                                    assertEquals(AivpnService.localizedStatus(it), it.findViewById<TextView>(R.id.textStatus).text.toString())
                                }
                            }
                        } finally {
                            shell("svc wifi enable")
                            shell("svc data enable")
                        }
                        val recoveryStarted = SystemClock.elapsedRealtime()
                        val restored = recoveryStarted + 10_000
                        var received = false
                        while (!received && SystemClock.elapsedRealtime() < restored) {
                            received = try {
                                java.net.Socket().use { socket ->
                                    socket.soTimeout = 1_000
                                    socket.connect(java.net.InetSocketAddress("203.0.113.2", 8000), 1_000)
                                    socket.getOutputStream().write("GET / HTTP/1.0\r\nHost: runtime-test\r\n\r\n".toByteArray())
                                    socket.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("aivpn-local-lab-ok\n")
                                }
                            } catch (_: Exception) { false }
                            if (!received) SystemClock.sleep(100)
                        }
                        assertTrue("После возврата сети трафик сам не восстановился", received)
                        instrumentation.sendStatus(2, android.os.Bundle().apply {
                            putString("stream", "\nВосстановление трафика: ${SystemClock.elapsedRealtime() - recoveryStarted} мс\n")
                        })
                        waitUntil("Восстановленный VPN не объявил готовность") { AivpnService.isEstablished }
                        // Ждем возврата Wi-Fi перед следующим ручным переподключением.
                        // Первый трафик уже мог восстановиться через мобильную сеть.
                        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                        waitUntil("Wi-Fi не вернулся после включения", 10_000) {
                            manager.allNetworks.any { manager.getNetworkCapabilities(it)
                                ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true }
                        }
                        SystemClock.sleep(750)
                    }
                    if (arguments.getString("serverOutage") == "true") {
                        instrumentation.sendStatus(2, android.os.Bundle().apply {
                            putString("stream", "\nAIVPN_TEST_READY_FOR_SERVER_RESTART\n")
                        })
                        var outageObserved = false
                        var restored = false
                        val restartStarted = SystemClock.elapsedRealtime()
                        val deadline = restartStarted + 90_000
                        while (SystemClock.elapsedRealtime() < deadline) {
                            assertTrue("Сбой сервера остановил службу", AivpnService.isServiceActive)
                            assertTrue("Сбой сервера отменил желание держать VPN",
                                BootPrefs.prefs(context).getBoolean(PrefsKeys.PREF_VPN_DESIRED, false))
                            val received = try {
                                java.net.Socket().use { socket ->
                                    socket.soTimeout = 1_000
                                    socket.connect(java.net.InetSocketAddress(probeHost, port), 1_000)
                                    socket.getOutputStream().write("GET / HTTP/1.0\r\nHost: runtime-test\r\n\r\n".toByteArray())
                                    socket.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("aivpn-local-lab-ok\n")
                                }
                            } catch (_: Exception) { false }
                            if (!received) outageObserved = true
                            if (outageObserved && received && AivpnService.isEstablished) {
                                restored = true
                                break
                            }
                            SystemClock.sleep(150)
                        }
                        assertTrue("Сбой тестового сервера не наблюдался", outageObserved)
                        assertTrue("После перезапуска сервера VPN сам не восстановился", restored)
                        instrumentation.sendStatus(2, android.os.Bundle().apply {
                            putString("stream", "\nВосстановление после сервера: ${SystemClock.elapsedRealtime() - restartStarted} мс\n")
                        })
                    }
                    if (arguments.getString("background") == "true") {
                        activity.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
                        SystemClock.sleep(500)
                        activity.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
                    }
                    if (arguments.getString("recreate") == "true") activity.recreate()
                    activity.onActivity {
                        assertEquals("После возврата статус расходится со службой", AivpnService.localizedStatus(it),
                            it.findViewById<TextView>(R.id.textStatus).text.toString())
                    }
                    previousService = AivpnService.instance
                    activity.onActivity { it.findViewById<Button>(R.id.btnConnect).performClick() }
                    waitUntil("Отключение $cycle не выполнено") { !AivpnService.isServiceActive }
                    SystemClock.sleep(arguments.getString("reconnectDelayMs")?.toLong() ?: 0)
                }
            }
        } finally {
            if (networkMode != null) {
                shell("svc wifi enable")
                shell("svc data enable")
            }
            stop()
            SecureStorage.saveProfiles(context, oldProfiles)
            SecureStorage.saveActiveProfileId(context, oldActive)
            SecureStorage.saveAllowedApps(context, oldApps)
            SecureStorage.saveExcludedDomains(context, oldExclusions)
            prefs.edit().also { editor ->
                for ((key, value) in oldPreferences) {
                    when (value) {
                        is Int -> editor.putInt(key, value)
                        is Boolean -> editor.putBoolean(key, value)
                        is String -> editor.putString(key, value)
                        else -> editor.remove(key)
                    }
                }
            }.commit()
        }
    }
}
