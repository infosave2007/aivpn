package com.aivpn.client

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Проверка настоящего VpnService и JNI на отдельном сетевом стенде. */
@RunWith(AndroidJUnit4::class)
class TunnelConnectivityTest {
    @Test
    @SdkSuppress(minSdkVersion = 31)
    fun connectsAndTransfersThroughTun() {
        val arguments = InstrumentationRegistry.getArguments()
        val connectionKey = arguments.getString("connectionKey").orEmpty()
        assumeTrue("Нужен ключ отдельного тестового сервера", connectionKey.isNotBlank())
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val probeHost = arguments.getString("probeHost") ?: "example.aivpn.test"
        val probePort = arguments.getString("probePort")?.toInt() ?: 8000
        require(probeHost.matches(Regex("[A-Za-z0-9.:-]+")) && probePort in 1..65535)
        val oldProfiles = SecureStorage.loadProfiles(context)
        val oldActive = SecureStorage.loadActiveProfileId(context)
        val oldApps = SecureStorage.loadAllowedApps(context)
        val oldDomains = SecureStorage.loadExcludedDomains(context)
        val profile = SecureStorage.ConnectionProfile(
            id = "runtime-connectivity-test",
            name = "Runtime connectivity test",
            key = connectionKey,
            dnsServers = listOf(arguments.getString("probeDns") ?: "203.0.113.2"),
            maskProfile = arguments.getString("maskProfile") ?: "quic_https_v2",
        )
        fun shell(command: String): String = instrumentation.uiAutomation
            .executeShellCommand(command).use { descriptor ->
                ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { stream ->
                    stream.readBytes().toString(Charsets.UTF_8)
                }
            }
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            assertNull("Нет разрешения на тестовый VPN", VpnService.prepare(context))
            SecureStorage.saveProfiles(context, oldProfiles.filter { it.id != profile.id } + profile)
            SecureStorage.saveActiveProfileId(context, profile.id)
            SecureStorage.saveAllowedApps(context, emptySet())
            SecureStorage.saveExcludedDomains(context, emptyList())
            context.startForegroundService(Intent(context, AivpnService::class.java).apply {
                action = AivpnService.ACTION_CONNECT
                putExtra("profile_id", profile.id)
            })
            val deadline = SystemClock.elapsedRealtime() + 8_000L
            while (!AivpnService.isEstablished && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(50)
            }
            assertTrue("Туннель не подключился: ${AivpnService.lastStatusText}", AivpnService.isEstablished)
            var reply = ""
            val dataDeadline = SystemClock.elapsedRealtime() + 8_000L
            while (SystemClock.elapsedRealtime() < dataDeadline) {
                val pipes = instrumentation.uiAutomation
                    .executeShellCommandRw("toybox nc -w 2 $probeHost $probePort")
                ParcelFileDescriptor.AutoCloseOutputStream(pipes[1]).use { stream ->
                    stream.write("GET / HTTP/1.0\r\nHost: runtime-test\r\n\r\n".toByteArray())
                }
                reply = ParcelFileDescriptor.AutoCloseInputStream(pipes[0]).use { stream ->
                    stream.readBytes().toString(Charsets.UTF_8)
                }
                if (reply.contains("200 OK")) break
                SystemClock.sleep(100)
            }
            assertTrue("HTTP-ответ не прошел через VPN: ${reply.take(200)}", reply.contains("200 OK"))
            assertTrue("Ответ тестового сервера поврежден", reply.endsWith("aivpn-local-lab-ok\n"))
            fun exchange(request: ByteArray): ByteArray {
                val pipes = instrumentation.uiAutomation
                    .executeShellCommandRw("toybox nc -w 10 $probeHost $probePort")
                ParcelFileDescriptor.AutoCloseOutputStream(pipes[1]).use { it.write(request) }
                val response = ParcelFileDescriptor.AutoCloseInputStream(pipes[0]).use { it.readBytes() }
                val header = response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
                assertTrue("HTTP-ответ не содержит заголовков", header >= 0)
                assertTrue("HTTP-запрос завершился ошибкой", response.take(40).toByteArray()
                    .toString(Charsets.US_ASCII).contains("200 OK"))
                return response.copyOfRange(header + 4, response.size)
            }
            val payload = ByteArray(65_536) { it.toByte() }
            val downloaded = exchange("GET /small HTTP/1.0\r\nHost: runtime-test\r\n\r\n".toByteArray())
            assertArrayEquals("Загрузка через VPN повреждена", payload, downloaded)
            val uploadHeader = "POST / HTTP/1.0\r\nHost: runtime-test\r\nContent-Length: ${payload.size}\r\n\r\n"
            val uploaded = exchange(uploadHeader.toByteArray() + payload).toString(Charsets.US_ASCII)
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(payload).joinToString("") { "%02x".format(it) }
            assertEquals("Отправка через VPN повреждена", digest, uploaded)
            assertTrue("Счетчик приема остался нулевым", AivpnJni.getDownloadBytes() > 0)
            assertTrue("Счетчик отправки остался нулевым", AivpnJni.getUploadBytes() > 0)
        } finally {
            context.startService(Intent(context, AivpnService::class.java).apply {
                action = AivpnService.ACTION_DISCONNECT
            })
            val deadline = SystemClock.elapsedRealtime() + 5_000L
            while (AivpnService.isServiceActive && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(50)
            }
            SecureStorage.saveProfiles(context, oldProfiles)
            SecureStorage.saveActiveProfileId(context, oldActive)
            SecureStorage.saveAllowedApps(context, oldApps)
            SecureStorage.saveExcludedDomains(context, oldDomains)
        }
    }
}
