package com.aivpn.client

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.appcompat.app.AppCompatDelegate
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Возврат из мастера и системных окон не теряет профиль или запрос VPN. */
@RunWith(AndroidJUnit4::class)
class ActivityRecoveryTest {
    private fun waitFor(message: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 12_000
        while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(25)
        assertTrue(message, condition())
    }

    private fun field(name: String) = MainActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    @Test
    @androidx.test.filters.SdkSuppress(minSdkVersion = 29)
    fun returningFromInstallerRefreshesProfilesBeforeSaving() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val original = SecureStorage.loadProfiles(context)
        val active = SecureStorage.loadActiveProfileId(context)
        val key = "aivpn://" + android.util.Base64.encodeToString(
            """{"s":"vpn.example.net:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","i":"10.0.0.2"}""".toByteArray(),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING,
        )
        val first = SecureStorage.ConnectionProfile("return-first", "Первый", key)
        val imported = first.copy(id = "return-imported", name = "Новый")
        try {
            SecureStorage.saveProfiles(context, listOf(first))
            SecureStorage.saveActiveProfileId(context, first.id)
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                fun loaded(id: String): Boolean {
                    var ready = false
                    scenario.onActivity { ready = field("profilesLoaded").getBoolean(it) && field("activeProfileId").get(it) == id }
                    return ready
                }
                waitFor("Первый профиль не загружен") { loaded(first.id) }
                scenario.moveToState(Lifecycle.State.CREATED)
                SecureStorage.saveProfiles(context, listOf(first, imported))
                SecureStorage.saveActiveProfileId(context, imported.id)
                scenario.moveToState(Lifecycle.State.RESUMED)
                waitFor("Импортированный профиль не появился после возврата") { loaded(imported.id) }
                scenario.onActivity { activity ->
                    MainActivity::class.java.getDeclaredMethod("showProfileDialog", SecureStorage.ConnectionProfile::class.java)
                        .apply { isAccessible = true }.invoke(activity, first)
                }
                InstrumentationRegistry.getInstrumentation().runOnMainSync {
                    android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                        .findViewById<android.view.View>(android.R.id.button1).performClick()
                }
                assertEquals(setOf(first.id, imported.id), SecureStorage.loadProfiles(context).map { it.id }.toSet())
            }
        } finally {
            SecureStorage.saveProfiles(context, original)
            if (active.isNullOrBlank()) SecureStorage.remove(context, "active_profile_id")
            else SecureStorage.saveActiveProfileId(context, active)
        }
    }

    @Test
    fun grantedConsentSurvivesPendingProfileLoadAndRecreation() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val key = InstrumentationRegistry.getArguments().getString("connectionKey").orEmpty()
        assumeTrue("Нужен отдельный тестовый сервер", key.isNotBlank())
        val original = SecureStorage.loadProfiles(context)
        val active = SecureStorage.loadActiveProfileId(context)
        val apps = SecureStorage.loadAllowedApps(context)
        val domains = SecureStorage.loadExcludedDomains(context)
        val profile = SecureStorage.ConnectionProfile("consent-pending", "Согласие", key, dnsServers = listOf("203.0.113.2"))
        try {
            SecureStorage.saveProfiles(context, listOf(profile))
            SecureStorage.saveActiveProfileId(context, profile.id)
            SecureStorage.saveAllowedApps(context, emptySet())
            SecureStorage.saveExcludedDomains(context, emptyList())
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                waitFor("Профили не загружены") {
                    var ready = false
                    scenario.onActivity { ready = field("profilesLoaded").getBoolean(it) }
                    ready
                }
                scenario.onActivity { activity ->
                    field("profilesLoaded").setBoolean(activity, false)
                    field("activeProfileId").set(activity, null)
                    field("pendingVpnProfileId").set(activity, profile.id)
                    val registry = activity.activityResultRegistry
                    val mapping = registry.javaClass.superclass!!.declaredFields.firstOrNull { it.name == "mKeyToRc" || it.name == "keyToRc" }
                        ?: androidx.activity.result.ActivityResultRegistry::class.java.declaredFields.first { it.name == "mKeyToRc" || it.name == "keyToRc" }
                    mapping.isAccessible = true
                    val codes = mapping.get(registry) as Map<*, *>
                    val launched = androidx.activity.result.ActivityResultRegistry::class.java.declaredFields
                        .first { it.name == "mLaunchedKeys" || it.name == "launchedKeys" }.apply { isAccessible = true }
                    @Suppress("UNCHECKED_CAST")
                    val waiting = launched.get(registry) as MutableList<String>
                    waiting.add("activity_rq#0")
                    registry.dispatchResult(codes["activity_rq#0"] as Int, Activity.RESULT_OK, Intent())
                    assertFalse("Служба запущена до чтения профиля", AivpnService.isServiceActive)
                    assertTrue(field("pendingVpnPermissionGranted").getBoolean(activity))
                }
                scenario.recreate()
                waitFor("Согласие потерялось при пересоздании Activity") { AivpnService.isEstablished }
            }
        } finally {
            context.startService(Intent(context, AivpnService::class.java).setAction(AivpnService.ACTION_DISCONNECT))
            waitFor("Служба не остановилась") { AivpnService.instance == null }
            SecureStorage.saveProfiles(context, original)
            if (active.isNullOrBlank()) SecureStorage.remove(context, "active_profile_id")
            else SecureStorage.saveActiveProfileId(context, active)
            SecureStorage.saveAllowedApps(context, apps)
            SecureStorage.saveExcludedDomains(context, domains)
        }
    }

    @Test
    @androidx.test.filters.SdkSuppress(minSdkVersion = 29)
    fun emptyClientNameDoesNotDiscardTheAdminForm() {
        ActivityScenario.launch(AdminActivity::class.java).use { scenario ->
            scenario.onActivity {
                AdminActivity::class.java.getDeclaredMethod("showAddDialogWithOptions", List::class.java)
                    .apply { isAccessible = true }.invoke(it, emptyList<Any>())
            }
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                val form = android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                form.findViewById<android.view.View>(android.R.id.button1).performClick()
                assertTrue("Пустое имя закрыло форму создания клиента", form.isAttachedToWindow)
            }
        }
    }

    @Test
    fun nightModeDoesNotDestroyTheInstallationWizard() {
        val original = AppCompatDelegate.getDefaultNightMode()
        try {
            ActivityScenario.launch(InstallServerActivity::class.java).use { scenario ->
                var initial: InstallServerActivity? = null
                scenario.onActivity {
                    initial = it
                    InstallServerActivity::class.java.getDeclaredField("host").apply { isAccessible = true }.set(it, "wizard-state.example")
                    val next = if (it.resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK == android.content.res.Configuration.UI_MODE_NIGHT_YES)
                        AppCompatDelegate.MODE_NIGHT_NO else AppCompatDelegate.MODE_NIGHT_YES
                    AppCompatDelegate.setDefaultNightMode(next)
                }
                SystemClock.sleep(500)
                scenario.onActivity {
                    assertSame("Смена темы уничтожила мастер", initial, it)
                    assertEquals("wizard-state.example", InstallServerActivity::class.java.getDeclaredField("host").apply { isAccessible = true }.get(it))
                }
            }
        } finally {
            InstrumentationRegistry.getInstrumentation().runOnMainSync { AppCompatDelegate.setDefaultNightMode(original) }
        }
    }
}
