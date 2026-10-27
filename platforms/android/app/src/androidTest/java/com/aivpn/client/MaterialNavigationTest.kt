package com.aivpn.client

import android.view.View
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.navigation.NavigationBarView
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Проверяет навигацию и защиту формы на настоящем Android. */
@RunWith(AndroidJUnit4::class)
class MaterialNavigationTest {
    @Test
    @androidx.test.filters.SdkSuppress(minSdkVersion = 29)
    fun profileEditorSavesEditsAndConfirmsDeletion() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val original = SecureStorage.loadProfiles(context)
        val active = SecureStorage.loadActiveProfileId(context)
        val key = "aivpn://" + android.util.Base64.encodeToString(
            """{"s":"vpn.example.net:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","i":"10.0.0.2"}""".toByteArray(),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING,
        )
        try {
            SecureStorage.saveProfiles(context, emptyList())
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                val loaded = MainActivity::class.java.getDeclaredField("profilesLoaded").apply { isAccessible = true }
                var ready = false
                val deadline = android.os.SystemClock.elapsedRealtime() + 5_000
                while (!ready && android.os.SystemClock.elapsedRealtime() < deadline) {
                    scenario.onActivity { ready = loaded.getBoolean(it) }
                    if (!ready) android.os.SystemClock.sleep(25)
                }
                assertTrue(ready)
                val editor = MainActivity::class.java.getDeclaredMethod("showProfileDialog", SecureStorage.ConnectionProfile::class.java).apply { isAccessible = true }
                scenario.onActivity { editor.invoke(it, null) }
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync {
                    val window = android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                    window.findViewById<EditText>(R.id.profileNameInput).setText("Личный профиль для поездок и удаленной работы ".repeat(4))
                    window.findViewById<EditText>(R.id.profileKeyInput).setText(key)
                    window.findViewById<View>(android.R.id.button1).performClick()
                }
                val created = SecureStorage.loadProfiles(context).single()
                assertEquals(key, created.key)
                scenario.onActivity { editor.invoke(it, created) }
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync {
                    val window = android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                    window.findViewById<EditText>(R.id.profileNameInput).setText("Переименованный")
                    window.findViewById<View>(android.R.id.button1).performClick()
                }
                val edited = SecureStorage.loadProfiles(context).single()
                assertEquals("Переименованный", edited.name)
                assertEquals(key, edited.key)
                scenario.onActivity { activity ->
                    MainActivity::class.java.getDeclaredMethod("confirmDeleteProfile", SecureStorage.ConnectionProfile::class.java)
                        .apply { isAccessible = true }.invoke(activity, edited)
                }
                instrumentation.waitForIdleSync()
                assertEquals("До подтверждения профиль должен сохраниться", 1, SecureStorage.loadProfiles(context).size)
                instrumentation.runOnMainSync {
                    android.view.inspector.WindowInspector.getGlobalWindowViews().last().findViewById<View>(android.R.id.button1).performClick()
                }
                instrumentation.waitForIdleSync()
                assertTrue(SecureStorage.loadProfiles(context).isEmpty())
            }
        } finally {
            SecureStorage.saveProfiles(context, original)
            SecureStorage.saveActiveProfileId(context, active)
        }
    }

    @Test
    @androidx.test.filters.SdkSuppress(minSdkVersion = 29)
    fun adminEditorCanScrollToTheLastField() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(AdminActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                AdminActivity::class.java.getDeclaredMethod("showEditDialogWithOptions", org.json.JSONObject::class.java, String::class.java, List::class.java)
                    .apply { isAccessible = true }
                    .invoke(activity, org.json.JSONObject("""{"name":"Проверка","enabled":true,"exit_node":"192.0.2.1:443"}"""), "ui-test-only", emptyList<Any>())
            }
            instrumentation.waitForIdleSync()
            scenario.onActivity {
                fun descendants(view: View): List<View> = listOf(view) +
                    if (view is android.view.ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()
                val root = android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                val fields = descendants(root).filterIsInstance<EditText>()
                assertTrue(fields.isNotEmpty())
                val last = fields.last()
                var ancestor = last.parent
                while (ancestor != null && ancestor !is androidx.core.widget.NestedScrollView) ancestor = ancestor.parent
                assertNotNull("Нижнее поле должно оставаться доступным при клавиатуре и крупном шрифте", ancestor)
                (ancestor as androidx.core.widget.NestedScrollView).fullScroll(View.FOCUS_DOWN)
                assertTrue(last.requestFocus())
            }
        }
    }

    @Test
    fun settingsRefreshSplitTunnelSummaryAfterReturn() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val original = SecureStorage.loadAllowedApps(context)
        val originalDomains = SecureStorage.loadExcludedDomains(context)
        try {
            SecureStorage.saveAllowedApps(context, emptySet())
            SecureStorage.saveExcludedDomains(context, emptyList())
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                android.os.SystemClock.sleep(500)
                scenario.onActivity { it.findViewById<NavigationBarView>(R.id.mainNavigation).selectedItemId = R.id.nav_settings }
                instrumentation.waitForIdleSync()
                scenario.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
                SecureStorage.saveAllowedApps(context, setOf("com.example.ui.acceptance"))
                scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
                var updated = false
                val deadline = android.os.SystemClock.elapsedRealtime() + 5_000
                while (!updated && android.os.SystemClock.elapsedRealtime() < deadline) {
                    scenario.onActivity { activity ->
                        fun hasText(view: View, expected: String): Boolean =
                            (view is android.widget.TextView && view.text.toString() == expected) ||
                                (view is android.view.ViewGroup && (0 until view.childCount).any { hasText(view.getChildAt(it), expected) })
                        updated = hasText(activity.findViewById(R.id.settingsContainer), activity.getString(R.string.split_tunnel_vpn_count, 1))
                    }
                    if (!updated) android.os.SystemClock.sleep(25)
                }
                assertTrue("Настройки показывают старое число приложений после возврата", updated)
            }
        } finally {
            SecureStorage.saveAllowedApps(context, original)
            SecureStorage.saveExcludedDomains(context, originalDomains)
        }
    }

    @Test
    fun appearanceDoesNotRequireCredentialStorage() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.targetContext
        val lockedContext = object : android.content.ContextWrapper(original) {
            override fun getSharedPreferences(name: String, mode: Int): android.content.SharedPreferences =
                throw IllegalStateException("Credential storage is unavailable before unlock")

            override fun createDeviceProtectedStorageContext(): android.content.Context =
                original.createDeviceProtectedStorageContext()
        }
        instrumentation.runOnMainSync {
            UiAppearance.applyTheme(lockedContext)
            UiAppearance.dynamicColors(lockedContext)
        }
    }

    @Test
    fun sessionMetricsRemainReadableWithLargeText() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            val original = instrumentation.targetContext
            for (scale in listOf(1f, 1.5f)) {
                val configuration = android.content.res.Configuration(original.resources.configuration).apply { fontScale = scale }
                val context = androidx.appcompat.view.ContextThemeWrapper(original.createConfigurationContext(configuration), R.style.Theme_AIVPN)
                val stats = SessionStatsView(context)
                stats.setTraffic(Long.MAX_VALUE, null)
                stats.setElapsed(90_061)
                val width = (280 * context.resources.displayMetrics.density).toInt()
                stats.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED))
                stats.layout(0, 0, stats.measuredWidth, stats.measuredHeight)
                val bounds = (0 until stats.childCount).map { index ->
                    stats.getChildAt(index).let { android.graphics.Rect(it.left, it.top, it.right, it.bottom) }
                }
                bounds.forEach { assertTrue("Показатель выходит за границы экрана", it.left >= 0 && it.right <= width && it.bottom <= stats.height) }
                for (first in bounds.indices) for (second in first + 1 until bounds.size) {
                    assertFalse("Показатели перекрываются при размере шрифта $scale", android.graphics.Rect.intersects(bounds[first], bounds[second]))
                }
                assertEquals("25:01:01", stats.elapsedText())
                assertEquals(context.getString(R.string.ui_no_data), stats.receivedText())
                assertTrue(stats.contentDescription.contains(stats.sentText()))
            }
        }
    }

    @Test
    fun connectedSessionCannotChangeProfiles() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val original = SecureStorage.loadProfiles(context)
        val activeId = SecureStorage.loadActiveProfileId(context)
        val key = "aivpn://" + android.util.Base64.encodeToString(
            """{"s":"vpn.example.net:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","i":"10.0.0.2"}""".toByteArray(),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING,
        )
        val first = SecureStorage.ConnectionProfile(id = "material-test-first", name = "Первый", key = key)
        val second = first.copy(id = "material-test-second", name = "Второй")
        try {
            SecureStorage.saveProfiles(context, listOf(first, second))
            SecureStorage.saveActiveProfileId(context, first.id)
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                val loaded = MainActivity::class.java.getDeclaredField("profilesLoaded").apply { isAccessible = true }
                val deadline = android.os.SystemClock.elapsedRealtime() + 5_000
                var ready = false
                while (!ready && android.os.SystemClock.elapsedRealtime() < deadline) {
                    scenario.onActivity { ready = loaded.getBoolean(it) }
                    if (!ready) android.os.SystemClock.sleep(20)
                }
                assertTrue(ready)
                scenario.onActivity { activity ->
                    MainActivity::class.java.getDeclaredMethod("updateUI", Boolean::class.javaPrimitiveType, String::class.java, Boolean::class.javaPrimitiveType)
                        .apply { isAccessible = true }.invoke(activity, true, activity.getString(R.string.ui_vpn_connected), false)
                    val list = activity.findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.profileList)
                    val adapter = list.adapter as ProfilesAdapter
                    assertFalse(adapter.editingEnabled)
                    val holder = adapter.createViewHolder(list, 0)
                    adapter.bindViewHolder(holder, 1)
                    holder.itemView.performClick()
                    assertEquals(first.id, SecureStorage.loadActiveProfileId(activity))
                    assertFalse(activity.findViewById<View>(R.id.btnAddProfile).isEnabled)
                }
            }
        } finally {
            SecureStorage.saveProfiles(context, original)
            if (activeId != null) SecureStorage.saveActiveProfileId(context, activeId)
            else SecureStorage.remove(context, "active_profile_id")
        }
    }

    @Test
    fun selectedSectionSurvivesRecreation() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val navigationId = activity.resources.getIdentifier("mainNavigation", "id", activity.packageName)
                assertNotEquals("Главные разделы должны быть постоянно доступны", 0, navigationId)
                val profilesId = activity.resources.getIdentifier("nav_profiles", "id", activity.packageName)
                activity.findViewById<NavigationBarView>(navigationId).selectedItemId = profilesId
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                val navigationId = activity.resources.getIdentifier("mainNavigation", "id", activity.packageName)
                val profilesId = activity.resources.getIdentifier("nav_profiles", "id", activity.packageName)
                assertEquals(profilesId, activity.findViewById<NavigationBarView>(navigationId).selectedItemId)
                assertTrue(activity.findViewById<View>(activity.resources.getIdentifier("profilesPage", "id", activity.packageName)).isShown)
            }
        }
    }

    @Test
    fun homeDoesNotExposeConnectionKey() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val inputId = activity.resources.getIdentifier("editConnectionKey", "id", activity.packageName)
                val input = if (inputId == 0) null else activity.findViewById<EditText>(inputId)
                assertTrue("На главном экране не должно быть открытого ключа", input == null || !input.isShown)
            }
        }
    }

    @Test
    fun invalidKeyKeepsProfileEditorOpen() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val loaded = MainActivity::class.java.getDeclaredField("profilesLoaded").apply { isAccessible = true }
            val deadline = android.os.SystemClock.elapsedRealtime() + 5_000
            var ready = false
            while (!ready && android.os.SystemClock.elapsedRealtime() < deadline) {
                scenario.onActivity { ready = loaded.getBoolean(it) }
                if (!ready) android.os.SystemClock.sleep(20)
            }
            assertTrue("Хранилище профилей должно загрузиться", ready)
            scenario.onActivity { activity ->
                val showEditor = MainActivity::class.java.getDeclaredMethod("showProfileDialog", SecureStorage.ConnectionProfile::class.java)
                showEditor.isAccessible = true
                showEditor.invoke(activity, null)
            }
            instrumentation.waitForIdleSync()
            instrumentation.runOnMainSync {
                val context = instrumentation.targetContext
                val keyId = context.resources.getIdentifier("profileKeyInput", "id", context.packageName)
                val nameId = context.resources.getIdentifier("profileNameInput", "id", context.packageName)
                assertNotEquals("Редактор должен содержать доступное поле ключа", 0, keyId)
                val window = android.view.inspector.WindowInspector.getGlobalWindowViews().last()
                window.findViewById<EditText>(nameId).setText("Проверка формы")
                window.findViewById<EditText>(keyId).setText("invalid-connection-key")
                window.findViewById<View>(android.R.id.button1).performClick()
                assertTrue("Неверный ключ не должен закрывать редактор", window.findViewById<View>(keyId).isShown)
            }
        }
    }
}
