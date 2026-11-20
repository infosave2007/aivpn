package com.aivpn.client

import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.materialswitch.MaterialSwitch
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SplitTunnelSwitchTest {
    @Test
    fun offRetainsListsAcrossEditsAndActivityRestart() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val apps = SecureStorage.loadAllowedApps(context)
        val domains = SecureStorage.loadExcludedDomains(context)
        val raw = SecureStorage.loadString(context, "split_tunnel_enabled")
        try {
            SecureStorage.saveAllowedApps(context, emptySet())
            SecureStorage.saveExcludedDomains(context, emptyList())
            SecureStorage.saveString(context, "split_tunnel_enabled", "")
            assertFalse(SecureStorage.loadSplitEnabled(context))
            val selected = setOf("com.android.chrome")
            val sites = listOf("example.net")
            SecureStorage.saveAllowedApps(context, selected)
            SecureStorage.saveExcludedDomains(context, sites)
            assertFalse(SecureStorage.loadSplitEnabled(context))
            ActivityScenario.launch(SplitTunnelActivity::class.java).use { scenario ->
                var ready = false
                val until = SystemClock.elapsedRealtime() + 8000
                while (!ready && SystemClock.elapsedRealtime() < until) {
                    scenario.onActivity { ready = it.findViewById<MaterialSwitch>(R.id.switchSplitEnabled).isEnabled }
                    if (!ready) SystemClock.sleep(25)
                }
                assertTrue(ready)
                scenario.onActivity {
                    val toggle = it.findViewById<MaterialSwitch>(R.id.switchSplitEnabled)
                    assertFalse(toggle.isChecked)
                    toggle.performClick()
                }
                val savedUntil = SystemClock.elapsedRealtime() + 3000
                while (!SecureStorage.loadSplitEnabled(context) && SystemClock.elapsedRealtime() < savedUntil) SystemClock.sleep(25)
                assertTrue(SecureStorage.loadSplitEnabled(context))
                scenario.recreate()
            }
            SecureStorage.saveSplitEnabled(context, false)
            assertFalse(SecureStorage.loadSplitEnabled(context))
            assertEquals(selected, SecureStorage.loadAllowedApps(context))
            assertEquals(sites, SecureStorage.loadExcludedDomains(context))
            SecureStorage.saveString(context, "split_tunnel_enabled", "")
            assertTrue(SecureStorage.loadSplitEnabled(context))
        } finally {
            SecureStorage.saveAllowedApps(context, apps)
            SecureStorage.saveExcludedDomains(context, domains)
            SecureStorage.saveString(context, "split_tunnel_enabled", raw)
        }
    }
}
