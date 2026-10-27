package com.aivpn.client

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelMtuTest {
    @Test
    fun carrierBudgetAndIpv6MinimumApplyToExplicitSettings() {
        assertEquals(1500, TunnelMtu.effective(1500, false, false))
        assertEquals(1346, TunnelMtu.effective(1346, false, false))
        assertEquals(1280, TunnelMtu.effective(1280, false, false))
        assertEquals(1200, TunnelMtu.effective(1200, false, false))
        assertEquals(1200, TunnelMtu.effective(1500, true, false))
        assertEquals(1280, TunnelMtu.effective(1500, true, true))
        assertEquals(576, TunnelMtu.effective(400, false, false))
    }
}
