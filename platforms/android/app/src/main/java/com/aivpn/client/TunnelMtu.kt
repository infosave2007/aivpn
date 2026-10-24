package com.aivpn.client

/** Крупные IP-пакеты делятся общим ядром; IPv6 требует минимум 1280 байт. */
internal object TunnelMtu {
    const val DEFAULT = 1280
    const val MAXIMUM = 1500

    fun effective(requested: Int, adaptive: Boolean, ipv6: Boolean): Int {
        val desired = if (adaptive) minOf(requested, 1200) else requested
        return desired.coerceIn(if (ipv6) 1280 else 576, MAXIMUM)
    }
}
