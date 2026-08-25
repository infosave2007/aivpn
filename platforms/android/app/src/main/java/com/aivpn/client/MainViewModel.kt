package com.aivpn.client

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.MutableLiveData

enum class ConnectionState { DISCONNECTED, CONNECTING, CONNECTED }

data class TrafficStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val quality: Int,
)

/**
 * ViewModel for MainActivity. Holds UI state that must survive configuration changes
 * (screen rotation). Does NOT hold Activity context or service bindings.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    val connectionState   = MutableLiveData(ConnectionState.DISCONNECTED)
    val trafficStats      = MutableLiveData(TrafficStats(0L, 0L, 0))
    val profiles          = MutableLiveData<List<SecureStorage.ConnectionProfile>>(emptyList())
    val activeProfileId   = MutableLiveData<String?>(null)
    val connectionStartTime = MutableLiveData(0L)
    val adaptiveLevel     = MutableLiveData(0)
    val errorMessage      = MutableLiveData<String?>(null)
    val statusText        = MutableLiveData("")

    fun loadProfiles(context: android.content.Context) {
        val list = SecureStorage.loadProfiles(context)
        profiles.value = list
        val savedActiveId = SecureStorage.loadActiveProfileId(context)
        activeProfileId.value = when {
            list.any { it.id == savedActiveId } -> savedActiveId
            list.isNotEmpty()                   -> list[0].id
            else                                -> null
        }
    }

    fun loadAdaptiveLevel(context: android.content.Context) {
        val level = context.getSharedPreferences(PrefsKeys.PREFS_NAME, android.content.Context.MODE_PRIVATE)
            .getInt(PrefsKeys.ADAPTIVE_LEVEL, 0)
        adaptiveLevel.value = level
    }

    fun saveAdaptiveLevel(context: android.content.Context, level: Int) {
        context.getSharedPreferences(PrefsKeys.PREFS_NAME, android.content.Context.MODE_PRIVATE)
            .edit().putInt(PrefsKeys.ADAPTIVE_LEVEL, level).apply()
        adaptiveLevel.value = level
    }

    /**
     * [startTime] comes from AivpnService.connectedAtMillis — the service-side
     * per-session stamp. The ViewModel only mirrors it for LiveData observers;
     * it no longer invents its own timestamp (an Activity-scoped stamp reset
     * the timer to "now" whenever the Activity was recreated over a live
     * tunnel, and went stale across silent reconnects).
     */
    fun setConnected(statusMsg: String, startTime: Long) {
        connectionState.value = ConnectionState.CONNECTED
        statusText.value = statusMsg
        connectionStartTime.value = startTime
    }

    fun setConnecting(statusMsg: String) {
        connectionState.value = ConnectionState.CONNECTING
        statusText.value = statusMsg
    }

    fun setDisconnected(statusMsg: String) {
        connectionState.value = ConnectionState.DISCONNECTED
        statusText.value = statusMsg
        connectionStartTime.value = 0L
    }

    fun updateTraffic(sent: Long, received: Long, quality: Int) {
        trafficStats.value = TrafficStats(sent, received, quality)
    }

    /**
     * Seed for mutating operations: the in-memory LiveData list when it has been
     * populated, otherwise the persisted list from SecureStorage. Guards against a
     * caller mutating "profiles" before [loadProfiles] ran — with a bare
     * `profiles.value` an add-then-save would overwrite the entire stored profile
     * list with just the new entry, silently destroying every existing key.
     */
    private fun currentOrStoredProfiles(
        context: android.content.Context,
    ): MutableList<SecureStorage.ConnectionProfile> =
        profiles.value?.takeIf { it.isNotEmpty() }?.toMutableList()
            ?: SecureStorage.loadProfiles(context).toMutableList()

    /** Add or update a profile. Returns the profile that was saved. */
    fun saveProfile(
        context: android.content.Context,
        existing: SecureStorage.ConnectionProfile?,
        name: String,
        key: String,
        mtlsCert: String?,
    ): SecureStorage.ConnectionProfile {
        val current = currentOrStoredProfiles(context)
        val saved: SecureStorage.ConnectionProfile
        if (existing != null) {
            val idx = current.indexOfFirst { it.id == existing.id }
            saved = existing.copy(name = name, key = key, mtlsCertBase64 = mtlsCert)
            if (idx >= 0) current[idx] = saved else current.add(saved)
        } else {
            saved = SecureStorage.ConnectionProfile(
                id = java.util.UUID.randomUUID().toString(),
                name = name,
                key = key,
                mtlsCertBase64 = mtlsCert,
            )
            current.add(saved)
            activeProfileId.value = saved.id
            SecureStorage.saveActiveProfileId(context, saved.id)
        }
        SecureStorage.saveProfiles(context, current)
        profiles.value = current
        return saved
    }

    fun deleteProfile(context: android.content.Context, profile: SecureStorage.ConnectionProfile) {
        val current = currentOrStoredProfiles(context)
        current.removeAll { it.id == profile.id }
        if (activeProfileId.value == profile.id) {
            val next = current.firstOrNull()?.id
            activeProfileId.value = next
            if (next != null) SecureStorage.saveActiveProfileId(context, next)
        }
        SecureStorage.saveProfiles(context, current)
        profiles.value = current
    }

    fun selectProfile(context: android.content.Context, profile: SecureStorage.ConnectionProfile) {
        activeProfileId.value = profile.id
        SecureStorage.saveActiveProfileId(context, profile.id)
    }

    /** Ensure a profile exists for the given key. Returns the matching profile's id. */
    fun ensureProfile(
        context: android.content.Context,
        connectionKey: String,
        defaultName: String,
    ): String {
        val current = currentOrStoredProfiles(context)
        val existing = current.find { it.key == connectionKey }
        if (existing != null) {
            if (activeProfileId.value != existing.id) {
                activeProfileId.value = existing.id
                SecureStorage.saveActiveProfileId(context, existing.id)
            }
            return existing.id
        }
        val profile = SecureStorage.ConnectionProfile(
            id = java.util.UUID.randomUUID().toString(),
            name = defaultName,
            key = connectionKey,
        )
        current.add(profile)
        activeProfileId.value = profile.id
        SecureStorage.saveProfiles(context, current)
        SecureStorage.saveActiveProfileId(context, profile.id)
        profiles.value = current
        return profile.id
    }
}
