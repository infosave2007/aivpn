package com.aivpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.*
import org.json.JSONObject
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Android VPN service — thin orchestrator over the Rust core (libaivpn_core.so).
 *
 * Responsibilities that must stay in Kotlin (Android API only):
 *   - VpnService.Builder / TUN interface establishment
 *   - NetworkCallback for network-change detection
 *   - VpnService.protect() — called from inside Rust via JNI on this instance
 *   - Foreground notification lifecycle
 *
 * Everything else (crypto, handshake, keepalive, anti-replay, rekey) is in Rust.
 */
class AivpnService : VpnService() {

    /**
     * Tri-state UI truth (see [uiState]) — declared at class level so callers can
     * reference it as `AivpnService.UiState`.
     */
    enum class UiState { DISCONNECTED, CONNECTING, CONNECTED }

    companion object {
        const val ACTION_CONNECT    = "com.aivpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aivpn.DISCONNECT"
        private const val CHANNEL_ID        = "aivpn_vpn"
        /** Separate high-importance channel for connect/disconnect user-facing events. */
        private const val CHANNEL_EVENTS_ID = "aivpn_events"
        /** HIGH-importance channel for security alerts (unexpected VPN death). */
        private const val CHANNEL_ALERTS_ID = "aivpn_alerts"
        private const val NOTIFICATION_ID       = 1
        private const val NOTIFICATION_EVENT_ID = 2
        private const val NOTIFICATION_ALERT_ID = 3
        // Match the desktop client's WAN-safe TUN MTU so encrypted outer UDP
        // datagrams stay below the path-MTU ceiling on real networks.
        private const val DEFAULT_TUN_MTU = 1346
        private const val ADAPTIVE_TUN_MTU = 1200
        private const val LEGACY_PREFIX_LEN = 24
        private const val INITIAL_RETRY_DELAY_MS = 500L
        private const val MAX_RETRY_DELAY_MS     = 8_000L
        // A session must have stayed up at least this long to count as
        // "genuinely established" for backoff purposes (mirrors desktop
        // main.rs should_reset_backoff / HEALTHY_CONNECTION_THRESHOLD).
        // Higher than desktop's 30 s because the Rust DATA-watchdog fires
        // ~25-40 s after connect against a server whose data downlink is
        // durably dead while keepalive-acks still flow: with the old
        // sessionEstablished-only check every such fire reconnected with
        // ZERO delay and reset the backoff, looping every ~20-30 s forever
        // (battery drain). 60 s comfortably exceeds the watchdog fire
        // horizon, so repeated fires keep escalating retryDelayMs while a
        // single fire after a long healthy session still reconnects
        // instantly.
        private const val HEALTHY_SESSION_MS = 60_000L
        // §2 crowdsourced blocking feedback — cap on persisted unreported outcome
        // entries, mirroring desktop's `MaskFeedbackLog::MAX_ENTRIES`.
        private const val FEEDBACK_OUTCOMES_MAX_ENTRIES = 128
        // Upper bounds on server-pushed `FeedbackConfig` tuning, mirroring
        // desktop's `MAX_REPORT_INTERVAL_SECS` / `MAX_FAILURE_THRESHOLD`
        // (`mask_feedback_log.rs`). A malicious or misconfigured server could
        // otherwise push a pathologically large interval or threshold; clamp
        // both so the feature stays meaningfully bounded.
        private const val FEEDBACK_MAX_INTERVAL_SECS = 7L * 24L * 3600L
        private const val FEEDBACK_MAX_FAILURE_THRESHOLD = 10
        // Android reshuffles underlying network IDs for 5-10s after VPN comes up.
        // 15s covers even slow devices without delaying genuine network-switch detection.
        private const val TAG = "AivpnService"

        @Volatile var statusCallback:  ((Boolean, String) -> Unit)? = null
        @Volatile var trafficCallback: ((Long, Long) -> Unit)?      = null
        @Volatile var tileCallback:    (() -> Unit)?                = null
        /** JSON blob from AivpnJni.getRecordingFeedback(), forwarded as-is; see that method's kdoc for shapes. */
        @Volatile var recordingCallback: ((String) -> Unit)?        = null
        @Volatile var isRunning     = false
        @Volatile var isServiceActive = false
        @Volatile var lastStatusText = ""

        /**
         * Tri-state UI truth, maintained alongside [lastStatusText] on every
         * transition. MainActivity's onCreate/onResume resync renders from this
         * single source instead of inferring state from [isRunning] /
         * [isServiceActive] (whose two-branch check had no terminal else — a
         * service that died while the Activity was paused left the UI frozen
         * at "Connected" with a running timer).
         */
        @Volatile var uiState: UiState = UiState.DISCONNECTED

        /**
         * True only between [onTunnelReady] (handshake + ratchet complete) and the
         * end of that session. Unlike [isRunning] — which merely means "a JNI
         * runTunnel call is in flight" and is true during connect/retry attempts —
         * this is the ground truth for "connected" (tile ACTIVE state).
         */
        @Volatile var isEstablished = false

        /** Weak reference to the live service instance, used for socket protection only. */
        @Volatile var instance: AivpnService? = null
    }

    // TUN interface wrapper kept open across reconnects so Android does not tear down
    // the device-level VPN interface between Rust tunnel restarts.
    private var vpnInterface: ParcelFileDescriptor? = null
    /** MTU the current [vpnInterface] was built with; 0 when no interface exists. */
    @Volatile private var currentTunMtu: Int = 0
    // Address the live TUN was established with; a pool re-home changes the
    // desired address and forces ensureVpnInterface() to rebuild (see there).
    @Volatile private var currentTunAddress: String? = null

    // Coroutine lifecycle
    @Volatile private var serviceJob: Job? = null
    private var restartJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val serviceLifecycleMutex = Mutex()
    @Volatile private var manualDisconnect = false

    // Saved params for reconnect
    @Volatile private var savedServerAddr: String? = null
    @Volatile private var savedServerKey: String?  = null
    @Volatile private var savedPsk: String?        = null
    @Volatile private var savedServerSigningKey: String? = null
    @Volatile private var savedMtlsCert: ByteArray? = null
    @Volatile private var savedVpnIp: String?      = null
    @Volatile private var savedServerVpnIp: String? = null
    @Volatile private var savedVpnPrefixLen: Int = LEGACY_PREFIX_LEN
    @Volatile private var savedVpnMtu: Int = DEFAULT_TUN_MTU
    @Volatile private var savedDnsServers: List<String> = emptyList()
    /** Preferred mask profile name, null/"auto" = server chooses. Forwarded to JNI as maskProfile. */
    @Volatile private var savedMaskProfile: String? = null

    // Whether the current session reached the running state
    @Volatile private var sessionEstablished = false

    // Monotonically-increasing session counter.  Incremented on every new tunnel session.
    // Captured in upgradePendingJob at trigger time so a stale job can't kill a newer session.
    @Volatile private var sessionId: Long = 0L

    // Network change detection
    @Volatile private var networkTrigger: Boolean   = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentUnderlyingNetwork: Network? = null
    @Volatile private var lastNetworkEventAtMs: Long = 0L
    private val NETWORK_EVENT_DEBOUNCE_MS = 1_000L
    // Android reshuffles underlying network IDs when VPN comes up; ignore churn for this window.
    @Volatile private var postConnectUntilMs: Long = 0L
    private val POST_CONNECT_COOLDOWN_MS = 15_000L

    private val mainHandler = Handler(Looper.getMainLooper())

    private fun postStatusCallback(connected: Boolean, text: String) {
        val cb = statusCallback ?: return
        mainHandler.post { cb.invoke(connected, text) }
    }

    // ──────────── Service lifecycle ────────────

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // The service is started via startForegroundService() (MainActivity, BootReceiver,
        // TileService). Android kills the whole app with
        // ForegroundServiceDidNotStartInTimeException if onStartCommand returns without a
        // startForeground() call, so promote to foreground FIRST — before ANY early-return
        // path. Every abort path below must then call stopSelfCleanly(startId), which
        // removes the placeholder notification and stops this start request.
        createNotificationChannel()
        try {
            val placeholder =
                if (isRunning && lastStatusText.isNotEmpty()) lastStatusText
                else getString(R.string.notification_connecting)
            startForegroundCompat(placeholder)
        } catch (e: Exception) {
            // e.g. ForegroundServiceStartNotAllowedException (API 31+ background start).
            // Proceed — the connect path re-attempts startForeground from the restart job.
            Log.w(TAG, "Early startForeground failed: ${e.message}")
        }
        when (intent?.action) {
            ACTION_CONNECT -> {
                // If the VPN permission was revoked since it was last granted (another
                // VPN app took over, user toggled it off in Settings), establish() would
                // return null / throw SecurityException forever — an infinite retry loop.
                // Bail out with a clear status instead; consent can only be re-granted
                // from an Activity.
                if (prepare(this) != null) {
                    Log.w(TAG, "ACTION_CONNECT but VPN permission not granted/revoked — stopping")
                    lastStatusText = getString(R.string.error_vpn_denied)
                    uiState = UiState.DISCONNECTED
                    postStatusCallback(false, lastStatusText)
                    stopSelfCleanly(startId)
                    return START_NOT_STICKY
                }
                // Read only the profile ID from the Intent.  The actual server key
                // and PSK are loaded from EncryptedSharedPreferences inside the
                // service so they never travel through IPC as plaintext extras.
                val profileId = intent.getStringExtra("profile_id")
                if (profileId == null) {
                    Log.w(TAG, "ACTION_CONNECT without profile_id — stopping")
                    stopSelfCleanly(startId)
                    return START_NOT_STICKY
                }
                loadAndStartVpnFromProfile(profileId, startId)
            }
            ACTION_DISCONNECT -> stopVpn(startId)
            else -> {
                // Two system-initiated start paths land here:
                //   1. Always-on VPN: the OS starts the service with
                //      action == SERVICE_INTERFACE ("android.net.VpnService") and no extras.
                //   2. START_STICKY restart with null intent — OS restarted us after a kill.
                // In both cases the SYSTEM wants the VPN up, so restore the last used
                // profile instead of stopping. An unconditional stopSelf() here left
                // always-on (and especially lockdown/"block connections without VPN")
                // users with a dead VPN — and under lockdown with NO network at all.
                val systemRequestedVpn = intent == null || intent.action == SERVICE_INTERFACE
                if (systemRequestedVpn && !isServiceActive) {
                    val profileId = lastKnownProfileId()
                    if (profileId != null && prepare(this) == null) {
                        Log.i(TAG, "System-initiated start (always-on/restart): restoring profile $profileId")
                        loadAndStartVpnFromProfile(profileId, startId)
                    } else {
                        // No saved profile, or the VPN permission was revoked — we cannot
                        // show the consent dialog from a service, so stop cleanly.
                        Log.w(TAG, "System-initiated start but no saved profile or no VPN permission — stopping")
                        stopSelfCleanly(startId)
                    }
                } else if (!isServiceActive) {
                    // Unknown explicit action while idle — avoid a zombie foreground
                    // service with no tunnel.
                    stopSelfCleanly(startId)
                }
            }
        }
        return START_STICKY
    }

    /** startForeground with the API-34+ foregroundServiceType overload where required. */
    private fun startForegroundCompat(text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID, buildNotification(text),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification(text))
        }
    }

    /**
     * Aborts a start request that will not produce a tunnel: demotes from foreground
     * (removing the placeholder notification posted at the top of [onStartCommand])
     * and stops this start ID. Using stopSelf(startId) keeps the service alive if a
     * newer start Intent has already been queued.
     */
    private fun stopSelfCleanly(startId: Int) {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    /**
     * Resolves the profile to restore for a system-initiated start (always-on VPN,
     * START_STICKY restart). Mirrors [BootReceiver]'s lookup order: the securely
     * stored active-profile ID first, then the device-protected-prefs copy of the
     * last connected ID, then the first stored profile. Candidate IDs are validated
     * against the actual profile list so a stale ID (profile deleted since the last
     * connect) cannot restore the wrong profile.
     */
    private fun lastKnownProfileId(): String? {
        val lastId = BootPrefs.prefs(this)
            .getString(PrefsKeys.PREF_LAST_PROFILE_ID, null)
            ?.takeIf { it.isNotBlank() }
        val profiles = try {
            SecureStorage.loadProfiles(this)
        } catch (e: Exception) {
            // EncryptedSharedPreferences unavailable (Direct Boot / Keystore issue) —
            // cannot validate; hand over the unverified ID (may be null).
            Log.w(TAG, "Secure storage unavailable while resolving last profile: ${e.message}")
            return lastId
        }
        val activeId = try {
            SecureStorage.loadActiveProfileId(this).takeIf { it.isNotBlank() }
        } catch (e: Exception) { null }
        return when {
            activeId != null && profiles.any { it.id == activeId } -> activeId
            lastId != null && profiles.any { it.id == lastId }     -> lastId
            else                                                    -> profiles.firstOrNull()?.id
        }
    }

    private fun startVpn(
        serverAddr: String,
        serverKeyBase64: String,
        pskBase64: String? = null,
        vpnIp: String? = null,
        serverVpnIp: String? = null,
        vpnPrefixLen: Int = LEGACY_PREFIX_LEN,
        vpnMtu: Int = DEFAULT_TUN_MTU,
        mtlsCert: ByteArray? = null,
        dnsServers: List<String> = emptyList(),
        preferredMask: String? = null,
        serverSigningKeyBase64: String? = null,
    ) {
        Log.d(TAG, "startVpn: server=$serverAddr mask=${preferredMask ?: "auto"}")

        // Native library failed to load (missing/corrupt libaivpn_core.so). Every
        // tunnel path below touches AivpnJni external functions, which would throw
        // UnsatisfiedLinkError (an Error, uncatchable by catch(Exception)) and crash
        // the app on the first Connect. Surface a clear status instead.
        if (!AivpnJni.isAvailable) {
            Log.e(TAG, "Cannot start VPN — native library unavailable: ${AivpnJni.loadError}")
            isServiceActive = false
            isRunning = false
            isEstablished = false
            lastStatusText = getString(R.string.status_native_lib_unavailable)
            uiState = UiState.DISCONNECTED
            postStatusCallback(false, lastStatusText)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val normalizedPrefixLen = vpnPrefixLen.coerceIn(1, 30)
        val normalizedMtu = vpnMtu.coerceIn(576, 1500)
        // Same normalization applied when storing savedMaskProfile below, so the
        // duplicate-CONNECT guard compares like with like.
        val normalizedMask = preferredMask?.takeIf { it.isNotBlank() && it != "auto" }

        val sameTarget =
            savedServerAddr == serverAddr &&
            savedServerKey == serverKeyBase64 &&
            savedPsk == pskBase64 &&
            savedVpnIp == vpnIp &&
            savedServerVpnIp == serverVpnIp &&
            savedVpnPrefixLen == normalizedPrefixLen &&
            savedVpnMtu == normalizedMtu &&
            savedDnsServers == dnsServers &&
            savedMaskProfile == normalizedMask &&
            savedServerSigningKey == serverSigningKeyBase64 &&
            (savedMtlsCert == null && mtlsCert == null ||
             savedMtlsCert != null && mtlsCert != null && savedMtlsCert.contentEquals(mtlsCert))
        val startupInFlight = restartJob?.isActive == true
        val tunnelLoopActive = serviceJob?.isActive == true
        // Allow reconnect after manual disconnect even if the old Rust call is still unwinding.
        // The restartJob uses withTimeoutOrNull(3s)+cancelAndJoin to wait for the old session.
        if (sameTarget && (startupInFlight || tunnelLoopActive) && !manualDisconnect) {
            Log.d(TAG, "Ignoring duplicate CONNECT while startup/session is already in progress")
            return
        }

        savedServerAddr  = serverAddr
        savedServerKey   = serverKeyBase64
        savedPsk         = pskBase64
        savedServerSigningKey = serverSigningKeyBase64
        savedMtlsCert    = mtlsCert
        // Prefer a server-assigned VPN IP remembered from an earlier session on
        // this server (pool re-home): the key still embeds the stale colliding
        // IP, so starting the TUN with it would earn an immediate anti-spoof
        // drop until the poll loop re-adopts the override. Start correct instead.
        savedVpnIp       = getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getString(PrefsKeys.PREF_VPN_IP_OVERRIDE + serverAddr, null) ?: vpnIp
        savedServerVpnIp = serverVpnIp
        savedVpnPrefixLen = normalizedPrefixLen
        savedVpnMtu = normalizedMtu
        savedDnsServers = dnsServers
        savedMaskProfile = normalizedMask
        manualDisconnect = false
        isServiceActive = true
        uiState = UiState.CONNECTING
        // A new connection attempt is starting: clear the stale "Отключено" event
        // row (ID 2) from a previous disconnect so it can't linger beside the live
        // foreground notification. Nothing else ever cancels it.
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_EVENT_ID)
        // Persist user intent: the VPN is wanted from now until an explicit manual
        // disconnect. onDestroy + VpnReconnectWorker use this to self-heal after a
        // system-initiated service stop.
        BootPrefs.prefs(this).edit().putBoolean(PrefsKeys.PREF_VPN_DESIRED, true).apply()

        restartJob?.cancel()
        restartJob = serviceScope.launch {
            serviceLifecycleMutex.withLock {
                AivpnJni.stopTunnel()
                // Increment before cancelAndJoin so that the old job's finally{}
                // sees sessionId != mySessionId and does NOT call stopSelf().
                val capturedSessionId = ++sessionId
                // AivpnJni.runTunnel() is a blocking native call — Kotlin coroutine
                // cancellation cannot interrupt it.  Give it 3 s to exit after
                // stopTunnel() fired the eventfd; proceed regardless so the mutex is
                // never held indefinitely.
                withTimeoutOrNull(3_000L) { serviceJob?.cancelAndJoin() }
                serviceJob = null
                // If a manual disconnect arrived during the cancelAndJoin window, abort
                // the restart so we don't launch a new session that immediately hangs
                // for TX_WITHOUT_RX_TIMEOUT (~20 s) before the watchdog kills it.
                if (manualDisconnect) {
                    AivpnJni.clearPendingStop()
                    closeTunnel()
                    return@withLock
                }
                // Clear any STOP_PENDING flag that stopTunnel() set while no session
                // was active (race window between old session exit and new activation).
                // We are about to start an intentional new connection.
                AivpnJni.clearPendingStop()
                closeTunnel()

                createNotificationChannel()
                // Disconnect may have raced in while this job waited on the mutex /
                // cancelAndJoin: re-promoting to foreground after stopVpn() already ran
                // stopForeground() would leave a zombie "Connecting…" notification with
                // no session behind it.
                if (manualDisconnect || !isServiceActive) {
                    return@withLock
                }
                try {
                    startForegroundCompat(getString(R.string.notification_connecting))
                } catch (e: Exception) {
                    // ForegroundServiceStartNotAllowedException or similar — without a
                    // foreground promotion the session would be killed shortly anyway.
                    Log.e(TAG, "startForeground failed in restart job: ${e.message}", e)
                    isServiceActive = false
                    // LOW-4: route this terminal stop through the same UI/tile refresh
                    // as every other stop path so MainActivity leaves "Connecting…" and
                    // the QS tile leaves UNAVAILABLE immediately (instead of waiting for
                    // the next onResume resync). No security alert: no session was ever
                    // up, so traffic was never (falsely) reported as "unprotected".
                    isRunning = false
                    isEstablished = false
                    lastStatusText = getString(R.string.status_disconnected)
                    uiState = UiState.DISCONNECTED
                    postStatusCallback(false, lastStatusText)
                    fireTileCallback()
                    stopSelf()
                    return@withLock
                }

                unregisterNetworkCallback()
                registerNetworkCallback()

                // Second manualDisconnect guard: closes the race window between
                // the first check (above) and the launch below.  If stopVpn()
                // fires after clearPendingStop() but before this launch, the
                // STOP_PENDING flag is already cleared and serviceJob is still
                // null (so stopVpn's cancel() was a no-op).  Without this check
                // the new session starts with no stop signal and runs until the
                // TX_WITHOUT_RX watchdog (~20 s), making the disconnect button
                // appear broken on the 2nd connection.
                if (manualDisconnect) {
                    return@withLock
                }
                serviceJob = serviceScope.launch {
            val mySessionId = capturedSessionId
            var retryDelayMs = INITIAL_RETRY_DELAY_MS
            var tunnelStartMs = System.currentTimeMillis()
            try {
                while (isActive && !manualDisconnect) {
                    try {
                        sessionEstablished = false
                        isEstablished = false
                        networkTrigger = false
                        // A NetworkCallback stopTunnel() that lands during the retry-
                        // delay window (no active native session) leaves a stale
                        // STOP_PENDING flag the next attempt would consume and insta-
                        // exit on. An intentional new attempt never honors a stale stop.
                        AivpnJni.clearPendingStop()
                        tunnelStartMs = System.currentTimeMillis()
                        runTunnel()
                        // runTunnel() returns normally on Rust rekey/network trigger — reconnect fast.
                        // Keep the TUN open on a plain rekey return (no routing gap, fd reuse), BUT
                        // rebuild it on a network-trigger return: a Wi-Fi→cellular switch leaves the
                        // reused interface tunnelling app packets with the device's real source
                        // address, which the server drops as anti-spoof (TX up, RX 0). Rebuilding
                        // re-binds the TUN to the VPN IP — the same reason a manual reconnect works.
                        if (networkTrigger) {
                            closeTunnel()
                        }
                        //
                        // Guard: if the tunnel exited normally in under 2 s without ever establishing
                        // a session (e.g. Rust returns "" immediately on a transient error), apply
                        // backoff to avoid a busy reconnect loop that drains the battery.
                        val tunnelLifeMs = System.currentTimeMillis() - tunnelStartMs
                        if (tunnelLifeMs < 2_000L && !sessionEstablished && !networkTrigger) {
                            lastStatusText = getString(R.string.status_reconnecting)
                            uiState = UiState.CONNECTING
                            postStatusCallback(false, lastStatusText)
                            fireTileCallback()
                            updateNotification(getString(R.string.notification_connecting))
                            retryDelayMs = (retryDelayMs * 2).coerceAtMost(MAX_RETRY_DELAY_MS)
                            delay(retryDelayMs)
                        } else {
                            retryDelayMs = INITIAL_RETRY_DELAY_MS
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: FatalConfigException) {
                        // Permanently-invalid config — retrying cannot succeed.
                        // Record the reason and break; the finally block below posts
                        // the full terminal-stop signal (status + tile + alert) and
                        // demotes from foreground / stops the service.
                        Log.e(TAG, "Fatal config error — not retrying: ${e.message}")
                        isRunning = false
                        lastStatusText = e.message ?: getString(R.string.status_disconnected)
                        break
                    } catch (e: Exception) {
                        Log.e(TAG, "Tunnel error: ${e.message}", e)
                        isRunning = false
                        isEstablished = false
                        if (manualDisconnect) break
                        // Rebuild the TUN on an error-triggered reconnect instead of
                        // reusing it. A reused interface that survives an underlying
                        // network change (Wi-Fi→cellular) keeps tunnelling app packets
                        // with the device's REAL source address (e.g. a carrier-CGNAT
                        // 10.x) instead of the VPN IP — the server then drops every
                        // uplink packet as anti-spoof ("dropping packet src=… from
                        // session owning vpn_ip=…"), so TX flows but RX stays 0. A
                        // manual disconnect+reconnect worked precisely because it
                        // rebuilds the interface; do the same here. Inline rekeys never
                        // reach this catch (they stay in-session), so this does not add
                        // a routing gap to the steady-state 120 s key rotation. The
                        // kill switch keeps traffic blocked during the brief rebuild.
                        closeTunnel()

                        // Network-triggered reconnects and reconnects after a genuinely
                        // healthy established session use zero delay so the switch feels
                        // instant. "Established" alone is NOT enough: a DATA-watchdog
                        // fire against a durably half-broken server (downlink data dead,
                        // keepalives flowing) exits with sessionEstablished==true every
                        // ~25-40 s — treating that as healthy meant an indefinite
                        // zero-backoff reconnect loop. Only a session that also stayed
                        // up past HEALTHY_SESSION_MS resets the backoff (mirrors desktop
                        // main.rs should_reset_backoff).
                        val tunnelLifeMs = System.currentTimeMillis() - tunnelStartMs
                        val healthySession = sessionEstablished && tunnelLifeMs >= HEALTHY_SESSION_MS
                        val delayMs = when {
                            networkTrigger -> 0L
                            healthySession -> 0L
                            else           -> retryDelayMs
                        }

                        lastStatusText = getString(R.string.status_reconnecting)
                        uiState = UiState.CONNECTING
                        postStatusCallback(false, lastStatusText)
                        fireTileCallback()
                        updateNotification(getString(R.string.notification_connecting))

                        if (delayMs > 0) {
                            Log.d(TAG, "Reconnecting in ${delayMs}ms")
                            delay(delayMs)
                        } else {
                            Log.d(TAG, "Reconnecting immediately (network=${networkTrigger}, healthy=${healthySession})")
                        }

                        if (!networkTrigger && !healthySession) {
                            retryDelayMs = (retryDelayMs * 2).coerceAtMost(MAX_RETRY_DELAY_MS)
                        } else {
                            retryDelayMs = INITIAL_RETRY_DELAY_MS
                        }
                    }
                }
            } catch (e: CancellationException) {
                Log.d(TAG, "Service job cancelled")
            } finally {
                // Only update shared service state if this session is still the active one.
                // A superseded session (cancelAndJoin timeout) must not clobber serviceJob,
                // isRunning, or isServiceActive that the new session has already set up.
                if (mySessionId == sessionId) {
                    isRunning = false
                    isEstablished = false
                    serviceJob = null
                    if (!manualDisconnect) {
                        isServiceActive = false
                        // Non-manual terminal exit (today: fatal config). This used
                        // to be silent — no status post, no tile refresh, no event —
                        // leaving the UI frozen at "Connected" while the service died.
                        notifyTerminalStop(
                            lastStatusText.ifEmpty { getString(R.string.status_disconnected) })
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
            }
                }
            }
        }
    }

    // ──────────── Tunnel session ────────────

    /**
     * Configuration error that no amount of retrying can fix — missing/undecodable
     * server key, wrong key size, invalid port. The reconnect loop treats these as
     * fatal and stops the service cleanly (mirroring the native-lib-unavailable
     * path) instead of retrying forever every [MAX_RETRY_DELAY_MS].
     */
    private class FatalConfigException(message: String) : Exception(message)

    /**
     * One tunnel session.  Blocks until the Rust core exits (error or rekey interval).
     * Any exception propagates to the reconnect loop.
     */
    private suspend fun runTunnel() {
        // Wait for any usable network before starting (avoids immediate DNS/handshake failure).
        waitForConnectivity()

        // Snapshot the saved config into locals up front: stopVpn() nulls these
        // fields non-atomically with this coroutine. A field that vanished because a
        // manual disconnect raced in is a lifecycle artifact — treated as a plain
        // cancellation via [configGone] — NOT invalid user config. FatalConfigException
        // is reserved for genuinely invalid values.
        val snapServerAddr = savedServerAddr
        val snapServerKey = savedServerKey
        val snapPsk = savedPsk
        val snapServerSigningKey = savedServerSigningKey
        val snapMtlsCert = savedMtlsCert

        val (host, port) = parseServerAddr(
            snapServerAddr ?: throw configGone("No server address"))

        val serverKey = try {
            android.util.Base64.decode(
                snapServerKey ?: throw configGone("No server key"),
                android.util.Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            throw FatalConfigException("Server key is not valid base64")
        }
        if (serverKey.size != 32) throw FatalConfigException("Invalid server key size: ${serverKey.size}")

        // Optional key material: an undecodable value degrades the feature (same as a
        // wrong-size value already did) instead of crash-looping the whole tunnel.
        val psk: ByteArray? = snapPsk?.let {
            val decoded = try {
                android.util.Base64.decode(it, android.util.Base64.DEFAULT)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "PSK is not valid base64 — ignoring")
                null
            }
            if (decoded != null && decoded.size == 32) decoded else null
        }
        val serverSigningKey: ByteArray? = snapServerSigningKey?.let {
            val decoded = try {
                android.util.Base64.decode(it, android.util.Base64.DEFAULT)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "Server signing key is not valid base64 — ignoring")
                null
            }
            if (decoded != null && decoded.size == 32) decoded else null
        }

        ensureVpnInterface()
        val activeTun = vpnInterface ?: throw Exception("VPN interface is not available")
        // WireGuard approach: let Android OS choose the best underlying network.
        // Setting null allows automatic network selection and seamless WiFi↔cellular switching.
        // The socket is protected via VpnService.protect() in Rust so it bypasses VPN routing.
        setUnderlyingNetworks(null)

        // Keep the original ParcelFileDescriptor open in the service so Android keeps the
        // device VPN active across reconnects. Rust receives only the borrowed fd number
        // and duplicates it on its side, so it never closes an Android-owned descriptor.
        val tunFd = activeTun.fd

        sessionEstablished = false
        isEstablished      = false
        isRunning          = true
        lastStatusText = getString(R.string.status_connecting)
        uiState = UiState.CONNECTING
        postStatusCallback(false, lastStatusText)
        updateNotification(getString(R.string.notification_connecting))

        // Poll Rust traffic counters once per second and forward to UI.
        // Use coroutineScope so statsJob is automatically cancelled when runTunnel exits,
        // preventing stale callbacks after disconnect.
        coroutineScope {
            val statsJob = launch {
                while (isActive) {
                    delay(1_000L)
                    val tcb = trafficCallback; tcb?.invoke(AivpnJni.getUploadBytes(), AivpnJni.getDownloadBytes())
                    // Apply server-suggested adaptive level silently (takes effect on next
                    // reconnect — ensureVpnInterface() rebuilds the TUN when the desired
                    // MTU changed). -1 = no hint this session; 0 is a REAL hint (server
                    // says adaptive Off) and must be persisted like any other level —
                    // ignoring it made the level ratchet-up-only, so one bad-RTT session
                    // left FEC/Aggressive stuck in prefs forever. Clamp to 0..3 so a
                    // rogue/buggy server hint can never index UI level arrays out of bounds.
                    val hint = AivpnJni.getAdaptiveLevelHint()
                    if (hint in 0..3 && hint != adaptiveLevel()) {
                        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
                            .edit().putInt(PrefsKeys.ADAPTIVE_LEVEL, hint).apply()
                    }
                    // Pool re-home healing: when the server's ServerHello assigns a
                    // different VPN IP than the connection key embeds (the pool moved
                    // this client to resolve an IP collision), every uplink data packet
                    // is silently anti-spoof-dropped while keepalives still flow — the
                    // session looks connected but passes no traffic. Adopt the server's
                    // address, persist it per-server, and bounce the tunnel once so the
                    // TUN is rebuilt with the working IP.
                    val assigned = AivpnJni.getAssignedVpnIp()
                    if (assigned.isNotEmpty() && assigned != savedVpnIp) {
                        Log.w(TAG, "Server assigned VPN IP $assigned (key has $savedVpnIp) — adopting and rebuilding TUN")
                        savedVpnIp = assigned
                        savedServerAddr?.let { server ->
                            getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
                                .edit()
                                .putString(PrefsKeys.PREF_VPN_IP_OVERRIDE + server, assigned)
                                .apply()
                        }
                        networkTrigger = true
                        AivpnJni.stopTunnel()
                    }
                    // Forward any pending recording ack/complete/failed/status message to
                    // whoever is currently observing (MainActivity, if visible).
                    val feedback = AivpnJni.getRecordingFeedback()
                    if (feedback.isNotEmpty()) {
                        recordingCallback?.invoke(feedback)
                    }
                }
            }
            try {
                // Load or generate the device private key for JIT Device Enrollment.
                val deviceKey: ByteArray = SecureStorage.loadDeviceKey(this@AivpnService)
                    ?: ByteArray(32).also { bytes ->
                        java.security.SecureRandom().nextBytes(bytes)
                        SecureStorage.saveDeviceKey(this@AivpnService, bytes)
                    }
                // §3 Polymorphic masks: only meaningful with a concrete (non-auto) base mask.
                val polymorphicBase: String? =
                    if (polymorphicEnabled() && savedMaskProfile != "auto") savedMaskProfile else null
                // §3 privacy: in polymorphic mode, do NOT forward the concrete preset as the
                // initial mask — the opening burst would otherwise be fingerprintable as e.g.
                // "webrtc_zoom_v3" for a full RTT until the server's polymorphic MaskUpdate
                // arrives. Passing null here makes Rust's initial_mask fall back to
                // bootstrap_mask_for_psk, mirroring the desktop CLI GUIs which simply omit
                // --preferred-mask when --polymorphic-base is set.
                val initialMaskArg = if (polymorphicBase != null) null else savedMaskProfile
                // §2 crowdsourced blocking feedback — honor the server-pushed minimum
                // spacing between MaskFeedback sends (persisted across reconnects,
                // since a fresh Rust instance is created every attempt). A hints-only
                // probe is cheap but still respects the interval so a reconnect storm
                // can't spam the server (mirrors desktop client.rs's
                // `maybe_send_mask_feedback`).
                val feedbackPrefs = getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
                val nowUnix = System.currentTimeMillis() / 1000
                val intervalOk = feedbackIntervalElapsed(feedbackPrefs, nowUnix)
                val effShareFeedback = shareMaskFeedback() && intervalOk
                val effReceiveHints = receiveMaskHints() && intervalOk
                val priorOutcomesArg: String? = if (effShareFeedback) {
                    feedbackPrefs.getString(PrefsKeys.PREF_FEEDBACK_OUTCOMES_JSON, null)
                        ?.takeIf { it.isNotBlank() && it != "[]" }
                } else null
                // Covert first handshake: feed the Rust core the descriptors we
                // persisted from a PRIOR session so a COLD-START first handshake
                // resolves a COVERT rotated descriptor mask instead of a public
                // preset. A truly-first-ever connect (nothing cached yet) passes
                // null and falls back to the preset — acceptable residual.
                val cachedDescriptorsArg: String? =
                    SecureStorage.loadBootstrapDescriptors(this@AivpnService, snapServerKey)
                val error = withContext(Dispatchers.IO) {
                    AivpnJni.runTunnel(
                        this@AivpnService, tunFd, host, port, serverKey, psk, snapMtlsCert,
                        adaptiveLevel(), deviceKey, initialMaskArg, serverSigningKey,
                        polymorphicBase, effShareFeedback, effReceiveHints, countryCode(),
                        priorOutcomesArg, cachedDescriptorsArg,
                    )
                }
                if (error.isNotEmpty()) throw RuntimeException(error)
            } finally {
                // HIGH-1: the native runTunnel returns when stopTunnel() closes the
                // socket, but on a manual disconnect / service destroy serviceJob is
                // cancelled, so the `withContext(Dispatchers.IO)` above RETHROWS
                // CancellationException at resumption — skipping any post-return code.
                // Manual-disconnect-then-cold-start is the single most common
                // end-of-session path, and skipping the persist there means the next
                // cold start has no cached descriptor and falls back to a public preset.
                // Run the bookkeeping in NonCancellable in the finally so §2 feedback
                // state AND the covert descriptor blob are ALWAYS persisted.
                withContext<Unit>(kotlinx.coroutines.NonCancellable) {
                    recordFeedbackOutcome()
                    // Persist any bootstrap descriptors the server pushed this session
                    // (deduped/validity-filtered in the core), keyed PER SERVER (M1) so a
                    // profile switch never loads another server's descriptors. Best-effort:
                    // a storage failure never breaks the tunnel. Blank/"[]" is filtered so
                    // a session that pushed nothing never clears this server's cache.
                    try {
                        val descriptorsJson = AivpnJni.getBootstrapDescriptorsJson()
                        if (descriptorsJson.isNotBlank() && descriptorsJson != "[]") {
                            SecureStorage.saveBootstrapDescriptors(
                                this@AivpnService, descriptorsJson, snapServerKey)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Persisting bootstrap descriptors failed: ${e.message}")
                    }
                }
                statsJob.cancel()
                isRunning = false
                isEstablished = false
            }
        }
    }

    /**
     * Classifies a missing saved-config field: if a manual disconnect is in flight
     * (stopVpn() clears the saved key material), the null is a lifecycle artifact —
     * unwind quietly as a cancellation. Only a genuinely absent value on an
     * intentional start is a fatal configuration error.
     */
    private fun configGone(what: String): Exception =
        if (manualDisconnect) CancellationException("$what — cleared by disconnect")
        else FatalConfigException(what)

    /**
     * Called from Rust (JNI) when handshake and key ratchet are complete.
     * This is the first moment when "connected" is actually true.
     */
    @Suppress("unused")
    fun onTunnelReady(host: String) {
        // postConnectUntilMs must be written BEFORE sessionEstablished — network callbacks
        // check sessionEstablished first and then read postConnectUntilMs; if the order were
        // reversed a callback could see sessionEstablished=true while postConnectUntilMs=0.
        postConnectUntilMs = SystemClock.elapsedRealtime() + POST_CONNECT_COOLDOWN_MS
        sessionEstablished = true
        isEstablished = true
        isRunning = true
        lastStatusText = getString(R.string.status_connected, host)
        uiState = UiState.CONNECTED
        postStatusCallback(true, lastStatusText)
        // onTunnelReady is invoked from the Rust JNI thread; TileService callbacks
        // (qsTile access) must run on the main thread, same as statusCallback above.
        mainHandler.post { tileCallback?.invoke() }
        // Only the ongoing foreground notification announces the connected
        // state. A separate event notification here duplicated it verbatim —
        // two identical "Connected to X" rows in the shade (and a re-fire on
        // every auto-reconnect). The events channel still carries disconnect.
        updateNotification(getString(R.string.notification_connected, host))
        // The tunnel is actually up again: clear any lingering HIGH-importance
        // "VPN stopped / traffic unprotected" alert (ID 3) from an earlier
        // unexpected stop so a stale warning doesn't sit beside the live
        // Connected notification. Done here (not at connect start) because the
        // warning stays true until the session is genuinely re-established.
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ALERT_ID)
        Log.d(TAG, "Tunnel ready: host=$host")
    }

    // ──────────── Network callbacks ────────────

    /**
     * WireGuard-style approach: we do NOT manually select networks or bind sockets
     * to specific interfaces.  Instead:
     *   - setUnderlyingNetworks(null) lets Android route through the best available network
     *   - VpnService.protect(fd) ensures the UDP socket bypasses VPN routing
    *   - We detect default-network switches/loss and trigger a fast tunnel restart (which will
     *     get a fresh DNS resolution and handshake on whatever network is available)
    *   - The Rust side has an aggressive RX silence detector as backup
     */
    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        currentUnderlyingNetwork = findUsableUnderlyingNetwork(cm)

        val callback = object : ConnectivityManager.NetworkCallback() {

            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network) ?: return
                if (!isUsableUnderlyingNetwork(caps)) return

                val previous = currentUnderlyingNetwork
                if (previous == null || previous == network) {
                    currentUnderlyingNetwork = network
                    return
                }

                Log.d(TAG, "Underlying network available: $network (previous=$previous)")

                // onAvailable fires for EVERY network matching the request, not
                // just the default one: on dual-SIM devices the standby SIM's
                // data network (and a re-validating Wi-Fi) periodically announce
                // themselves while the network the tunnel is riding stays
                // perfectly healthy. Blindly adopting each announcement made
                // consecutive events alternate previous/next between two live
                // networks — an endless restart ping-pong every 5-10 s that only
                // a manual reconnect (which re-initialises
                // currentUnderlyingNetwork) could break. A switch is real only
                // when the network we ride is no longer usable, or when Wi-Fi
                // appears while riding cellular (the one upgrade users expect).
                val prevCaps = cm.getNetworkCapabilities(previous)
                val prevAlive = prevCaps != null && isUsableUnderlyingNetwork(prevCaps)
                val wifiUpgrade = prevAlive &&
                    prevCaps!!.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                if (prevAlive && !wifiUpgrade) {
                    Log.d(TAG, "Ignoring additional usable network $network — current $previous still healthy")
                    return
                }

                if (!isRunning || !sessionEstablished) {
                    currentUnderlyingNetwork = network
                    return
                }

                // Seamless roaming with a protected UDP socket is not reliable across
                // all Android vendors/radios. If the network we ride actually changed
                // under an established session, restart immediately on the new path.
                val now = SystemClock.elapsedRealtime()
                if (now < postConnectUntilMs) {
                    // VPN just came up — Android reshuffles network IDs; ignore
                    // same-transport churn and defer Wi-Fi upgrades until the
                    // settle window ends. But if the previous network died AND
                    // the transport type actually changed (e.g. WiFi → cellular),
                    // restart now so the tunnel doesn't stay bound to the dead
                    // network until the RX watchdog fires.
                    if (wifiUpgrade) return
                    if (prevCaps != null && isTransportChange(prevCaps, caps)) {
                        if (now - lastNetworkEventAtMs >= NETWORK_EVENT_DEBOUNCE_MS) {
                            lastNetworkEventAtMs = now
                            currentUnderlyingNetwork = network
                            Log.d(TAG, "Transport type changed within post-connect cooldown; restarting tunnel")
                            networkTrigger = true
                            AivpnJni.stopTunnel()
                        }
                    } else {
                        // Same-transport ID reshuffle of a dead old ID — adopt silently.
                        currentUnderlyingNetwork = network
                    }
                } else if (now - lastNetworkEventAtMs >= NETWORK_EVENT_DEBOUNCE_MS) {
                    lastNetworkEventAtMs = now
                    currentUnderlyingNetwork = network
                    Log.d(TAG, "Underlying network switched: $previous -> $network " +
                        "(${if (wifiUpgrade) "wifi upgrade" else "previous no longer usable"}); restarting tunnel")
                    networkTrigger = true
                    AivpnJni.stopTunnel()
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (!isUsableUnderlyingNetwork(caps)) return
                if (currentUnderlyingNetwork == null) {
                    currentUnderlyingNetwork = network
                    Log.d(TAG, "Underlying network became usable: $network")
                }
            }

            override fun onLost(network: Network) {
                Log.d(TAG, "Underlying network lost: $network")

                // Only the loss of the network the tunnel actually RIDES may
                // trigger a restart. onLost also fires for secondary networks
                // (standby SIM, a passing Wi-Fi) whose loss doesn't touch the
                // carrier — reacting to those restarted the tunnel every time a
                // secondary dropped: the same ping-pong the onAvailable guard
                // fixed (82aee70), which onLost never got.
                if (network != currentUnderlyingNetwork) return

                currentUnderlyingNetwork = findUsableUnderlyingNetwork(cm)

                val replacement = currentUnderlyingNetwork
                val hasUsableDefault = replacement?.let { net ->
                    val caps = cm.getNetworkCapabilities(net)
                    caps != null && isUsableUnderlyingNetwork(caps)
                } == true

                if (hasUsableDefault && replacement != null && isRunning && sessionEstablished) {
                    val now = SystemClock.elapsedRealtime()
                    if (now >= postConnectUntilMs && now - lastNetworkEventAtMs >= NETWORK_EVENT_DEBOUNCE_MS) {
                        lastNetworkEventAtMs = now
                        Log.d(TAG, "Underlying network moved to $replacement after loss of $network; restarting tunnel")
                        networkTrigger = true
                        AivpnJni.stopTunnel()
                    }
                    return
                }

                // Only abort an established session on total network loss.
                // During handshake (sessionEstablished=false) Android transiently
                // reshuffles network IDs as the VPN interface comes up, causing
                // momentary hasUsableDefault=false even when the link is healthy.
                // Stopping the tunnel here before sessionEstablished produces
                // repeated rapid reconnects ("jitter") on initial connect.
                if (!hasUsableDefault && isRunning && sessionEstablished) {
                    val now = SystemClock.elapsedRealtime()
                    if (now - lastNetworkEventAtMs >= NETWORK_EVENT_DEBOUNCE_MS) {
                        lastNetworkEventAtMs = now
                        Log.d(TAG, "No usable underlying network — stopping tunnel for fast reconnect")
                        networkTrigger = true
                        AivpnJni.stopTunnel()
                    }
                }
            }
        }

        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register NetworkCallback: ${e.message}", e)
        }
    }

    fun adaptiveLevel(): Int =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getInt(PrefsKeys.ADAPTIVE_LEVEL, 0)
            .coerceIn(0, 3)

    private fun isAdaptiveEnabled(): Boolean = adaptiveLevel() > 0

    /** §3 Polymorphic masks: whether to request a per-session unique variant of the selected mask. */
    private fun polymorphicEnabled(): Boolean =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getBoolean(PrefsKeys.PREF_POLYMORPHIC_ENABLED, false)

    /** §2 crowdsourced blocking feedback (opt-in): whether to report mask outcomes to the server. */
    private fun shareMaskFeedback(): Boolean =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getBoolean(PrefsKeys.PREF_SHARE_MASK_FEEDBACK, false)

    /** §2 crowdsourced blocking feedback (opt-in): whether to accept server regional mask hints. */
    private fun receiveMaskHints(): Boolean =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getBoolean(PrefsKeys.PREF_RECEIVE_MASK_HINTS, false)

    /** 2-letter ISO-3166-1 alpha-2 country code for §2 feedback/hints, or null if unset/invalid. */
    private fun countryCode(): String? =
        getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
            .getString(PrefsKeys.PREF_COUNTRY_CODE, null)
            ?.trim()
            ?.takeIf { it.length == 2 && it.all(Char::isLetter) }

    // ──────────── §2 crowdsourced blocking feedback — persisted outcome log ────────────
    //
    // `AivpnJni.runTunnel` handles exactly one connection attempt per call, so this
    // service — which owns the reconnect loop — is responsible for everything the
    // desktop CLI's `main.rs` + `mask_feedback_log.rs` do together: tracking
    // consecutive per-family failures across attempts, batching unreported outcomes,
    // honoring the server-pushed report interval/threshold, and persisting all of it
    // (here: plain SharedPreferences instead of a JSON file) so it survives the Rust
    // instance being dropped and recreated on every reconnect.

    private fun feedbackFailureThreshold(prefs: android.content.SharedPreferences): Int =
        prefs.getInt(PrefsKeys.PREF_FEEDBACK_FAILURE_THRESHOLD, 3)
            .coerceIn(1, FEEDBACK_MAX_FAILURE_THRESHOLD)

    private fun feedbackIntervalSecs(prefs: android.content.SharedPreferences): Long {
        val v = prefs.getLong(PrefsKeys.PREF_FEEDBACK_INTERVAL_SECS, 3600L)
        return if (v <= 0) 3600L else v.coerceAtMost(FEEDBACK_MAX_INTERVAL_SECS)
    }

    private fun feedbackIntervalElapsed(prefs: android.content.SharedPreferences, nowUnix: Long): Boolean {
        val last = prefs.getLong(PrefsKeys.PREF_FEEDBACK_LAST_REPORT_UNIX, 0L)
        return (nowUnix - last) >= feedbackIntervalSecs(prefs)
    }

    private fun loadConsecutiveFails(prefs: android.content.SharedPreferences): MutableMap<String, Int> {
        val json = prefs.getString(PrefsKeys.PREF_FEEDBACK_CONSECUTIVE_FAILS_JSON, null)
            ?: return mutableMapOf()
        return try {
            val obj = JSONObject(json)
            val map = mutableMapOf<String, Int>()
            obj.keys().forEach { k -> map[k] = obj.optInt(k, 0) }
            map
        } catch (e: Exception) {
            mutableMapOf()
        }
    }

    private fun saveConsecutiveFails(prefs: android.content.SharedPreferences, fails: Map<String, Int>) {
        val obj = JSONObject()
        fails.forEach { (k, v) -> obj.put(k, v) }
        prefs.edit().putString(PrefsKeys.PREF_FEEDBACK_CONSECUTIVE_FAILS_JSON, obj.toString()).apply()
    }

    /**
     * Appends one outcome entry for `family` to the persisted unreported-outcome
     * buffer, bounded to [FEEDBACK_OUTCOMES_MAX_ENTRIES] (oldest evicted first,
     * mirroring desktop's `MaskFeedbackLog::MAX_ENTRIES`). Entries are summed per
     * mask family by the Rust core (`merge_mask_outcomes`) when a batch is sent, so
     * appending one small entry per outcome — rather than merging here — matches
     * desktop's append-then-aggregate-at-send-time design.
     */
    private fun appendFeedbackOutcome(
        prefs: android.content.SharedPreferences,
        family: String,
        success: Boolean,
    ) {
        val current = try {
            org.json.JSONArray(prefs.getString(PrefsKeys.PREF_FEEDBACK_OUTCOMES_JSON, "[]"))
        } catch (e: Exception) {
            org.json.JSONArray()
        }
        val entry = JSONObject().apply {
            put("mask_id", family)
            put("success", if (success) 1 else 0)
            put("fail", if (success) 0 else 1)
        }
        val startIdx = (current.length() - FEEDBACK_OUTCOMES_MAX_ENTRIES + 1).coerceAtLeast(0)
        val out = org.json.JSONArray()
        for (i in startIdx until current.length()) out.put(current.get(i))
        out.put(entry)
        prefs.edit().putString(PrefsKeys.PREF_FEEDBACK_OUTCOMES_JSON, out.toString()).apply()
    }

    /**
     * Called after every [AivpnJni.runTunnel] call returns (success or error) to
     * process this attempt's §2 outcome. Order of operations mirrors desktop's
     * split between `client.rs` (tuning/hints/success bookkeeping, live during a
     * session) and `main.rs`'s reconnect loop (failure attribution, after the
     * session ends):
     *  1. Persist any server-pushed `FeedbackConfig` tuning from this session.
     *  2. Persist any `RegionalMaskHints` received this session.
     *  3. If a `MaskFeedback` was actually sent, this attempt's own outcome was
     *     already folded into that batch by Rust — clear the local buffer and
     *     record the send time.
     *  4. Otherwise: on success, buffer a success entry locally so a future send
     *     reports it; on failure, bump the family's consecutive-fail counter and,
     *     at the server-pushed threshold, buffer a failure entry and reset it.
     */
    private fun recordFeedbackOutcome() {
        val prefs = getSharedPreferences(PrefsKeys.PREFS_NAME, MODE_PRIVATE)
        val nowUnix = System.currentTimeMillis() / 1000

        val threshold = AivpnJni.getFeedbackThreshold()
        val intervalSecs = AivpnJni.getFeedbackIntervalSecs()
        if (threshold > 0 || intervalSecs > 0) {
            val editor = prefs.edit()
            if (threshold > 0) {
                // Upper-clamp a server-pushed threshold — a malicious server
                // could otherwise push a value so high failure reporting is
                // effectively disabled.
                editor.putInt(
                    PrefsKeys.PREF_FEEDBACK_FAILURE_THRESHOLD,
                    threshold.coerceIn(1, FEEDBACK_MAX_FAILURE_THRESHOLD)
                )
            }
            if (intervalSecs > 0) {
                // Upper-clamp a server-pushed interval — a malicious server
                // could otherwise push a value of years, effectively
                // disabling reporting.
                editor.putLong(
                    PrefsKeys.PREF_FEEDBACK_INTERVAL_SECS,
                    intervalSecs.coerceAtMost(FEEDBACK_MAX_INTERVAL_SECS)
                )
            }
            editor.apply()
        }

        if (AivpnJni.getRegionalHintsSeq() > 0) {
            val hintsJson = AivpnJni.getRegionalHintsJson()
            if (hintsJson.isNotEmpty()) {
                prefs.edit().putString(PrefsKeys.PREF_REGIONAL_HINTS_JSON, hintsJson).apply()
            }
        }

        val sent = AivpnJni.wasMaskFeedbackSent()
        if (sent) {
            prefs.edit()
                .putString(PrefsKeys.PREF_FEEDBACK_OUTCOMES_JSON, "[]")
                .putLong(PrefsKeys.PREF_FEEDBACK_LAST_REPORT_UNIX, nowUnix)
                .apply()
        }

        // Failure attribution + local outcome bookkeeping only applies when the
        // user opted in to sharing and a region is configured (mirrors desktop
        // main.rs's `feedback_share_enabled = args.share_mask_feedback &&
        // country_code.is_some()`), independent of whether THIS attempt's send
        // was suppressed by the interval gate.
        if (!shareMaskFeedback() || countryCode() == null) return
        val family = AivpnJni.getAttemptedMaskFamily()
        if (family.isEmpty()) return

        val fails = loadConsecutiveFails(prefs)
        if (AivpnJni.everConnected()) {
            if (fails.remove(family) != null) saveConsecutiveFails(prefs, fails)
            if (!sent) appendFeedbackOutcome(prefs, family, success = true)
            return
        }
        if (sent) return // sent implies a connected attempt; nothing more to do on failure
        val count = (fails[family] ?: 0) + 1
        if (count >= feedbackFailureThreshold(prefs)) {
            appendFeedbackOutcome(prefs, family, success = false)
            fails.remove(family)
            Log.d(TAG, "§2 recorded mask FAILURE for family '$family' ($count consecutive failed attempts)")
        } else {
            fails[family] = count
        }
        saveConsecutiveFails(prefs, fails)
    }

    private fun isTransportChange(prev: NetworkCapabilities, next: NetworkCapabilities): Boolean {
        val prevWifi     = prev.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val nextWifi     = next.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val prevCellular = prev.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val nextCellular = next.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        return prevWifi != nextWifi || prevCellular != nextCellular
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (e: Exception) { Log.w(TAG, "Failed to unregister network callback: ${e.message}") }
            networkCallback = null
        }
        currentUnderlyingNetwork = null
    }

    // ──────────── Stop ────────────

    private fun stopVpn(startId: Int? = null) {
        val wasEstablished = sessionEstablished
        manualDisconnect = true
        isServiceActive = false
        // The user explicitly turned the VPN off — clear the persisted intent so
        // no watchdog resurrects the tunnel.
        BootPrefs.prefs(this).edit().putBoolean(PrefsKeys.PREF_VPN_DESIRED, false).apply()
        restartJob?.cancel()
        restartJob = null
        unregisterNetworkCallback()
        if (AivpnJni.isAvailable) AivpnJni.stopTunnel()
        serviceJob?.cancel()
        // Do NOT null serviceJob here — the finally block sets it after the native call
        // actually returns.  startVpn's cancelAndJoin() uses this reference to wait for
        // the old session to fully unwind before starting a new one; a premature null
        // turns that join into a no-op and lets two runTunnel calls overlap.
        closeTunnel()
        savedServerKey = null
        savedPsk = null
        savedServerSigningKey = null
        savedMtlsCert = null
        isRunning = false
        isEstablished = false
        lastStatusText = getString(R.string.status_disconnected)
        uiState = UiState.DISCONNECTED
        postStatusCallback(false, lastStatusText)
        val ticb1 = tileCallback; ticb1?.invoke()
        if (wasEstablished) {
            postEventNotification(getString(R.string.status_disconnected))
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        // Use stopSelf(startId) so Android does not destroy the service if a new
        // ACTION_CONNECT intent arrived after this ACTION_DISCONNECT.  Without the
        // startId guard, onDestroy() could fire and cancel a freshly-launched
        // restartJob, leaving the UI stuck at "Connecting…" forever.
        if (startId != null) stopSelf(startId) else stopSelf()
    }

    private fun closeTunnel() {
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        currentTunMtu = 0
        currentTunAddress = null
    }

    /**
     * Called when Android revokes the VPN permission (e.g. another VPN app takes over).
     * Mark as manual disconnect so the reconnect loop does not attempt to reconnect, stop
     * the tunnel, and call super so Android tears down the VPN interface and service cleanly.
     */
    override fun onRevoke() {
        Log.w(TAG, "onRevoke() — OS revoked VPN permission, stopping permanently")
        manualDisconnect = true
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        // Capture BEFORE overwriting: manualDisconnect == false with an active
        // service here means the SYSTEM stopped us mid-session (Android 12+
        // battery "Restricted" state, OEM power manager, FGS Task-Manager stop) —
        // the user never asked. This path used to be completely silent: no status
        // post, no tile refresh, no event notification, lastStatusText still
        // saying "Connected" — while the closed TUN reverted traffic to the real
        // interface with the real IP.
        val unexpectedStop = !manualDisconnect && isServiceActive
        manualDisconnect = true
        isServiceActive = false
        restartJob?.cancel()
        restartJob = null
        unregisterNetworkCallback()
        if (AivpnJni.isAvailable) AivpnJni.stopTunnel()
        serviceJob?.cancel()
        serviceJob = null
        if (unexpectedStop) {
            // Must run BEFORE tileCallback is nulled below (fireTileCallback
            // captures the reference synchronously).
            notifyTerminalStop(getString(R.string.status_disconnected))
            // The user still wants the VPN up (intent persisted at connect):
            // schedule an expedited one-shot to re-send ACTION_CONNECT.
            // START_STICKY covers a process KILL, but a system-initiated service
            // STOP is never restarted by the framework — this is that recovery.
            if (BootPrefs.prefs(this).getBoolean(PrefsKeys.PREF_VPN_DESIRED, false)) {
                VpnReconnectWorker.schedule(this)
            }
        } else {
            // Keep the ground truth honest for any later Activity resync.
            isEstablished = false
            lastStatusText = getString(R.string.status_disconnected)
            uiState = UiState.DISCONNECTED
        }
        closeTunnel()
        isRunning = false
        serviceScope.cancel()
        tileCallback = null
        instance = null
        super.onDestroy()
    }

    /**
     * Centralized signal for every NON-manual terminal service stop (system stop,
     * OEM power manager, fatal config, reconnect-loop exit). The manual path posts
     * its own signals in [stopVpn]. This is a security event: the TUN is closed
     * (or about to be), so traffic reverts to the real interface with the real IP —
     * hence the HIGH-importance alert notification.
     */
    private fun notifyTerminalStop(reason: String) {
        isEstablished = false
        isRunning = false
        lastStatusText = reason
        uiState = UiState.DISCONNECTED
        postStatusCallback(false, reason)
        fireTileCallback()
        postSecurityAlertNotification(reason)
    }

    /**
     * Invokes the QS-tile refresh callback on the main thread. Captures the
     * reference synchronously so a caller that nulls [tileCallback] right after
     * (onDestroy) cannot lose the final refresh.
     */
    private fun fireTileCallback() {
        val tcb = tileCallback ?: return
        mainHandler.post { tcb.invoke() }
    }

    /** API 29+: whether OS Always-on lockdown ("Block connections without VPN") is enabled. */
    private fun isLockdownActive(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            try { isLockdownEnabled } catch (e: Exception) { false }

    /**
     * HIGH-importance security alert for an unexpected VPN death: states explicitly
     * that traffic is NOT protected, and — when OS-level lockdown is not enabled —
     * deep-links to the system Always-on VPN screen, recommending "Block connections
     * without VPN" (the only real kill switch available to a non-system app).
     */
    private fun postSecurityAlertNotification(reason: String) {
        val lockdown = isLockdownActive()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Log.i(TAG, "Terminal stop: alwaysOn=${try { isAlwaysOn } catch (e: Exception) { false }} lockdown=$lockdown")
        }
        val body = StringBuilder(getString(R.string.alert_vpn_stopped, reason))
        if (!lockdown) {
            body.append("\n\n").append(getString(R.string.alert_lockdown_hint))
        }
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = Notification.Builder(this, CHANNEL_ALERTS_ID)
            .setContentTitle(getString(R.string.alert_vpn_stopped_title))
            .setContentText(getString(R.string.alert_vpn_stopped, reason))
            .setStyle(Notification.BigTextStyle().bigText(body.toString()))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
        if (!lockdown) {
            val settingsIntent = PendingIntent.getActivity(
                this, 1,
                Intent(android.provider.Settings.ACTION_VPN_SETTINGS),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            builder.addAction(
                Notification.Action.Builder(
                    null as android.graphics.drawable.Icon?,
                    getString(R.string.alert_open_vpn_settings), settingsIntent
                ).build())
        }
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ALERT_ID, builder.build())
        } catch (e: Exception) {
            Log.w(TAG, "Failed to post security alert: ${e.message}")
        }
    }

    private fun ensureVpnInterface() {
        val tunMtu = if (isAdaptiveEnabled()) ADAPTIVE_TUN_MTU else savedVpnMtu.coerceAtLeast(576)
        val tunAddress4 = savedVpnIp ?: "10.0.0.2"
        val tunPrefixLen = savedVpnPrefixLen.coerceIn(1, 30)
        if (vpnInterface != null) {
            if (currentTunMtu == tunMtu && currentTunAddress == tunAddress4) {
                return
            }
            // The desired MTU or address changed since this interface was built —
            // both only apply at establish() time, so rebuild. Address changes come
            // from a pool re-home (server-assigned VPN IP differs from the key); MTU
            // changes come from the adaptive level. This runs only at a reconnect
            // boundary (no live session holds the fd) and mirrors the first connect;
            // the brief routing gap is the price of the new value taking effect.
            Log.i(
                TAG,
                "TUN params changed (mtu $currentTunMtu->$tunMtu addr $currentTunAddress->$tunAddress4) — recreating VPN interface",
            )
            closeTunnel()
        }

        // Diagnostic: surface the EXACT address set on the TUN. A
        // VpnService.establish() "Cannot set address" failure is otherwise
        // opaque — the exception names no value — so this line is the only way
        // to tell a bad client_ip from a stale-state / device rejection.
        Log.i(
            TAG,
            "Establishing TUN: addr=$tunAddress4/$tunPrefixLen mtu=$tunMtu " +
                "serverVpnIp=$savedServerVpnIp v6=fd00::2/64",
        )

        // Build TUN (must stay in Kotlin — Android API).
        // setBlocking(false): Rust uses epoll/AsyncFd on the raw fd.
        // allowBypass() is intentionally NOT called — default VpnService.Builder behaviour
        // prevents any app from bypassing the VPN tunnel.
        //
        // IPv6: we do NOT tunnel v6 (the Rust data path drops non-IPv4 payloads),
        // but we MUST still CAPTURE it. Omitting IPv6 config does not disable v6 —
        // Android then routes v6-capable sockets over the real (non-VPN) interface
        // with the device's real address, a full deanonymisation leak on any
        // dual-stack network. Add a ULA address + a ::/0 catch-all so all v6
        // traffic enters the tun and is dropped rather than leaking.
        val dnsList = savedDnsServers.ifEmpty { listOf("8.8.8.8", "1.1.1.1") }
        val allowedApps = SecureStorage.loadAllowedApps(this)

        // Build a fresh Builder. `includeIpv6` adds the ULA + ::/0 capture (see
        // below); we drop it on the v4-only retry because some ROMs (observed
        // on ColorOS) reject the IPv6 address at establish() with an opaque
        // "Cannot set address" even though addAddress() accepted it.
        //
        // IPv6 rationale: we do NOT tunnel v6 (the Rust data path drops non-IPv4
        // payloads), but we MUST still CAPTURE it. Omitting IPv6 config does not
        // disable v6 — Android then routes v6-capable sockets over the real
        // (non-VPN) interface with the device's real address, a deanonymisation
        // leak on any dual-stack network. So v6 capture is preferred; v4-only is
        // the fallback that keeps the tunnel working (v4 still fully protected).
        fun buildTun(includeIpv6: Boolean): Builder {
            // setBlocking(false): Rust uses epoll/AsyncFd on the raw fd.
            // allowBypass() is intentionally NOT called — default behaviour
            // prevents any app from bypassing the VPN tunnel.
            val b = Builder()
                .setSession("AIVPN")
                .addAddress(tunAddress4, tunPrefixLen)
                .addRoute("0.0.0.0", 0)
                .setMtu(tunMtu)
                .setBlocking(false)
            if (includeIpv6) {
                try {
                    // Valid ULA (fd00::/8). A non-numeric literal would make
                    // addAddress throw and skip BOTH the address AND the ::/0
                    // route, leaking IPv6 around the tunnel.
                    b.addAddress("fd00::2", 64)
                    b.addRoute("::", 0)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to add IPv6 capture route: ${e.message}")
                }
            }
            for (dns in dnsList) {
                try { b.addDnsServer(dns) } catch (e: Exception) {
                    Log.w(TAG, "Skipping invalid DNS server: $dns")
                }
            }
            for (pkg in allowedApps) {
                try {
                    b.addAllowedApplication(pkg)
                } catch (_: Exception) {
                    // Package may have been uninstalled — skip silently
                }
            }
            // Domain-based split tunnel: resolve each excluded domain to IPv4
            // addresses and add /32 exclusion routes so that traffic to those
            // IPs bypasses the VPN. Re-resolved on every (re)connect.
            applyDomainExclusions(b)
            return b
        }

        vpnInterface = try {
            buildTun(includeIpv6 = true).establish()
                ?: throw Exception("Failed to establish VPN interface")
        } catch (e: IllegalArgumentException) {
            // establish() rejected the address set (kernel jniSetAddresses).
            // Most likely the IPv6 ULA on a ROM that refuses it. Retry v4-only
            // before giving up — a working v4 tunnel beats an infinite reconnect
            // loop (the reported symptom). The v4 address itself is validated as
            // an assignable host by ConnectionKeyParser, so if THIS also fails
            // the config is genuinely unusable → stop the loop (FatalConfig)
            // with a message naming the address, instead of retrying every 8 s.
            Log.w(TAG, "establish() rejected addr set (${e.message}) — retrying IPv4-only")
            try {
                val v4only = buildTun(includeIpv6 = false).establish()
                    ?: throw Exception("Failed to establish VPN interface (v4-only)")
                Log.w(TAG, "Established IPv4-only TUN (IPv6 capture disabled on this device)")
                v4only
            } catch (e2: IllegalArgumentException) {
                Log.e(TAG, "establish() rejected addr=$tunAddress4/$tunPrefixLen even v4-only: ${e2.message}")
                throw FatalConfigException(
                    "Android rejected VPN address $tunAddress4/$tunPrefixLen (${e2.message}). " +
                        "Clear app data and re-add the connection key.",
                )
            }
        }
        currentTunMtu = tunMtu
        currentTunAddress = tunAddress4
    }

    /**
     * Resolve each excluded domain to IPv4 addresses and register them as exclusion routes
     * via [Builder.excludeRoute] so traffic to those IPs bypasses the VPN tunnel.
     *
     * [Builder.excludeRoute] was added in API 33 (Android 13). On older devices the builder
     * has no exclusion-route primitive; we log a warning and skip — the stored domain list
     * will take effect once the device is on API 33+.
     *
     * Limitation: CDN IPs rotate and vary per client. Domains are re-resolved on every
     * tunnel (re)connect. DNS resolution runs synchronously here because
     * [ensureVpnInterface] is already called from a background coroutine (Dispatchers.IO).
     */
    private fun applyDomainExclusions(builder: Builder) {
        val domains = SecureStorage.loadExcludedDomains(this)
        if (domains.isEmpty()) return

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            Log.w(TAG, "Domain split tunnel requires API 33 (Android 13); " +
                "${domains.size} domain(s) configured but skipped on API ${Build.VERSION.SDK_INT}")
            return
        }

        val resolvedIps = mutableSetOf<Inet4Address>()

        for (domain in domains) {
            try {
                val addrs = InetAddress.getAllByName(domain)
                val v4addrs = addrs.filterIsInstance<Inet4Address>()
                if (v4addrs.isEmpty()) {
                    Log.d(TAG, "Domain $domain: no IPv4 addresses returned — skipping")
                } else {
                    Log.d(TAG, "Domain $domain resolved: ${v4addrs.map { it.hostAddress }}")
                    resolvedIps.addAll(v4addrs)
                }
            } catch (e: Exception) {
                Log.w(TAG, "DNS resolution failed for excluded domain $domain: ${e.message}")
            }
        }

        if (resolvedIps.isEmpty()) {
            Log.d(TAG, "No IPv4 addresses resolved for excluded domains")
            return
        }

        for (addr in resolvedIps) {
            try {
                // Builder.excludeRoute(IpPrefix) — API 33+. Traffic to this /32 prefix
                // is routed through the underlying network, not through the VPN tunnel.
                @Suppress("NewApi")
                builder.excludeRoute(android.net.IpPrefix(addr, 32))
                Log.d(TAG, "Exclusion route applied: ${addr.hostAddress}/32")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to add exclusion route for ${addr.hostAddress}: ${e.message}")
            }
        }
    }

    // ──────────── Network waiting ────────────

    /**
     * Block until at least one non-VPN network with internet capability exists.
     * This prevents wasting time on DNS lookups / handshakes when there's no connectivity.
     */
    private suspend fun waitForConnectivity() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        var waitedMs = 0L
        while (currentCoroutineContext().isActive) {
            val active = findUsableUnderlyingNetwork(cm)
            val hasUsableActiveNetwork = active != null

            if (hasUsableActiveNetwork) return

            // Fallback: when VPN is active, activeNetwork can point to TRANSPORT_VPN.
            // In that case, scan all networks for any non-VPN internet-capable network.
            val hasAnyUsableNetwork = cm.allNetworks.any { net ->
                val netCaps = cm.getNetworkCapabilities(net) ?: return@any false
                !netCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    netCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
            if (hasAnyUsableNetwork) return

            // Last resort: if any network (including our own VPN from a previous
            // session) reports internet capability, proceed immediately.  As a
            // VpnService we can replace any existing VPN interface, so blocking here
            // when only the old VPN network is visible causes an infinite hang.
            val hasAnyInternet = cm.allNetworks.any { net ->
                cm.getNetworkCapabilities(net)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            }
            if (hasAnyInternet) return

            // Hard safety timeout: if absolutely no connectivity after 5 s, proceed
            // anyway and let the DNS / handshake fail with a clear error message.
            if (waitedMs >= 5_000L) return

            delay(300L)
            waitedMs += 300L
        }
        throw CancellationException("Cancelled while waiting for network")
    }

    private fun findUsableUnderlyingNetwork(cm: ConnectivityManager): Network? {
        return cm.allNetworks.firstOrNull { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
            isUsableUnderlyingNetwork(caps)
        }
    }

    private fun isUsableUnderlyingNetwork(caps: NetworkCapabilities): Boolean {
        return !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    // ──────────── Address parsing ────────────

    private fun parseServerAddr(serverAddr: String): Pair<String, Int> {
        if (serverAddr.startsWith("[")) {
            val bracket = serverAddr.indexOf(']')
            if (bracket > 0) {
                val host = serverAddr.substring(1, bracket)
                // An explicitly-specified port must be valid; silently substituting 443
                // for garbage like "[::1]:99999" would connect to the wrong endpoint.
                val port = if (bracket + 1 < serverAddr.length && serverAddr[bracket + 1] == ':')
                    serverAddr.substring(bracket + 2).toIntOrNull()?.takeIf { it in 1..65535 }
                        ?: throw FatalConfigException("Invalid port in server address: $serverAddr")
                else 443
                return Pair(host, port)
            }
        }
        val lastColon = serverAddr.lastIndexOf(':')
        // No colon at all — bare hostname/IPv4, default port.
        if (lastColon < 0) return Pair(serverAddr, 443)
        // More than one colon without brackets is a bare IPv6 literal, not
        // host:port (IPv6-with-port requires the bracket form handled above).
        if (serverAddr.indexOf(':') != lastColon) return Pair(serverAddr, 443)
        // Exactly one colon = an explicit host:port. The port must be valid;
        // silently folding garbage like "host:99999" back into the hostname
        // makes DNS fail and the reconnect loop retry forever.
        val port = serverAddr.substring(lastColon + 1).toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw FatalConfigException("Invalid port in server address: $serverAddr")
        return Pair(serverAddr.substring(0, lastColon), port)
    }

    // ──────────── Profile-keyed connect ────────────

    /**
     * Load the VPN profile from EncryptedSharedPreferences by [profileId] and
     * start the tunnel.  Server keys stay in secure storage and are never
     * exposed as Intent extras.
     *
     * All failure paths call [stopSelfCleanly] — this method is only reached from
     * [onStartCommand], which has already promoted the service to foreground, so a
     * bare return would leave a zombie foreground notification (and, before the
     * early startForeground existed, an ANR-crash).
     */
    private fun loadAndStartVpnFromProfile(profileId: String, startId: Int) {
        // A transient Keystore/EncryptedSharedPreferences failure (device just
        // unlocked, Direct Boot) used to throw straight out of onStartCommand and
        // crash the whole app on connect. Fail this start request cleanly instead.
        val profiles = try {
            SecureStorage.loadProfiles(this)
        } catch (e: Exception) {
            Log.e(TAG, "Secure storage unavailable: ${e.message}", e)
            lastStatusText = getString(R.string.status_storage_unavailable)
            uiState = UiState.DISCONNECTED
            postStatusCallback(false, lastStatusText)
            stopSelfCleanly(startId)
            return
        }
        val profile = profiles.find { it.id == profileId } ?: profiles.firstOrNull()
        if (profile == null) {
            Log.w(TAG, "loadAndStartVpnFromProfile: no profile for id=$profileId")
            lastStatusText = getString(R.string.status_disconnected)
            uiState = UiState.DISCONNECTED
            postStatusCallback(false, lastStatusText)
            stopSelfCleanly(startId)
            return
        }
        // Shared parser (same one MainActivity uses) — validates client_ip /
        // server_vpn_ip / prefix_len / mtu, so a malformed address can never reach
        // VpnService.Builder.addAddress() and crash the reconnect loop forever.
        val parsed = ConnectionKeyParser.parse(profile.key)
        if (parsed == null) {
            // A key that fails to parse is permanently invalid — retrying cannot help.
            Log.e(TAG, "Invalid connection key for profile id=${profile.id}")
            lastStatusText = "Invalid connection key"
            uiState = UiState.DISCONNECTED
            postStatusCallback(false, lastStatusText)
            stopSelfCleanly(startId)
            return
        }
        val mtlsCert: ByteArray? = profile.mtlsCertBase64?.let { b64 ->
            try { Base64.decode(b64, Base64.DEFAULT).takeIf { it.size == 104 } }
            catch (e: Exception) { Log.e(TAG, "mTLS cert decode failed: ${e.message}"); null }
        }
        startVpn(
            serverAddr      = parsed.server,
            serverKeyBase64 = parsed.serverKey,
            pskBase64       = parsed.psk,
            vpnIp           = parsed.vpnIp,
            serverVpnIp     = parsed.serverVpnIp,
            vpnPrefixLen    = parsed.prefixLen,
            vpnMtu          = parsed.mtu,
            mtlsCert        = mtlsCert,
            serverSigningKeyBase64 = parsed.serverSigningKey,
            dnsServers      = profile.dnsServers ?: emptyList(),
            preferredMask   = profile.maskProfile,
        )
    }

    // ──────────── Notifications ────────────

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        // Persistent low-importance channel for the ongoing foreground service notification.
        val tunnel = NotificationChannel(
            CHANNEL_ID, getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = getString(R.string.notification_channel_desc) }
        nm.createNotificationChannel(tunnel)
        // Separate default-importance channel for connect / disconnect events.
        val events = NotificationChannel(
            CHANNEL_EVENTS_ID, getString(R.string.notification_event_channel),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply { description = getString(R.string.notification_event_channel_desc) }
        nm.createNotificationChannel(events)
        // HIGH-importance channel for security alerts: the VPN died without the
        // user asking and traffic is no longer protected. Heads-up + sound.
        val alerts = NotificationChannel(
            CHANNEL_ALERTS_ID, getString(R.string.notification_alert_channel),
            NotificationManager.IMPORTANCE_HIGH
        ).apply { description = getString(R.string.notification_alert_channel_desc) }
        nm.createNotificationChannel(alerts)
    }

    /**
     * Posts a dismissible event notification (connect / disconnect).
     * Uses [CHANNEL_EVENTS_ID] which has DEFAULT importance so the device makes a sound.
     */
    private fun postEventNotification(text: String) {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL_EVENTS_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_EVENT_ID, notification)
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("AIVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
