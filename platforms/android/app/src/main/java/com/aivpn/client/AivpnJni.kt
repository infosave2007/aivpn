package com.aivpn.client

import android.net.VpnService

/**
 * JNI bridge to the native Rust core (libaivpn_core.so).
 *
 * The library is cross-compiled for arm64-v8a / armeabi-v7a / x86_64 and placed in
 * app/src/main/jniLibs/ by build-rust-android.sh.
 */
object AivpnJni {

    /**
     * Non-null when libaivpn_core.so failed to load (missing ABI split, corrupted
     * install, stripped .so). [System.loadLibrary] throws [UnsatisfiedLinkError],
     * which is an [Error] (LinkageError), NOT an [Exception] — an unguarded `init`
     * block would turn the very first touch of this object into an app crash
     * (ExceptionInInitializerError) that no `catch (e: Exception)` can intercept.
     *
     * Callers MUST check [isAvailable] before invoking any `external fun`;
     * calling one while the library is not loaded still throws
     * [UnsatisfiedLinkError] at the call site.
     */
    @Volatile
    var loadError: String? = null
        private set

    val isAvailable: Boolean
        get() = loadError == null

    init {
        try {
            System.loadLibrary("aivpn_core")
        } catch (t: Throwable) { // UnsatisfiedLinkError is an Error, not an Exception
            loadError = "${t.javaClass.simpleName}: ${t.message}"
            android.util.Log.e("AivpnJni", "Failed to load libaivpn_core.so", t)
        }
    }

    /**
     * Runs a full VPN tunnel session on the calling thread (blocks until done).
     *
     * @param vpnService  The VpnService instance — used to call `protect(int)` on the UDP socket.
     * @param tunFd       Borrowed raw TUN file descriptor ([android.os.ParcelFileDescriptor.getFd]
     *                    on the still-owned descriptor — NOT `detachFd`). Rust `dup(2)`s it
     *                    internally (android_tunnel.rs) and only ever closes its own duplicate;
     *                    the Kotlin side retains ownership of the original and closes it via
     *                    `ParcelFileDescriptor.close()` when the VPN interface is torn down.
     * @param serverHost  Server hostname or IP.
     * @param serverPort  Server UDP port.
     * @param serverKey   32-byte server X25519 public key.
     * @param psk         32-byte pre-shared key or `null`.
     * @return            Empty string on a clean rekey-triggered exit, error message otherwise.
     */
    /**
     * adaptiveLevel: 0=Off, 1=Light (keepalive 6s), 2=Aggressive (4s), 3=Satellite (15s).
     * The level controls keepalive interval and FEC group size.
     */
    external fun runTunnel(
        vpnService: VpnService,
        tunFd: Int,
        serverHost: String,
        serverPort: Int,
        serverKey: ByteArray,
        psk: ByteArray?,
        mtlsCert: ByteArray?,
        adaptiveLevel: Int,
        staticPrivkey: ByteArray?,
        maskProfile: String?,
        serverSigningKey: ByteArray?,
        /** §3 Polymorphic masks: base mask id to request a per-session unique variant of, or null. */
        polymorphicBase: String?,
        /** §2 crowdsourced blocking feedback (opt-in): report mask success/fail outcomes. */
        shareMaskFeedback: Boolean,
        /** §2 crowdsourced blocking feedback (opt-in): accept server regional mask hints. */
        receiveMaskHints: Boolean,
        /** §2 crowdsourced blocking feedback: 2-letter ISO-3166-1 alpha-2 country code, or null. */
        countryCode: String?,
        /**
         * §2 crowdsourced blocking feedback: JSON array of prior (unreported) mask
         * outcomes persisted across earlier failed/succeeded attempts, e.g.
         * `[{"mask_id":"quic_https","success":2,"fail":1}]`, or null/empty for none.
         * Merged with a success entry for THIS attempt's mask family and reported as
         * one MaskFeedback on success. Malformed JSON collapses to an empty batch.
         */
        priorOutcomesJson: String?,
        /**
         * App-persisted, ed25519-signed bootstrap descriptors as a JSON array
         * (saved from a prior session's BootstrapDescriptorUpdate messages), or
         * null/empty for none. Signature-verified and validity-filtered on the
         * Rust side, then loaded into the descriptor store BEFORE the handshake
         * so a COLD-START first handshake is shaped with a COVERT rotated
         * descriptor mask instead of a fingerprintable public preset. A
         * truly-first-ever connect (no cached descriptor yet) still uses the
         * preset.
         */
        cachedDescriptorsJson: String?,
    ): String

    /**
     * Returns the currently-stored bootstrap descriptors as a JSON array so the
     * caller can persist them across process restarts and pass them back into
     * [runTunnel] via `cachedDescriptorsJson` on the next connect. Returns "[]"
     * when the store is empty. Poll after [runTunnel] returns — the descriptor
     * store is process-global and survives the call.
     */
    external fun getBootstrapDescriptorsJson(): String

    /**
     * `true` when the last session proved its cached bootstrap descriptors are
     * unusable against this server: the handshake was accepted but not a single
     * downlink DATA packet ever arrived. The persisted blob for that server must
     * then be deleted, otherwise the next cold start reloads the same descriptor
     * and reconnects into the same dead data plane (issue #71 — today only
     * clearing app data breaks the loop, and only for one connection).
     *
     * Poll once after [runTunnel] returns; reading clears the flag.
     */
    external fun getDiscardPersistedDescriptors(): Boolean

    /**
     * Closes the protected UDP socket so the tunnel loop exits immediately.
     * Safe to call from any thread, including the NetworkCallback.
     */
    external fun stopTunnel()

    /**
     * Clears the STOP_PENDING flag set by [stopTunnel] when no session was active.
     * Must be called in the restartJob after [Job.cancelAndJoin] and before launching
     * the new connection so the intentional new session is not immediately stopped.
     */
    external fun clearPendingStop()

    /** Total bytes written to the server UDP socket in the current session. */
    external fun getUploadBytes(): Long

    /** Total bytes written to the TUN interface in the current session. */
    external fun getDownloadBytes(): Long

    /** Connection quality score 0–100 from last KeepaliveAck RTT. 0 = no data yet. */
    external fun getQualityScore(): Int

    /** Adaptive level hint from server (0–3). 0 = no hint received. Takes effect on next reconnect. */
    external fun getAdaptiveLevelHint(): Int

    // ──────────── §2 crowdsourced blocking feedback getters ────────────
    //
    // `runTunnel` handles exactly one connection attempt per call, so this
    // service (which owns the reconnect loop and cross-attempt persistence)
    // polls these once the blocking call returns to learn the outcome, then
    // persists across attempts itself (see AivpnService.kt).

    /**
     * Whether the most recently completed [runTunnel] call ever reached a
     * connected (post-handshake, PFS ratchet complete) state. `false` means
     * the attempt never connected, so the caller should count it toward
     * [getFeedbackThreshold] consecutive failures for [getAttemptedMaskFamily].
     */
    external fun everConnected(): Boolean

    /**
     * Whether a MaskFeedback control message (share entries or a hints-only
     * probe) was actually sent during the most recently completed [runTunnel]
     * call. Used to decide whether to clear the persisted outcome buffer and
     * record a new last-report timestamp.
     */
    external fun wasMaskFeedbackSent(): Boolean

    /**
     * Server-pushed FeedbackConfig.report_failure_threshold from the most
     * recently completed [runTunnel] call, or 0 if no FeedbackConfig was
     * received this session — the caller should keep whichever value it had
     * previously persisted (defaulting to 3 if none).
     */
    external fun getFeedbackThreshold(): Int

    /**
     * Server-pushed FeedbackConfig.report_interval_secs from the most recently
     * completed [runTunnel] call, or 0 if no FeedbackConfig was received this
     * session — the caller should keep whichever value it had previously
     * persisted (defaulting to 3600 if none).
     */
    external fun getFeedbackIntervalSecs(): Long

    /**
     * Base mask family (already normalized, e.g. "webrtc_zoom_v3") that the
     * most recently completed [runTunnel] call attempted, or "" if no attempt
     * has run yet. Set as soon as the mask is chosen — before the handshake —
     * so it is populated even when the attempt never reaches [everConnected].
     */
    external fun getAttemptedMaskFamily(): String

    /**
     * Monotonically increasing counter, bumped each time a new
     * RegionalMaskHints message is received (only when `receiveMaskHints` was
     * enabled for that call). Compare against the last-seen value before
     * re-reading via [getRegionalHintsJson].
     */
    external fun getRegionalHintsSeq(): Long

    /**
     * Most recently received RegionalMaskHints as a JSON object
     * (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`), or ""
     * if no hints have been received yet.
     */
    external fun getRegionalHintsJson(): String

    /**
     * Monotonic counter bumped each time a fresh MaskCatalog is received, so the
     * UI can detect a new list before re-reading [getMaskCatalogJson].
     */
    external fun getMaskCatalogSeq(): Long

    /**
     * Most recent server-pushed MaskCatalog as a JSON array
     * (`[{"mask_id","label","generated"},...]`), or "" if none received yet.
     * The mask spinner renders this list and marks generated masks "(авто)".
     */
    external fun getMaskCatalogJson(): String

    /** Send RecordingStart to the server. Returns 1 if queued, 0 if no active session. */
    external fun startRecording(serviceName: String): Int

    /** Send RecordingStop to the server. No-op if no active session. */
    external fun stopRecording()

    /**
     * Returns (and clears) the most recent recording-related feedback message
     * from the server as a JSON string, or "" if nothing is pending.
     *
     * JSON shapes (matched on the "type" field):
     *   {"type":"ack","status":"started"|"analyzing"}
     *   {"type":"complete","mask_id":"...","confidence":0.87}
     *   {"type":"failed","reason":"..."}
     *   {"type":"status","can_record":true,"active_service":"zoom"|null}
     */
    external fun getRecordingFeedback(): String

    /**
     * Verifies a single bootstrap descriptor (JSON-encoded) fetched by
     * [BootstrapDiscovery] against an operator-supplied ed25519 signing public key,
     * and checks it hasn't expired as of [nowUnixSecs]. Never throws.
     */
    external fun verifyBootstrapDescriptor(
        descriptorJson: String,
        signingPublicKey: ByteArray,
        nowUnixSecs: Long,
    ): Boolean
}
