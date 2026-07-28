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
        /**
         * R2 Phase B: 32-byte ed25519 verifying key for artifact-level MaskUpdate
         * signature verification (the "mop" connection-key field, mirrors desktop's
         * `--mask-operator-pubkey`), or null to skip. Distinct from [serverSigningKey]:
         * that authenticates "pushed by my server" (transport); this authenticates
         * "gated + signed by the operator" (artifact).
         */
        maskOperatorPubkey: ByteArray?,
        /**
         * Matching verification strictness: 0=off, 1=warn, 2=enforce (mirrors desktop's
         * `--mask-verify-mode`). Any other value is treated as warn.
         */
        maskVerifyMode: Int,
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

    /**
     * Adaptive level hint from server: 0–3 (0 = server says adaptive Off — a real
     * downgrade), or -1 when no hint has been received this session. Takes effect
     * on next reconnect.
     */
    external fun getAdaptiveLevelHint(): Int

    /**
     * VPN IPv4 the server assigned to this session in its ServerHello (dotted
     * quad), or "" when the current session has not received one. Differs from
     * the key-embedded IP after a pool re-home — the TUN must then be rebuilt
     * with this address or the server's anti-spoof check drops all uplink data.
     */
    external fun getAssignedVpnIp(): String

    /**
     * Returns `true` (and atomically clears the flag) if the server sent CertRejected
     * (mTLS client certificate rejected) at any point since the last call. Poll this
     * live during a session, like [getAssignedVpnIp] — the server keeps the tunnel up
     * while rejecting the cert rather than tearing it down, so waiting for [runTunnel]
     * to return would never observe it. A `true` result means the current certificate
     * will never be accepted by this server; prompt the user to re-provision.
     */
    external fun certRejected(): Boolean

    /**
     * Returns the `HandshakeReject` reason code (0=unspecified, 1=one-time key
     * already used, 2=client expired, 3=client disabled) and atomically clears
     * the pending flag, or -1 if no `HandshakeReject` has been observed since
     * the last call. Unlike [certRejected], this is a TERMINAL, authenticated
     * refusal — the server only ever sends it to a peer that already proved
     * PSK knowledge during the handshake — so the caller must STOP the
     * reconnect loop instead of backing off and retrying under the same
     * credential.
     */
    external fun handshakeRejectReason(): Int

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

    // ──────────── In-app admin: client management (P3.1) ────────────
    //
    // These three exports back the curated management-API client used by
    // [AdminApi] / [AdminActivity]. They operate on the currently-active tunnel
    // session (process-global, like the getters above) — there is no separate
    // "admin connection". Callers MUST check [isAvailable] first, same as any
    // other `external fun` on this object.

    /**
     * This device's role on the currently-configured identity: 0=User,
     * 1=Viewer, 2=Admin. Role is bound to the client's cryptographic identity
     * (set server-side) and is NOT assignable over the tunnel — there is no
     * corresponding setter here.
     */
    external fun getRole(): Int

    /**
     * Issues one request against the curated management API
     * (`/api/v1/clients`, `/api/v1/status`, `/api/v1/audit-log`, ...) over the
     * active tunnel session and blocks for up to ~10s waiting for the reply.
     *
     * @param method HTTP method byte: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.
     * @param path   Request path, e.g. "/api/v1/clients/{id}".
     * @param body   Request body bytes (JSON), or an empty array for methods
     *               without a body.
     * @return       `[status_hi, status_lo, ...response_body]` — a 2-byte
     *               big-endian HTTP status prefix followed by the response
     *               body bytes. An EMPTY array means the call did not
     *               complete (not connected / timed out) — callers must
     *               check `size < 2` before indexing. NULLABLE like the
     *               `String?` getters above: the Rust `make_bytes` helper
     *               returns a null jbyteArray rather than panicking across
     *               the FFI boundary when the JVM cannot allocate the array.
     */
    external fun mgmtRequest(method: Int, path: String, body: ByteArray): ByteArray?

    /**
     * Renders `text` (typically an `aivpn://...` connection key) as a PNG QR
     * code and returns the raw PNG bytes, or an empty array on failure (null
     * if the JVM array allocation itself failed — see [mgmtRequest]).
     * Decode with [android.graphics.BitmapFactory.decodeByteArray].
     */
    external fun qrPng(text: String): ByteArray?

    // ──────────── C2b: in-app SSH server installer (ssh-install feature) ────────────
    //
    // Backed by `aivpn-common::ssh_install` via the JNI bridge in
    // `aivpn-android-core/src/lib.rs` (`ssh-install` is a default feature of
    // that crate, so it ships in the standard .so build). These calls are
    // completely independent of the tunnel session used by [mgmtRequest] —
    // they open their own outbound SSH connection to the target host.

    /**
     * Connects to `host:port` as `user`, completes just enough of the SSH
     * handshake to read the server's host key, and returns its fingerprint
     * for TOFU confirmation before [sshInstallStart] is called with it.
     * Blocks the calling thread (spins up a throwaway single-thread tokio
     * runtime) — call off the UI thread.
     *
     * @return `"SHA256:..."` fingerprint, or `null` on any error (DNS/TCP/
     *         protocol failure, invalid port, bad UTF-8 in `host`/`user`).
     */
    external fun sshProbeHostkey(host: String, port: Int, user: String): String?

    /** SHA256 (hex) of the embedded `install-server.sh`, for display before running it. */
    external fun sshInstallScriptSha256(): String

    /** Full text of the embedded `install-server.sh`. */
    external fun sshInstallScript(): String

    /**
     * Parses `paramsJson` (host/port/user/auth/fingerprint/binary/mode/...
     * — see [AdminApi]/[InstallServerActivity] callers for the exact shape)
     * and, if valid, spawns a background thread that runs the installer,
     * returning immediately with a job handle to poll via [sshInstallPoll].
     *
     * @return job handle (>=1), or `-1` if `paramsJson` is malformed —
     *         in that case no job is created; nothing to poll or free.
     */
    external fun sshInstallStart(paramsJson: String): Long

    /**
     * Pops the next queued progress event for `handle` (JSON, one of the
     * `InstallEvent` shapes: `connected`/`uploading`/`line`/`marker`/`finished`).
     *
     * - An event is queued -> that event's JSON string.
     * - No event queued, job still running -> `null` — poll again later (~300ms).
     * - No event queued, job finished, OR `handle` unknown -> `""` — safe to
     *   call [sshInstallFree].
     */
    external fun sshInstallPoll(handle: Long): String?

    /**
     * Forgets `handle`, freeing its queued-events storage. Does NOT cancel an
     * in-flight install — if the background thread is still running it keeps
     * going, just becomes unobservable.
     *
     * @return `0` if a job was removed, `-1` if `handle` was already unknown.
     */
    external fun sshInstallFree(handle: Long): Int

    /**
     * Derives this device's X25519 public key from `privkeyB64` — the same 32-byte
     * device static private key ([SecureStorage.loadDeviceKey], base64 STANDARD-encoded
     * by the caller) already passed as `staticPrivkey` into [runTunnel] for JIT device
     * enrollment. Used by [InstallServerActivity] to populate `sshInstallStart`'s params
     * JSON `device_pubkey_b64` field when the user opts into device-bound admin install
     * (mirrors the desktop CLI's `--device-pubkey`).
     *
     * @param privkeyB64 32 raw bytes, base64 STANDARD (NOT `android.util.Base64.DEFAULT`,
     *                   which may insert newlines — re-encode if the source used a
     *                   different variant).
     * @return the base64 STANDARD-encoded public key, or `null` if `privkeyB64` is not
     *         valid base64 or does not decode to exactly 32 bytes. Never throws.
     */
    external fun devicePubkey(privkeyB64: String): String?
}
