#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Callback invoked from Rust when the VPN tunnel is ready (handshake complete).
/// @param host  NUL-terminated server hostname (valid only for the duration of the callback).
/// @param ctx   Opaque pointer passed back from aivpn_run_tunnel.
typedef void (*aivpn_ready_callback_t)(const char *host, void *ctx);

/// Run a full VPN tunnel session (blocks until done).
///
/// @param tun_fd         AF_UNIX SOCK_DGRAM socketpair fd (Rust reads/writes IP packets).
///                       Rust dups it internally — caller keeps ownership.
/// @param server_host    NUL-terminated server hostname or IP address.
/// @param server_port    UDP port.
/// @param server_key     32-byte server X25519 public key.
/// @param psk            32-byte pre-shared key, or NULL.
/// @param cert_bytes     104-byte mTLS client certificate blob, or NULL.
/// @param cert_len       Length of cert_bytes (104 or 0).
/// @param static_privkey  32-byte device static private key for JIT enrollment, or NULL.
/// @param adaptive_level  Adaptive mode level: 0=Off, 1=Light, 2=Aggressive, 3=Satellite.
/// @param on_ready        Callback invoked once the handshake succeeds (may be NULL).
/// @param ctx             Opaque pointer forwarded to on_ready (may be NULL).
/// @param server_signing_key  32-byte ed25519 verifying key used to authenticate the
///                       server's ServerHello signature, or NULL to skip verification
///                       (mirrors desktop's --server-signing-key; opt-in, same as
///                       desktop's behavior when no signing key is configured).
/// @param polymorphic_base  NUL-terminated base mask id (e.g. "webrtc_zoom_v3") to
///                       request a per-session polymorphic variant of, or NULL to
///                       disable (§3; mirrors desktop's --polymorphic-base).
/// @param share_mask_feedback  Non-zero to opt in to reporting mask success/fail
///                       outcomes to the server (§2; mirrors desktop's
///                       --share-mask-feedback). No effect unless country_code is
///                       also non-NULL. OFF by default (pass 0).
/// @param receive_mask_hints  Non-zero to opt in to accepting RegionalMaskHints
///                       pushed by the server (§2; mirrors desktop's
///                       --receive-mask-hints). OFF by default (pass 0).
/// @param country_code   NUL-terminated ISO-3166-1 alpha-2 country code (e.g. "US"),
///                       or NULL. Validated as exactly 2 ASCII letters on the Rust
///                       side; anything else is treated as not set.
/// @param prior_outcomes_json  NUL-terminated JSON array of prior (unreported) mask
///                       outcomes the platform has persisted across earlier
///                       failed/succeeded attempts, e.g.
///                       `[{"mask_id":"quic_https","success":2,"fail":1}]`, or
///                       NULL/empty for none. Merged with a success entry for THIS
///                       attempt's mask family and reported as one MaskFeedback on
///                       success (§2; mirrors desktop's
///                       MaskFeedbackLog::aggregate_unreported — persistence itself
///                       lives in the platform layer, not this core). Malformed
///                       JSON collapses to an empty batch, never an error.
/// @param preferred_mask  NUL-terminated preset mask id (e.g. "webrtc_zoom_v3") the
///                       mask picker selected, or NULL/empty/"auto" for the
///                       PSK-derived bootstrap mask. Mirrors Android's
///                       preferred_mask; shapes the handshake + opening burst.
/// @param cached_descriptors_json  NUL-terminated JSON array of app-persisted,
///                       ed25519-signed BootstrapDescriptors saved from a prior
///                       session, or NULL/empty for none. Signature-verified and
///                       validity-filtered, then loaded into the descriptor
///                       store BEFORE the handshake so a COLD-START first
///                       handshake is shaped with a COVERT rotated descriptor
///                       mask instead of a public preset (mirrors desktop
///                       bootstrap_cache::select_initial_mask; persistence lives
///                       in the Swift App Group layer). A truly-first-ever
///                       connect with no persisted descriptor still uses the
///                       preset.
/// @param mask_operator_pubkey  Optional 32-byte ed25519 verifying key used to
///                       check the embedded operator signature on mask
///                       artifacts pushed via MaskUpdate (R2 Phase B), or NULL
///                       to leave it unconfigured (mirrors desktop's
///                       --mask-operator-pubkey / config-file / connection-key
///                       "mop" field precedence — the Swift layer resolves
///                       which source wins before this call).
/// @param mask_verify_mode  Optional NUL-terminated verification mode string
///                       ("off"|"warn"|"enforce", case-insensitive), or
///                       NULL/empty/unrecognized for the default ("warn" —
///                       same default desktop uses with no override
///                       configured). Never fails the call on a bad string.
/// @return 0 on a clean rekey-triggered exit, -1 on error.
int aivpn_run_tunnel(
    int tun_fd,
    const char *server_host,
    int server_port,
    const uint8_t *server_key,
    const uint8_t *psk,
    const uint8_t *cert_bytes,
    int cert_len,
    const uint8_t *static_privkey,
    int static_privkey_len,
    int adaptive_level,
    aivpn_ready_callback_t on_ready,
    void *ctx,
    const uint8_t *server_signing_key,
    const char *polymorphic_base,
    int share_mask_feedback,
    int receive_mask_hints,
    const char *country_code,
    const char *prior_outcomes_json,
    const char *preferred_mask,
    const char *cached_descriptors_json,
    const uint8_t *mask_operator_pubkey,
    const char *mask_verify_mode
);

/// Close the active UDP socket so the tunnel loop exits immediately.
/// Safe to call from any thread.
void aivpn_stop_tunnel(void);

/// Clear a stop that arrived while no session was active (STOP_PENDING), so a
/// stale stop from a previously aborted setup cannot immediately abort a fresh
/// connection. Call at the start of startTunnel, before aivpn_run_tunnel
/// (mirrors Android's clearPendingStop). Safe to call from any thread.
void aivpn_clear_pending_stop(void);

/// Total bytes sent to the server in the current session.
int64_t aivpn_get_upload_bytes(void);

/// Total bytes received from the server in the current session.
int64_t aivpn_get_download_bytes(void);

/// Wall-clock epoch milliseconds at which the current session became
/// established, or 0 when no session is active. Same session scope as the
/// byte counters, so the UI stopwatch can never desync from them.
int64_t aivpn_get_connected_since_ms(void);

/// Current connection quality score (0–100). Returns 0 when no session is active.
int aivpn_get_quality_score(void);

/// Most recent AdaptiveHint level received from the server (0–3).
int aivpn_get_adaptive_level_hint(void);

/// VPN IPv4 the server assigned to this session in its ServerHello network
/// config, as a host-order u32 (10.0.0.3 = 0x0A000003), or 0 when none has
/// been received this session. Differs from the connection-key IP after a
/// pool re-home — re-apply tunnel network settings with this address or the
/// server's anti-spoof check silently drops all uplink data.
unsigned int aivpn_get_assigned_vpn_ip(void);

/// Monotonically increasing counter, bumped each time new mask-recording
/// feedback (RecordingAck/RecordingComplete/RecordingFailed/RecordingStatus)
/// arrives from the server. Compare against the last-seen value to detect a
/// fresh message before re-reading kind/confidence/message.
int64_t aivpn_get_recording_feedback_seq(void);

/// Kind of the most recent mask-recording feedback message.
/// 0 = none received yet, 1 = RecordingAck, 2 = RecordingComplete,
/// 3 = RecordingFailed, 4 = RecordingStatus.
int aivpn_get_recording_feedback_kind(void);

/// Confidence score (0.0-1.0) from the most recent RecordingComplete message.
/// Returns 0.0 if the current feedback is not a RecordingComplete.
float aivpn_get_recording_confidence(void);

/// Whether the current authenticated session may record masks, from the most
/// recent RecordingStatus message. Returns 0 if no RecordingStatus has been
/// received yet.
int aivpn_recording_can_record(void);

/// Copies the 16-byte recording session id from the most recent RecordingAck
/// message into `out16`. Returns 1 if the current feedback is a RecordingAck
/// (buffer populated), 0 otherwise (buffer left untouched).
/// @param out16 Buffer to receive the 16-byte session id; must point to at
///              least 16 writable bytes.
int aivpn_get_recording_session_id(uint8_t *out16);

/// Copies the service name associated with the most recent recording
/// feedback into `buf` as a NUL-terminated UTF-8 string, truncated to fit:
/// the service that finished recording (RecordingComplete), or the service
/// currently being recorded, if any (RecordingStatus). Empty string for
/// RecordingAck/RecordingFailed.
/// @param buf      Buffer to receive the NUL-terminated string; must point
///                  to at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if
///         buf is NULL, buf_len <= 0, or no feedback has been received yet.
int aivpn_get_recording_service(char *buf, int buf_len);

/// Copies a human-readable message for the most recent recording feedback
/// into `buf` as a NUL-terminated UTF-8 string, truncated to fit:
///  - RecordingAck      -> the status string ("started", "analyzing", ...)
///  - RecordingComplete -> the mask_id
///  - RecordingFailed   -> the failure reason
///  - RecordingStatus   -> the active_service name, or an empty string if None
/// @param buf      Buffer to receive the NUL-terminated string; must point
///                  to at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if
///         buf is NULL, buf_len <= 0, or no feedback has been received yet.
int aivpn_get_recording_message(char *buf, int buf_len);

/// Send RecordingStart to the active tunnel. Returns 1 on success, 0 if not connected.
/// @param service NUL-terminated service name string (truncated to 128 chars).
int aivpn_start_recording(const char *service);

/// Send RecordingStop to the active tunnel.
void aivpn_stop_recording(void);

/// Seed the process-global consecutive handshake-fail streak from a
/// platform-persisted value. The streak drives the descriptor→builtin-preset
/// fallback; it lives in a process-global static, but iOS tears the Network
/// Extension process down between failed starts, so without re-seeding the
/// fallback threshold could never be reached and a poisoned cached descriptor
/// would block connecting until it expires. Call ONCE per extension process,
/// before the first aivpn_run_tunnel attempt, with the value previously read
/// via aivpn_get_handshake_fail_streak and persisted per server. Clamped
/// internally against corrupted persisted values.
void aivpn_seed_handshake_fail_streak(unsigned int streak);

/// Current consecutive handshake-fail streak (see
/// aivpn_seed_handshake_fail_streak). Read after each aivpn_run_tunnel return
/// and persist per server; reset to 0 internally when a session's PFS ratchet
/// completes and when the server key changes.
unsigned int aivpn_get_handshake_fail_streak(void);

/// §2 crowdsourced blocking feedback — whether the most recently completed
/// aivpn_run_tunnel call ever reached a connected (post-handshake, PFS ratchet
/// complete) state. Read immediately after the call returns: 0 means the
/// attempt never connected, so the platform should count it toward
/// aivpn_get_feedback_threshold() consecutive failures for
/// aivpn_get_attempted_mask_family() (mirrors desktop main.rs's
/// client.ever_connected() check in the reconnect loop).
int aivpn_ever_connected(void);

/// Whether the server sent CertRejected (mTLS certificate rejected) during the
/// most recently completed aivpn_run_tunnel call. 0 = not rejected (or no
/// mTLS cert was configured). Poll alongside get_traffic and, when 1, prompt
/// the user to re-provision their mTLS cert instead of retrying forever in
/// silence.
int aivpn_cert_was_rejected(void);

/// Whether the server sent HandshakeReject (an AEAD-authenticated,
/// handshake-time refusal sent only to a peer that already proved knowledge
/// of the PSK) during the most recently completed aivpn_run_tunnel call.
/// 0 = not rejected. Unlike a timeout or transient disconnect this is a
/// TERMINAL refusal — the platform must stop its reconnect loop instead of
/// retrying. Poll alongside get_traffic and, when 1, show the user the
/// reason from aivpn_get_handshake_reject_reason() and stop reconnecting.
int aivpn_handshake_was_rejected(void);

/// Reason code for the most recent HandshakeReject (only meaningful when
/// aivpn_handshake_was_rejected() returns non-zero). 0 = unspecified,
/// 1 = one-time key already used, 2 = client expired, 3 = client disabled.
int aivpn_get_handshake_reject_reason(void);

/// §2 crowdsourced blocking feedback — whether a MaskFeedback control message
/// was actually sent during the most recently completed aivpn_run_tunnel call
/// (a share send or a hints-only probe). Use to decide whether to clear the
/// persisted outcome buffer and record a new last-report timestamp (mirrors
/// desktop's MaskFeedbackLog::mark_reported).
int aivpn_mask_feedback_sent(void);

/// §2 crowdsourced blocking feedback — server-pushed
/// FeedbackConfig.report_failure_threshold received during the most recently
/// completed aivpn_run_tunnel call. Returns 0 if no FeedbackConfig was
/// received this session — the platform should keep whichever value it had
/// previously persisted (defaulting to 3 if none).
int aivpn_get_feedback_threshold(void);

/// §2 crowdsourced blocking feedback — server-pushed
/// FeedbackConfig.report_interval_secs received during the most recently
/// completed aivpn_run_tunnel call. Returns 0 if no FeedbackConfig was
/// received this session — the platform should keep whichever value it had
/// previously persisted (defaulting to 3600 if none).
int64_t aivpn_get_feedback_interval_secs(void);

/// §2 crowdsourced blocking feedback — copies the base mask family (already
/// normalized, e.g. "webrtc_zoom_v3") that the most recently completed
/// aivpn_run_tunnel call attempted, into buf as a NUL-terminated UTF-8
/// string, truncated to fit. Set as soon as the mask is chosen — before the
/// handshake — so it is populated even when the attempt never reaches
/// aivpn_ever_connected(). Needed because mask selection (including the
/// AIVPN_PREFERRED_MASK=auto PSK-derived pick) happens inside this one-shot
/// call; the platform has no other way to learn which family a failed "auto"
/// attempt used.
/// @param buf      Buffer to receive the NUL-terminated string; must point
///                  to at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if
///         buf is NULL, buf_len <= 0, or no attempt has run yet.
int aivpn_get_attempted_mask_family(char *buf, int buf_len);

/// §2 crowdsourced blocking feedback — monotonically increasing counter,
/// bumped each time a new RegionalMaskHints message is received (only when
/// receive_mask_hints was enabled for that call). Compare against the
/// last-seen value before re-reading via aivpn_get_regional_hints_json.
int64_t aivpn_get_regional_hints_seq(void);

/// §2 crowdsourced blocking feedback — copies the most recently received
/// RegionalMaskHints as a JSON object
/// (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`) into buf
/// as a NUL-terminated UTF-8 string, truncated to fit. The platform should
/// persist this per-region and use it to softly bias mask selection
/// (AIVPN_PREFERRED_MASK) on the next reconnect attempt, never overriding an
/// explicit user mask choice (mirrors desktop's HINT_BIAS_MIN_SCORE gate).
/// @param buf      Buffer to receive the NUL-terminated string; must point
///                  to at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if
///         buf is NULL, buf_len <= 0, or no hints have been received yet.
int aivpn_get_regional_hints_json(char *buf, int buf_len);

/// Monotonically increasing counter, bumped each time a fresh MaskCatalog is
/// received from the server. Compare against the last-seen value before
/// re-reading via aivpn_get_mask_catalog_json.
int64_t aivpn_get_mask_catalog_seq(void);

/// Copies the most recent MaskCatalog as a JSON array
/// (`[{"mask_id":"auto_quic_v1","label":"QUIC","generated":true},...]`) into
/// buf as a NUL-terminated UTF-8 string, truncated to fit. The mask Picker
/// renders this list and appends "(auto)" to entries with generated:true.
/// @param buf      Buffer to receive the NUL-terminated string; must point
///                  to at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if
///         buf is NULL, buf_len <= 0, or no catalog has been received yet.
int aivpn_get_mask_catalog_json(char *buf, int buf_len);

/// Copies the currently-stored bootstrap descriptors as a JSON array into `buf`
/// as a NUL-terminated UTF-8 string, truncated to fit. Swift persists this into
/// the shared App Group so the very next COLD START can pass it back into
/// aivpn_run_tunnel(cached_descriptors_json=…) and shape its first handshake
/// with a COVERT rotated descriptor mask instead of a public preset. The blobs
/// are ed25519-signed and self-authenticating and are re-verified on load.
/// Poll after aivpn_run_tunnel returns (the store is process-global and
/// survives the call).
/// @param buf      Buffer to receive the NUL-terminated string; must point to
///                  at least buf_len writable bytes.
/// @param buf_len  Size of buf in bytes.
/// @return Number of bytes written excluding the NUL terminator, or -1 if buf
///         is NULL or buf_len <= 0. Writes "[]" when the store is empty.
int aivpn_get_bootstrap_descriptors_json(char *buf, int buf_len);

/// Verify a bootstrap descriptor fetched by the main app's multi-channel
/// discovery flow (CDN/GitHub/Telegram) — NOT called from the tunnel
/// extension. Has no dependency on any active tunnel/session state, so it is
/// safe to call at any time, from any thread, before a VPN profile exists.
///
/// @param descriptor_json  Pointer to a single JSON-encoded BootstrapDescriptor
///                         object (not a JSON array — callers must iterate the
///                         fetched array and call this once per element).
/// @param descriptor_json_len  Length in bytes of descriptor_json.
/// @param signing_pubkey   Pointer to exactly 32 bytes: the operator's
///                         ed25519 verifying key.
/// @return 1 if the descriptor's JSON parses, is not expired, and its
///         signature verifies against signing_pubkey. 0 for any failure
///         (malformed JSON, null/invalid pointers, bad signature, expired).
///         Never panics/crashes across the FFI boundary.
int aivpn_verify_bootstrap_descriptor(
    const uint8_t *descriptor_json,
    size_t descriptor_json_len,
    const uint8_t *signing_pubkey
);

/// Current server-assigned role (0=User, 1=Viewer, 2=Admin) cached from the
/// most recent Capabilities control message this session, or 0 (User)
/// before one has arrived. Reset at the start of each aivpn_run_tunnel
/// attempt.
uint8_t aivpn_get_role(void);

/// Issue an in-tunnel management API call (Phase A in-app admin) and block
/// until the correlated response arrives or the call times out (10s).
///
/// @param method      0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.
/// @param path         NUL-terminated, curated REST-shaped path (e.g.
///                     "/api/v1/clients").
/// @param body         Optional JSON request payload, or NULL for none.
/// @param body_len     Length of body in bytes (0 if body is NULL).
/// @param out_status   Receives the response status code on success. Must
///                     point to a writable uint16_t.
/// @param out_buf      Buffer to receive the response body bytes (NOT
///                     NUL-terminated — it is arbitrary JSON, not a C
///                     string). May be NULL only if out_cap is 0.
/// @param out_cap      Size of out_buf in bytes.
/// @return Buffer convention shared with aivpn_qr_png: if the response body
///         fits in out_cap, it is copied into out_buf and the number of
///         bytes written is returned (always <= out_cap). If it does not
///         fit, out_buf is left untouched and the needed length is
///         returned instead (always > out_cap) — the caller distinguishes
///         the two cases by comparing the return value against the
///         out_cap it passed in, then retries with a buffer of at least
///         that size. Returns -1 on any error: NULL/invalid path, no
///         active tunnel session, the control channel is closed, or the
///         call times out awaiting a response.
intptr_t aivpn_mgmt_request(
    uint8_t method,
    const char *path,
    const uint8_t *body,
    size_t body_len,
    uint16_t *out_status,
    uint8_t *out_buf,
    size_t out_cap
);

/// Render `text` (typically an aivpn://... connection key) as a QR code PNG
/// and copy the encoded bytes into out_buf.
///
/// @param text     NUL-terminated, valid-UTF-8 string to encode.
/// @param out_buf  Buffer to receive the PNG bytes. May be NULL only if
///                 out_cap is 0.
/// @param out_cap  Size of out_buf in bytes.
/// @return Same written-len-or-needed-len convention as
///         aivpn_mgmt_request: the number of PNG bytes written when out_cap
///         was large enough, or the needed length (out_buf left untouched)
///         otherwise. Returns -1 if text is NULL/not valid UTF-8/empty, or
///         PNG encoding fails.
intptr_t aivpn_qr_png(
    const char *text,
    uint8_t *out_buf,
    size_t out_cap
);

#ifdef __cplusplus
}
#endif
