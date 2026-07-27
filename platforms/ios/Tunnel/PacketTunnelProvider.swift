import NetworkExtension
import Network
import Darwin
import Security
import os.log

// PacketTunnelProvider bridges NEPacketTunnelProvider to the Rust aivpn-ios-core
// static library via a socketpair.
//
// Data path:
//   packetFlow ↔ sp[0]  (Swift bridge loops)
//              sp[1]  (Rust dup()s on entry, owns its copy)
//
// IPC from the main app arrives via handleAppMessage(_:completionHandler:).

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var sp: [Int32] = [-1, -1]
    private var rustThread: Thread?
    // Outbound bridge: event-driven read source on sp[0]. Created, fired and
    // cancelled on bridgeQueue; its cancel handler owns closing sp[0].
    private var outboundSource: DispatchSourceRead?
    // isStopped is read on the cooperative thread pool (Task.detached) and written
    // on the extension main thread (stopTunnel). Protect it with a lock.
    private let stopLock = NSLock()
    private var _isStopped = false
    private var isStopped: Bool {
        get { stopLock.withLock { _isStopped } }
        set { stopLock.withLock { _isStopped = newValue } }
    }
    /// Atomically flips isStopped to true and returns the PREVIOUS value, so
    /// error paths can distinguish "this path initiated the stop" (false)
    /// from "a stop was already in progress" (true) without a
    /// check-then-set race against stopTunnel.
    private func markStopped() -> Bool {
        stopLock.withLock {
            let was = _isStopped
            _isStopped = true
            return was
        }
    }
    private let appGroup = "group.com.aivpn.client"
    private var canRecord: Bool = false
    private let bridgeQueue = DispatchQueue(label: "com.aivpn.tunnel.bridge")
    private var recordingPhase: String = "idle"
    private var recordingServiceName: String = ""
    private var preferredMask: String = "auto"
    // M1: the persisted App-Group descriptor blob is scoped PER SERVER (keyed by a
    // suffix derived from the server pubkey) so switching profiles never loads
    // another server's descriptors — which would invert the covertness benefit and
    // can mis-frame server B's opening packet. Set from the connection key's server
    // pubkey in startTunnel; defaults to the legacy global key until then.
    private var descriptorStoreKey: String = PacketTunnelProvider.bootstrapDescriptorsKey
    // §3 Polymorphic masks / §2 crowdsourced mask feedback — threaded through
    // providerConfiguration exactly like preferredMask above (see VPNManager.swift
    // connect() and startTunnel() below), then forwarded to the Rust FFI.
    private var polymorphicBase: String?
    private var shareMaskFeedback: Bool = false
    private var receiveMaskHints: Bool = false
    private var countryCode: String = ""
    // Mask-recording feedback from the server (RecordingAck/RecordingComplete/
    // RecordingFailed/RecordingStatus), surfaced via the aivpn_get_recording_*
    // FFI getters in aivpn-ios-core and polled from the get_traffic handler.
    // Pool re-home healing: the address the tunnel settings were applied with,
    // the parameters needed to rebuild them, and the watcher that polls the
    // Rust core for a server-assigned IP differing from the connection-key IP.
    private var appliedVpnIP: String = ""
    private var settingsServerHost: String = ""
    private var settingsFullTunnel: Bool = false
    private var settingsExcludedRoutes: [String] = []
    private var settingsExcludedDomains: [String] = []
    private var settingsAdaptiveLevel: Int = 0
    private var settingsKillSwitch: Bool = false
    private var rehomeWatch: DispatchSourceTimer?
    private static let vpnIpOverridePrefix = "vpn_ip_override_"
    // C1/H2: in-extension reconnect support. The Rust core's resilience
    // statics (HANDSHAKE_FAIL_STREAK, LAST_GOOD_MASK, …) are process-local
    // and only do their job across MULTIPLE aivpn_run_tunnel calls in the
    // SAME process — so the extension runs a bounded retry loop (see the
    // thread body in startTunnel) instead of dying on the first session
    // error, and persists the handshake-fail streak per server in the App
    // Group so even a process teardown between failed starts cannot keep the
    // descriptor→preset fallback threshold forever out of reach.
    private var failStreakKey: String = PacketTunnelProvider.handshakeFailStreakBaseKey
    // H2: interface-change watcher — on a meaningful path change the current
    // Rust session is stopped so the retry loop reconnects on the new path
    // immediately instead of waiting out the RX-silence watchdogs.
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String?
    // L5: count of inbound (packetFlow → Rust) packets dropped because the
    // bridge socket buffer was full (write() EAGAIN). Debug visibility only.
    // Touched exclusively on bridgeQueue.
    private var inboundDropCount: UInt64 = 0
    private var recordingMaskId: String = ""
    private var recordingFailureReason: String = ""
    private var lastSeenRecordingFeedbackSeq: Int64 = 0

    // Public DNS fallback used alongside the VPN's internal resolver (the .1 of the
    // assigned VPN /24 — see buildSettings/slash24Prefix) so that
    // hostnames outside the VPN's own zone still resolve in full-tunnel mode. There is no
    // field for this in the connection key / providerConfiguration today (see
    // ConnectionKey.swift, network_config.rs) — adding one would be a wire-format change
    // spanning every platform, which is out of scope here. Named as a constant so the
    // literal isn't duplicated/buried, and so a future config-driven value is a one-line change.
    private static let fallbackPublicDNS = "1.1.1.1"

    // MARK: - Start

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // A stop that raced a previous (aborted) setup can leave the Rust core's
        // STOP_PENDING flag set; activate_session() would propagate it into this
        // fresh session and kill it immediately. This start is an intentional new
        // connection, so clear the stale flag first (mirrors Android's
        // clearPendingStop-on-connect).
        aivpn_clear_pending_stop()

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let cfg   = proto.providerConfiguration else {
            completionHandler(makeError("missing provider configuration"))
            return
        }
        // Resolve the connection key.
        // Priority order:
        //   1. One-time handoff token from providerConfiguration — a token that is
        //      still retrievable means the app just wrote a FRESH key for this
        //      start (new profile / changed server). It must win over any
        //      previously persisted key, otherwise switching profiles would be
        //      silently ignored forever after the first successful start.
        //   2. Persistent Keychain entry — written on every successful resolution
        //      below. Covers tunnel reassertion (WiFi→cellular, signal loss) where
        //      providerConfiguration is replayed but the one-time token has
        //      already been consumed.
        //   3. Direct embed in providerConfiguration as final fallback (also
        //      fresh from the current connect(), so it overwrites the persistent
        //      copy too).
        let keyStr: String
        if let token = cfg["keyToken"] as? String,
           let secret = retrieveHandoffSecret(token: token) {
            keyStr = secret
            storePersistentKey(secret)
        } else if let persistent = retrievePersistentKey() {
            keyStr = persistent
        } else if let direct = cfg["keyDirect"] as? String, !direct.isEmpty {
            keyStr = direct
            storePersistentKey(direct)
        } else {
            completionHandler(makeError("missing connection key"))
            return
        }

        let fullTunnel = cfg["fullTunnel"] as? Bool ?? true
        let adaptiveLevel = cfg["adaptiveLevel"] as? Int ?? 0
        let killSwitch = cfg["killSwitch"] as? Bool ?? false
        self.preferredMask = cfg["preferred_mask"] as? String ?? "auto"
        self.polymorphicBase = cfg["polymorphic_base"] as? String
        self.shareMaskFeedback = cfg["share_mask_feedback"] as? Bool ?? false
        self.receiveMaskHints = cfg["receive_mask_hints"] as? Bool ?? false
        self.countryCode = cfg["country_code"] as? String ?? ""

        // Split-tunnel lists forwarded by VPNManager from App Group UserDefaults.
        let excludedRoutes = (cfg["excluded_routes"] as? String ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let excludedDomains = (cfg["excluded_domains"] as? String ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard let key = TunnelConnectionKey(rawKey: keyStr) else {
            completionHandler(makeError("invalid connection key"))
            return
        }
        self.canRecord = key.canRecord ?? false

        // M1: scope the persisted descriptor blob to THIS server so a profile switch
        // never loads another server's descriptors.
        self.descriptorStoreKey = Self.perServerDescriptorsKey(key.serverKey)
        // C1: the handshake-fail streak is scoped per server the same way —
        // server B must not start at server A's fallback threshold.
        self.failStreakKey = Self.perServerFailStreakKey(key.serverKey)
        // M3: if the connection key carried freshly-discovered descriptors ("bd",
        // written by BootstrapDiscovery) and this server has none cached yet, seed
        // the per-server App-Group blob so the VERY FIRST connect to this server is
        // covert instead of using a public preset. `descriptorsJson` is already a
        // validated JSON array string (see TunnelConnectionKey).
        if let bd = key.descriptorsJson, !bd.isEmpty,
           (self.appGroupDefaults?.string(forKey: self.descriptorStoreKey) ?? "").isEmpty {
            self.appGroupDefaults?.set(bd, forKey: self.descriptorStoreKey)
        }

        // Operator's ed25519 verifying key for ServerHello/MaskUpdate signature
        // checks (base64, exactly 32 bytes — same encoding as desktop's
        // --server-signing-key and macOS ConnectionKey.serverSigningKey).
        // Absent/empty = verification skipped, matching the opt-in behavior of
        // desktop (no --server-signing-key) and Android (null serverSigningKey).
        // Present but malformed = fail closed rather than silently connecting
        // without the verification the user asked for.
        let signingKeyB64 = (cfg["server_signing_key"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let serverSigningKey: [UInt8]?
        if signingKeyB64.isEmpty {
            serverSigningKey = nil
        } else if let data = Data(base64Encoded: signingKeyB64), data.count == 32 {
            serverSigningKey = Array(data)
        } else {
            completionHandler(makeError("invalid server signing key (expected base64-encoded 32 bytes)"))
            return
        }

        // R2 Phase B: operator's ed25519 mask-verifying public key (base64, 32
        // bytes) for MaskUpdate artifact signature checks — sourced from the
        // connection key's "mop" field via ConnectionKey.maskOperatorPubkey
        // (App target), threaded through providerConfiguration exactly like
        // server_signing_key above. Same fail-closed-on-malformed rule.
        let maskOperatorPubkeyB64 = (cfg["mask_operator_pubkey"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let maskOperatorPubkey: [UInt8]?
        if maskOperatorPubkeyB64.isEmpty {
            maskOperatorPubkey = nil
        } else if let data = Data(base64Encoded: maskOperatorPubkeyB64), data.count == 32 {
            maskOperatorPubkey = Array(data)
        } else {
            completionHandler(makeError("invalid mask operator public key (expected base64-encoded 32 bytes)"))
            return
        }
        // R2 Phase B: verification mode ("off"|"warn"|"enforce"). No UI sets
        // this today — an unset/absent value falls through to the Rust side's
        // own default ("warn"), matching desktop's default with no
        // --mask-verify-mode/config override. Left as a providerConfiguration
        // string (like preferred_mask) so a future settings screen is a
        // one-line addition rather than a new FFI parameter.
        let maskVerifyMode = cfg["mask_verify_mode"] as? String ?? ""

        // Create socketpair: sp[0] = Swift side, sp[1] = Rust side
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            completionHandler(makeError("socketpair failed: \(errno)"))
            return
        }
        sp = fds
        isStopped = false

        var bufSize: Int32 = 65536
        if setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) != 0 {
            os_log(.error, "setsockopt SO_SNDBUF sp[0] failed: %d", errno)
        }
        if setsockopt(sp[0], SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) != 0 {
            os_log(.error, "setsockopt SO_RCVBUF sp[0] failed: %d", errno)
        }
        if setsockopt(sp[1], SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) != 0 {
            os_log(.error, "setsockopt SO_SNDBUF sp[1] failed: %d", errno)
        }
        if setsockopt(sp[1], SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) != 0 {
            os_log(.error, "setsockopt SO_RCVBUF sp[1] failed: %d", errno)
        }

        // sp[0] must be non-blocking so the outbound drain loop (DispatchSourceRead
        // event handler in startBridge) returns EAGAIN once the socket buffer is
        // empty instead of blocking bridgeQueue.
        let flags = fcntl(sp[0], F_GETFL)
        guard fcntl(sp[0], F_SETFL, flags | O_NONBLOCK) >= 0 else {
            completionHandler(makeError("fcntl F_SETFL failed: \(errno)"))
            return
        }

        // Prefer a server-assigned VPN IP remembered from an earlier session on
        // this server (pool re-home): the key still embeds the stale colliding
        // IP, and starting with it earns an immediate anti-spoof drop until the
        // re-home watcher re-applies the settings. Start correct instead.
        let keyVpnIP = key.vpnIP ?? "10.8.0.2"
        let vpnIP    = appGroupDefaults?.string(forKey: Self.vpnIpOverridePrefix + key.serverHost) ?? keyVpnIP
        appliedVpnIP           = vpnIP
        settingsServerHost     = key.serverHost
        settingsFullTunnel     = fullTunnel
        settingsExcludedRoutes = excludedRoutes
        settingsExcludedDomains = excludedDomains
        settingsAdaptiveLevel  = adaptiveLevel
        settingsKillSwitch     = killSwitch
        let settings = buildSettings(vpnIP: vpnIP, serverHost: key.serverHost,
                                     fullTunnel: fullTunnel,
                                     excludedRoutes: excludedRoutes,
                                     excludedDomains: excludedDomains,
                                     adaptiveLevel: adaptiveLevel,
                                     killSwitch: killSwitch)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                completionHandler(error)
                return
            }

            // Guard against an early stopTunnel racing this async callback:
            // if the tunnel was already stopped, sp[] is closed (or about to
            // be) — starting the Rust thread / bridge now would hand a closed
            // or recycled fd to dup()/makeReadSource. Claim sp[1] atomically
            // under bridgeQueue: once claimed (set to -1), stopTunnel will not
            // close it — the Rust thread below owns and closes it instead.
            let claimedRustFd: Int32 = self.bridgeQueue.sync {
                guard !self.isStopped, self.sp[1] >= 0 else { return -1 }
                let fd = self.sp[1]
                self.sp[1] = -1 // ownership transferred to the Rust thread
                return fd
            }
            guard claimedRustFd >= 0 else {
                completionHandler(self.makeError("tunnel stopped during startup"))
                return
            }
            self.startRehomeWatch()
            self.startPathMonitor()

            let host       = key.serverHost
            let port       = key.serverPort
            var sKeyArr    = key.serverKey
            var pskArr     = key.psk
            let rustFd     = claimedRustFd
            let mask       = self.preferredMask
            let polymorphicBase = self.polymorphicBase
            // §2 crowdsourced blocking feedback — honor the server-pushed minimum
            // spacing between MaskFeedback sends (persisted in the shared App Group
            // UserDefaults across reconnects, since a fresh Rust instance is created
            // every attempt). A hints-only probe is cheap but still respects the
            // interval so a reconnect storm can't spam the server (mirrors desktop
            // client.rs's `maybe_send_mask_feedback`).
            let nowUnix = Date().timeIntervalSince1970
            let intervalOk = self.feedbackIntervalElapsed(now: nowUnix)
            let shareFeedback   = self.shareMaskFeedback && intervalOk
            let receiveHints    = self.receiveMaskHints && intervalOk
            let country         = self.countryCode
            let priorOutcomesJson: String? = shareFeedback
                ? self.appGroupDefaults?.string(forKey: Self.feedbackOutcomesKey).flatMap { $0 == "[]" ? nil : $0 }
                : nil

            // Covert first handshake: hand the Rust core the descriptors we
            // persisted from a PRIOR session so a COLD-START first handshake
            // resolves a COVERT rotated descriptor mask instead of a public
            // preset. A truly-first-ever connect (nothing cached yet) passes nil
            // and falls back to the preset — acceptable residual.
            let cachedDescriptorsJson: String? = self.appGroupDefaults?
                .string(forKey: self.descriptorStoreKey)
                .flatMap { $0.isEmpty || $0 == "[]" ? nil : $0 }

            // Retrieve mTLS cert — M2: same 3-tier resolution as the connection
            // key above. The one-time handoff token is consumed on first use, so
            // a system-initiated restart (reassertion, always-on relaunch) that
            // replays providerConfiguration would silently drop the cert and the
            // server would reject the mTLS-required session. Mirror the key's
            // persistent-Keychain fallback: token (fresh, wins + persists) →
            // persistent copy (reassertion) → direct embed (fresh, persists).
            // The persistent copy is only consulted when the profile actually
            // carries a cert token — a profile WITHOUT mTLS must never pick up
            // a stale cert from an earlier profile.
            let certBytes: [UInt8]? = {
                let certStr: String?
                if let token = cfg["mtlsCertToken"] as? String {
                    if let secret = self.retrieveHandoffSecret(token: token) {
                        certStr = secret
                        self.storePersistentCert(secret)
                    } else {
                        certStr = self.retrievePersistentCert()
                    }
                } else if let direct = cfg["mtlsCertDirect"] as? String, !direct.isEmpty {
                    certStr = direct
                    self.storePersistentCert(direct)
                } else {
                    certStr = nil
                }
                return certStr.flatMap {
                    guard let data = Data(base64Encoded: $0), !data.isEmpty else { return nil }
                    return Array(data)
                }
            }()

            // Load or generate the device private key for JIT Device Enrollment.
            let deviceKey = loadOrCreateDeviceKey()

            // Wire on_ready → completionHandler via C-compatible trampoline.
            // passUnretained: the thread closure captures readyBox strongly, so the
            // box outlives the entire aivpn_run_tunnel call — no extra retain needed.
            let readyBox = TunnelReadyBox(completionHandler)
            let readyCtx = Unmanaged.passUnretained(readyBox).toOpaque()

            let thread = Thread {
                // C1/H2: bounded in-extension retry loop. aivpn_run_tunnel
                // handles exactly ONE connection attempt; previously any
                // session error ended the whole extension process via
                // cancelTunnelWithError, so the Rust core's cross-attempt
                // resilience statics (HANDSHAKE_FAIL_STREAK descriptor
                // fallback, LAST_GOOD_MASK stickiness, DATA_STALL_STREAK
                // exploration) never saw a second attempt and a poisoned
                // cached descriptor could block connecting until expiry.
                // Retrying HERE keeps those statics alive across attempts —
                // the same shape as Android's in-service reconnect loop.
                //
                // Conservative bounds: at most backoffSeconds.count + 1
                // attempts with growing backoff; a user/OS stop (isStopped)
                // aborts immediately; a session that established and lived
                // >60 s resets the attempt budget (long-lived tunnel with an
                // occasional blip must never exhaust it).
                let backoffSeconds: [TimeInterval] = [1, 2, 4, 8, 15, 30]
                var attempt = 0
                // C1: seed the Rust core's handshake-fail streak from the App
                // Group so the descriptor→preset fallback threshold survives
                // extension-process teardown between failed starts.
                let persistedStreak = self.appGroupDefaults?.integer(forKey: self.failStreakKey) ?? 0
                if persistedStreak > 0 {
                    aivpn_seed_handshake_fail_streak(UInt32(clamping: persistedStreak))
                }
                while true {
                let attemptStart = Date()
                // Run the tunnel; withUnsafeBufferPointer closures end before zeroing.
                sKeyArr.withUnsafeBufferPointer { sKeyPtr in
                    deviceKey.withUnsafeBufferPointer { dkPtr in
                        let certCount = Int32(certBytes?.count ?? 0)

                        // Collapse psk/cert optionality into a single call site.
                        func withOptional(_ arr: [UInt8]?, body: (UnsafePointer<UInt8>?) -> Void) {
                            if let a = arr {
                                a.withUnsafeBufferPointer { body($0.baseAddress) }
                            } else {
                                body(nil)
                            }
                        }
                        // Same collapse for optional/empty C strings (polymorphic base
                        // mask id, country code) — nil or empty both map to NULL, which
                        // aivpn_run_tunnel treats as "not set" on the Rust side.
                        func withOptionalCString(_ s: String?, body: (UnsafePointer<CChar>?) -> Void) {
                            if let s = s, !s.isEmpty {
                                s.withCString { body($0) }
                            } else {
                                body(nil)
                            }
                        }

                        withOptional(pskArr) { pskPtr in
                            withOptional(certBytes) { certPtr in
                                // Forward preferred mask to the Rust runtime via env var.
                                // aivpn_run_tunnel's C signature has no mask parameter, so
                                // the environment variable is the least-invasive ABI extension.
                                //
                                // §3 privacy: in polymorphic mode, do NOT forward the concrete
                                // preset — the opening burst would otherwise be fingerprintable
                                // as e.g. "webrtc_zoom_v3" for a full RTT until the server's
                                // polymorphic MaskUpdate arrives. Only set the env var when
                                // polymorphic mode is not active for a concrete mask, mirroring
                                // the desktop CLI GUIs which omit --preferred-mask when
                                // --polymorphic-base is set. Leaving it unset lets the Rust
                                // side's initial_mask fall back to bootstrap_mask_for_psk.
                                // unsetenv covers tunnel reassertion within the same extension
                                // process, so a prior run's value can't leak into this one.
                                let polymorphicActive = !(polymorphicBase?.isEmpty ?? true)
                                if polymorphicActive {
                                    unsetenv("AIVPN_PREFERRED_MASK")
                                } else {
                                    mask.withCString { setenv("AIVPN_PREFERRED_MASK", $0, 1) }
                                }
                                withOptional(serverSigningKey) { signingKeyPtr in
                                    withOptionalCString(polymorphicBase) { polyPtr in
                                        withOptionalCString(country) { countryPtr in
                                            withOptionalCString(priorOutcomesJson) { priorPtr in
                                                // §3 privacy: in polymorphic mode pass NULL (not the
                                                // concrete preset) so the opening burst isn't
                                                // fingerprintable until the server's polymorphic
                                                // MaskUpdate lands — same rule the AIVPN_PREFERRED_MASK
                                                // unsetenv above enforces.
                                                withOptionalCString(polymorphicActive ? nil : mask) { maskPtr in
                                                withOptionalCString(cachedDescriptorsJson) { cachedDescPtr in
                                                withOptional(maskOperatorPubkey) { mopPtr in
                                                withOptionalCString(maskVerifyMode) { mvmPtr in
                                                _ = aivpn_run_tunnel(rustFd, host, Int32(port),
                                                                     sKeyPtr.baseAddress!, pskPtr,
                                                                     certPtr, certCount,
                                                                     dkPtr.baseAddress!, Int32(32),
                                                                     Int32(adaptiveLevel),
                                                                     tunnelOnReady, readyCtx,
                                                                     signingKeyPtr,
                                                                     polyPtr,
                                                                     shareFeedback ? 1 : 0,
                                                                     receiveHints ? 1 : 0,
                                                                     countryPtr,
                                                                     priorPtr,
                                                                     maskPtr,
                                                                     cachedDescPtr,
                                                                     mopPtr,
                                                                     mvmPtr)
                                                }
                                                }
                                                }
                                                }
                                            }
                                        }
                                    }
                                }
                                // §2 crowdsourced blocking feedback — record this attempt's
                                // outcome (success/failure attribution, server-pushed tuning,
                                // regional hints) via the FFI getters, now that the call above
                                // has returned. See recordFeedbackOutcome()'s doc comment.
                                self.recordFeedbackOutcome()
                                // Persist any bootstrap descriptors the server pushed this
                                // session (deduped/validity-filtered in the core) so the next
                                // COLD START can be covert. The store is process-global and
                                // survives the call above, so reading it here captures them.
                                self.persistBootstrapDescriptors()
                            }
                        }
                    }
                }
                // C1: persist the updated handshake-fail streak per server —
                // the core resets it to 0 internally once the PFS ratchet
                // completes, so this write also CLEARS the persisted value
                // after a successful connect.
                let streak = aivpn_get_handshake_fail_streak()
                self.appGroupDefaults?.set(Int(streak), forKey: self.failStreakKey)
                // User/OS-initiated stop: exit the loop immediately, no retry.
                if self.isStopped { break }
                // Terminal authenticated refusal (HandshakeReject): the server
                // has already verified this peer's PSK proof and refused for a
                // reason retrying can never fix (one-time key already used /
                // expired / disabled — see aivpn_get_handshake_reject_reason()).
                // Stop the reconnect loop immediately, same as a user stop,
                // instead of burning the backoff budget hammering a refusal
                // that will repeat identically on every attempt.
                if aivpn_handshake_was_rejected() != 0 {
                    os_log(.error, "aivpn: server sent HandshakeReject (reason=%d) — authenticated refusal, giving up",
                           aivpn_get_handshake_reject_reason())
                    break
                }
                // A session that established and lived >60 s was healthy —
                // whatever ended it is a fresh incident, not a continuation of
                // an earlier failure run. Reset the attempt budget.
                if aivpn_ever_connected() != 0,
                   Date().timeIntervalSince(attemptStart) > 60 {
                    attempt = 0
                }
                guard attempt < backoffSeconds.count else {
                    os_log(.error, "aivpn: tunnel session failed after %d attempts — giving up", Int32(attempt + 1))
                    break
                }
                let backoff = backoffSeconds[attempt]
                attempt += 1
                os_log(.info, "aivpn: tunnel session ended — reconnect attempt %d in %.0f s", Int32(attempt), backoff)
                // Sleep in short slices so a user stop aborts the wait fast.
                let sleepDeadline = Date().addingTimeInterval(backoff)
                while Date() < sleepDeadline && !self.isStopped {
                    Thread.sleep(forTimeInterval: 0.25)
                }
                if self.isStopped { break }
                // H2: a path-change aivpn_stop_tunnel() that landed in the gap
                // BETWEEN sessions set STOP_PENDING, which would kill the next
                // session instantly. This retry is an intentional reconnect —
                // clear it, then re-check isStopped: a USER stop always sets
                // isStopped BEFORE calling aivpn_stop_tunnel, so the re-check
                // keeps a raced user stop honored. (Residual: a user stop
                // landing exactly between this re-check and session start is
                // torn down moments later when iOS reaps the extension after
                // stopTunnel returns.)
                aivpn_clear_pending_stop()
                if self.isStopped { break }
                }
                // Zeroize key material *after* all withUnsafeBufferPointer closures
                // have returned — calling withUnsafeMutableBufferPointer while the
                // immutable variant is still on the stack is undefined behaviour.
                // L2 NOTE: this zeroization is best-effort only — Swift Array is
                // copy-on-write and the closures above may have left transient
                // copies (or the optimizer may elide the memset of a
                // provably-dead buffer), so erasure of every copy is NOT
                // guaranteed. Kept because it shrinks the window for the
                // canonical buffers; a guaranteed-erasure design needs
                // non-COW storage (flagged for a future security pass).
                sKeyArr.withUnsafeMutableBufferPointer { buf in
                    _ = memset(buf.baseAddress, 0, buf.count * MemoryLayout<UInt8>.size)
                }
                pskArr?.withUnsafeMutableBufferPointer { buf in
                    _ = memset(buf.baseAddress, 0, buf.count * MemoryLayout<UInt8>.size)
                }
                // This thread owns rustFd (claimed from sp[1] above, so stopTunnel
                // no longer closes it). Rust dup()ed its own copy on entry and has
                // already closed it by the time aivpn_run_tunnel returns.
                Darwin.close(rustFd)
                // Fallback: if aivpn_run_tunnel exited without calling on_ready
                // (e.g. connection refused, bad key, OS killed the thread), call
                // completionHandler with a failure so startTunnel is never stranded
                // in "Connecting" forever. TunnelReadyBox.complete is idempotent —
                // the call is a no-op if on_ready already fired successfully.
                let completedNow = readyBox.complete(error: NSError(
                    domain: "com.aivpn.tunnel", code: -2,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel exited before connecting"]))
                // complete() returning false means on_ready already fired: the
                // OS believes the tunnel is up, yet aivpn_run_tunnel has now
                // returned, so the data path is dead. Unless this return is
                // part of a user/OS-initiated stop (isStopped — set before
                // aivpn_stop_tunnel in stopTunnel), report the failure so NE
                // tears the tunnel down instead of blackholing in .connected.
                if !completedNow && !self.isStopped {
                    self.cancelTunnelWithError(
                        self.makeError("tunnel exited after connecting"))
                }
            }
            thread.name = "aivpn-rust-tunnel"
            thread.qualityOfService = .userInitiated
            self.rustThread = thread
            thread.start()

            self.startBridge()
        }
    }

    // MARK: - Stop
    //
    // Order matters:
    //   1. Set isStopped — packetFlow inbound loop will not re-queue after its
    //      current readPackets call returns.
    //   2. aivpn_stop_tunnel() — signals Rust to exit its event loop.
    //   3. Cancel the outbound read source (inside bridgeQueue.sync, so no event
    //      handler is mid-flight on the serial queue). Its cancel handler — which
    //      runs on bridgeQueue right after — closes sp[0]. Closing the fd only
    //      after cancellation is the required DispatchSource discipline; closing
    //      it while the source is armed could let it fire on a recycled fd.
    //   4. Close sp[1] if still owned here — the setTunnelNetworkSettings
    //      callback claims sp[1] (setting it to -1) before spawning the Rust
    //      thread, which then owns and closes it. sp[1] >= 0 here only when
    //      startup failed (or was raced) before that claim happened.
    //   5. Call completionHandler — iOS tears down the extension process shortly
    //      after, so we don't need to join the Rust thread.

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        isStopped = true
        aivpn_stop_tunnel()
        bridgeQueue.sync {
            pathMonitor?.cancel()
            pathMonitor = nil
            rehomeWatch?.cancel()
            rehomeWatch = nil
            if let source = outboundSource {
                source.cancel() // cancel handler closes sp[0] and sets it to -1
                outboundSource = nil
            } else if sp[0] >= 0 {
                // startBridge never ran (startup failed early) — close directly.
                Darwin.close(sp[0]); sp[0] = -1
            }
            if sp[1] >= 0 { Darwin.close(sp[1]); sp[1] = -1 }
        }
        completionHandler()
    }

    // MARK: - IPC from main app

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        guard let json = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let type = json["type"] as? String else {
            completionHandler?(nil)
            return
        }

        func serialize(_ obj: [String: Any]) -> Data? {
            do {
                return try JSONSerialization.data(withJSONObject: obj)
            } catch {
                os_log(.error, "handleAppMessage: serialization failed for type %@: %@", type, error.localizedDescription)
                return try? JSONSerialization.data(withJSONObject: ["error": "serialization failed"])
            }
        }

        switch type {
        case "get_traffic":
            applyPendingRecordingFeedback()
            let up      = (NSNumber(value: aivpn_get_upload_bytes())).int64Value
            let down    = (NSNumber(value: aivpn_get_download_bytes())).int64Value
            let quality = Int(aivpn_get_quality_score())
            // Core-owned connected-since (epoch ms, 0 = not established) —
            // same session scope as the byte counters, so the app's stopwatch
            // and traffic stats stay in sync across UI relaunch/jetsam.
            let since = (NSNumber(value: aivpn_get_connected_since_ms())).int64Value
            let resp: [String: Any] = [
                "upload":          up,
                "download":        down,
                "connected_since": since,
                "can_record":      canRecord,
                "recording_state": recordingPhase,
                "service":         recordingServiceName,
                "mask_id":         recordingMaskId,
                "message":         recordingFailureReason,
                "quality_score":   quality,
                "adaptive_level":  Int(aivpn_get_adaptive_level_hint()),
                // Server-pushed mask catalog (JSON array string, "" until received)
                // so the app's Picker can render a live list + "(авто)" marker.
                "mask_catalog":    readCString(capacity: 8192) { aivpn_get_mask_catalog_json($0, $1) } ?? "",
                // Protocol parity #3: surfaces a server-side mTLS CertRejected
                // this session so VPNManager can prompt the user to
                // re-provision instead of the tunnel silently retrying forever.
                "cert_rejected":   aivpn_cert_was_rejected() != 0,
                // AEAD-authenticated terminal handshake refusal — surfaced the
                // same way as cert_rejected above so VPNManager can show WHY
                // and stop treating the tunnel as merely "reconnecting".
                "handshake_rejected":      aivpn_handshake_was_rejected() != 0,
                "handshake_reject_reason": Int(aivpn_get_handshake_reject_reason()),
            ]
            completionHandler?(serialize(resp))

        case "record_start":
            let service = json["service"] as? String ?? ""
            // Mirror the macOS helper's record_start validation (bounded
            // length + restricted charset, main.swift) before the name
            // crosses the FFI boundary — isEmpty alone puts no bound on
            // what reaches aivpn_start_recording / the wire.
            let serviceOk = service.range(of: #"^[a-zA-Z0-9 _\-]{1,128}$"#,
                                          options: .regularExpression) != nil
            let ok: Bool
            if !serviceOk {
                ok = false
            } else {
                ok = service.withCString { ptr in
                    aivpn_start_recording(ptr) != 0
                }
            }
            if ok {
                recordingPhase = "recording"
                recordingServiceName = service
            }
            completionHandler?(serialize(["started": ok]))

        case "record_stop":
            // Don't jump straight to "idle": the server still needs to send
            // RecordingAck(status: "analyzing") followed by RecordingComplete
            // or RecordingFailed. applyPendingRecordingFeedback() (polled from
            // get_traffic) drives the real phase transition from here on;
            // recordingServiceName is kept so those later messages can still
            // report which service was being recorded.
            recordingPhase = "stopping"
            aivpn_stop_recording()
            completionHandler?(serialize(["stopped": true]))

        case "record_status":
            completionHandler?(serialize(["can_record": canRecord]))

        default:
            completionHandler?(nil)
        }
    }

    // MARK: - Swift <-> Rust bridge

    private func startBridge() {
        // L1: read-buffer size for sp[0]. Must cover the LARGEST datagram the
        // Rust core can write (its BUF_SIZE = 2048 — a decoded downlink payload
        // can exceed utun MTU + 4); a SOCK_DGRAM read into a smaller buffer
        // silently TRUNCATES the packet. Keep in sync with ios_tunnel.rs.
        let readBufSize = 2048

        // Outbound: sp[0] → packetFlow.
        // Event-driven: a DispatchSourceRead fires only when sp[0] becomes
        // readable, so the extension sleeps at ~0% CPU when idle instead of
        // busy-polling. sp[0] is O_NONBLOCK, so the drain loop below exits on
        // EAGAIN once the socket buffer is empty and waits for the next event.
        //
        // The whole setup runs inside bridgeQueue.sync and re-checks
        // isStopped/sp[0] there: an early stopTunnel that raced the async
        // startTunnel path may already have closed sp[0], and creating a
        // read source on a closed (possibly recycled) fd would be undefined.
        let claimedSwiftFd: Int32 = bridgeQueue.sync {
            guard !isStopped, sp[0] >= 0 else { return -1 }
            let swiftFd = sp[0]
            let source = DispatchSource.makeReadSource(fileDescriptor: swiftFd,
                                                       queue: bridgeQueue)
            source.setEventHandler { [weak self] in
                guard let self = self, !self.isStopped else { return }
                var buf = [UInt8](repeating: 0, count: readBufSize)
                while true {
                    let n = Darwin.read(swiftFd, &buf, readBufSize)
                    if n > 0 {
                        let data = Data(buf[0..<n])
                        let af: NSNumber = (buf[0] >> 4 == 6)
                            ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
                        self.packetFlow.writePackets([data], withProtocols: [af])
                        continue
                    }
                    if n < 0 && errno == EINTR { continue }
                    if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break // drained — wait for the next readable event
                    }
                    // n == 0 (peer closed; SOCK_DGRAM never carries empty
                    // datagrams here) or fatal errno (EBADF/ENOTSOCK/…):
                    // the bridge is going down. Set isStopped FIRST so the
                    // inbound packetFlow loop stops writing to swiftFd —
                    // otherwise it could keep write()ing into a closed and
                    // then recycled descriptor (plaintext VPN packets into a
                    // foreign fd). Only then cancel the source; its cancel
                    // handler closes sp[0].
                    let wasAlreadyStopping = self.markStopped()
                    self.outboundSource?.cancel()
                    self.outboundSource = nil
                    // If this EOF was NOT part of a user/OS-initiated stop,
                    // the Rust data path died on its own. Report it via
                    // cancelTunnelWithError — otherwise NE keeps the tunnel
                    // in .connected while all traffic blackholes and never
                    // restarts the extension. Dispatched off bridgeQueue:
                    // the stopTunnel this triggers does bridgeQueue.sync and
                    // must not be entered from bridgeQueue itself.
                    if !wasAlreadyStopping {
                        DispatchQueue.main.async {
                            self.cancelTunnelWithError(
                                self.makeError("tunnel data path closed"))
                        }
                    }
                    break
                }
            }
            // DispatchSource discipline: the fd is closed in the cancel handler,
            // i.e. only after the source can no longer fire — never while it is
            // still active (that could hit a recycled descriptor).
            source.setCancelHandler { [weak self] in
                // Close only while still owned: if stopTunnel's direct-close
                // branch ran first (racing an EOF-path cancel), sp[0] is
                // already -1 and swiftFd may have been recycled — closing it
                // again would hit a foreign descriptor.
                if let self = self, self.sp[0] == swiftFd {
                    self.sp[0] = -1
                    Darwin.close(swiftFd)
                }
            }
            outboundSource = source
            source.resume()
            return swiftFd
        }
        guard claimedSwiftFd >= 0 else { return }
        let swiftFd = claimedSwiftFd

        // Inbound: packetFlow → sp[0] → Rust.
        // Uses isStopped rather than Task cancellation because readPackets uses
        // a callback that does not observe Swift concurrency cancellation.
        // isStopped is re-checked before every write so that the outbound error
        // path above (which flips it before closing sp[0]) halts this loop too.
        Task.detached { [weak self] in
            guard let self = self else { return }
            while !self.isStopped {
                let packets = await withCheckedContinuation { cont in
                    self.packetFlow.readPackets { pkts, _ in
                        cont.resume(returning: pkts)
                    }
                }
                guard !self.isStopped else { break }
                for pkt in packets {
                    // The write must run on bridgeQueue — the same serial
                    // queue whose cancel handler closes sp[0] — so the fd
                    // cannot be closed (and recycled) between the isStopped
                    // check and the write. sp[0] still equaling swiftFd
                    // proves the cancel handler has not run yet; this is the
                    // same closed-then-recycled-fd hazard the outbound error
                    // path documents, applied to the inbound writer.
                    let bridgeDown = self.bridgeQueue.sync { () -> Bool in
                        guard !self.isStopped, self.sp[0] == swiftFd else { return true }
                        pkt.withUnsafeBytes { buf in
                            guard let base = buf.baseAddress, buf.count > 0 else { return }
                            let n = Darwin.write(swiftFd, base, buf.count)
                            // L5: a full socket buffer (EAGAIN/EWOULDBLOCK)
                            // silently drops this uplink packet — upper-layer
                            // protocols retransmit, but count it so sustained
                            // bridge backpressure is visible in debug logs.
                            if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                                self.inboundDropCount += 1
                                if self.inboundDropCount == 1 || self.inboundDropCount % 512 == 0 {
                                    os_log(.debug, "aivpn: inbound bridge full — %llu packets dropped so far",
                                           self.inboundDropCount)
                                }
                            }
                        }
                        return false
                    }
                    if bridgeDown { break }
                }
            }
        }
    }

    // MARK: - Network path monitoring (H2)

    /// Watches for interface changes (WiFi↔cellular, airplane-mode flip, hotspot
    /// handoff). On a meaningful change the current Rust session is stopped via
    /// aivpn_stop_tunnel() so the in-extension retry loop (startTunnel's thread)
    /// reconnects on the NEW path immediately, instead of waiting for the
    /// RX-silence watchdogs to notice the dead flow on the old one. The handler
    /// runs on bridgeQueue; lastPathSignature is touched only there.
    private func startPathMonitor() {
        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, !self.isStopped else { return }
            var sig = path.status == .satisfied ? "up" : "down"
            for iface in path.availableInterfaces {
                sig += "|\(iface.type)#\(iface.name)"
            }
            let previous = self.lastPathSignature
            self.lastPathSignature = sig
            // The first callback merely reports the current path — never
            // restart on it.
            guard let prev = previous, prev != sig else { return }
            // While the path is down there is nothing to reconnect TO; the
            // transition back to satisfied fires its own change event.
            guard path.status == .satisfied else { return }
            os_log(.info, "aivpn: network path changed (%{public}@ -> %{public}@) — restarting tunnel session",
                   prev, sig)
            // Stops ONLY the Rust session: isStopped stays false, so the retry
            // loop treats the exit as an internal error and reconnects.
            aivpn_stop_tunnel()
        }
        monitor.start(queue: bridgeQueue)
        pathMonitor = monitor
    }

    // MARK: - Pool re-home healing

    /// Polls the core for a server-assigned VPN IP that differs from the
    /// address the tunnel settings were applied with (the server re-homed this
    /// client to resolve a pool IP collision). Without this the server's
    /// anti-spoof check silently drops every uplink data packet while
    /// keepalives keep flowing — "connected" with no traffic. Re-applying the
    /// settings moves the utun to the working address without restarting the
    /// session, and the address is remembered per-server so the next start is
    /// correct from the first packet.
    private func startRehomeWatch() {
        rehomeWatch?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: bridgeQueue)
        timer.schedule(deadline: .now() + 3, repeating: 3)
        timer.setEventHandler { [weak self] in
            guard let self = self, !self.isStopped else { return }
            let raw = aivpn_get_assigned_vpn_ip()
            guard raw != 0 else { return }
            let ip = "\((raw >> 24) & 0xFF).\((raw >> 16) & 0xFF).\((raw >> 8) & 0xFF).\(raw & 0xFF)"
            guard ip != self.appliedVpnIP else { return }
            os_log(.info, "Server assigned VPN IP %{public}@ (settings had %{public}@) — re-applying network settings",
                   ip, self.appliedVpnIP)
            self.appliedVpnIP = ip
            self.appGroupDefaults?.set(ip, forKey: Self.vpnIpOverridePrefix + self.settingsServerHost)
            let settings = self.buildSettings(vpnIP: ip, serverHost: self.settingsServerHost,
                                              fullTunnel: self.settingsFullTunnel,
                                              excludedRoutes: self.settingsExcludedRoutes,
                                              excludedDomains: self.settingsExcludedDomains,
                                              adaptiveLevel: self.settingsAdaptiveLevel,
                                              killSwitch: self.settingsKillSwitch)
            self.setTunnelNetworkSettings(settings) { error in
                if let error = error {
                    os_log(.error, "Re-applying network settings failed: %{public}@",
                           error.localizedDescription)
                }
            }
        }
        timer.resume()
        rehomeWatch = timer
    }

    // MARK: - Network settings

    private func buildSettings(vpnIP: String, serverHost: String,
                               fullTunnel: Bool,
                               excludedRoutes: [String] = [],
                               excludedDomains: [String] = [],
                               adaptiveLevel: Int = 0,
                               killSwitch: Bool = false) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverHost)
        settings.mtu = adaptiveLevel >= 2 ? 1200 : (adaptiveLevel == 1 ? 1300 : 1400)

        // M1: derive the VPN /24 from the ACTUAL assigned address instead of
        // hardcoding 10.8.0.x — an operator running a different pool subnet
        // (or a pool re-home landing outside 10.8.0.0/24) would otherwise get
        // a split-tunnel route / DNS resolver pointing at the wrong network.
        // Falls back to the legacy 10.8.0 prefix only if vpnIP is unparsable.
        let subnetPrefix = Self.slash24Prefix(of: vpnIP) ?? "10.8.0"

        let ipv4 = NEIPv4Settings(addresses: [vpnIP], subnetMasks: ["255.255.255.0"])
        if fullTunnel {
            ipv4.includedRoutes = [NEIPv4Route.default()]

            // Build NEIPv4Route entries for any user-specified CIDR exclusions.
            // Only applies in full-tunnel mode; split-tunnel mode already routes
            // only the VPN subnet so there is nothing to exclude.
            if !excludedRoutes.isEmpty {
                ipv4.excludedRoutes = excludedRoutes.compactMap { cidr -> NEIPv4Route? in
                    parseCIDR(cidr)
                }
            }
        } else {
            ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "\(subnetPrefix).0",
                                               subnetMask: "255.255.255.0")]
        }
        settings.ipv4Settings = ipv4

        // DNS is intentionally only forced through the VPN in full-tunnel mode.
        // In split-tunnel mode (fullTunnel == false) only the VPN /24 subnet is
        // routed (see the `else` branch above) — general internet traffic stays on the
        // regular interface, so forcing all system DNS through the VPN's resolver here
        // would not match where the traffic actually goes (and the .1 gateway is not
        // known to be a general-purpose recursive resolver for arbitrary internet
        // domains, only for the VPN's own zone). This is the same reason
        // `excludedRoutes` is only applied in full-tunnel mode just above. This is a
        // deliberate design choice, not an oversight — changing it needs a product
        // decision plus on-device verification, since it can't be validated from this
        // sandbox (no Xcode/macOS toolchain here).
        if fullTunnel {
            // M1: the VPN-side resolver is the .1 of the ACTUAL assigned /24
            // (the server-side gateway convention), not a hardcoded 10.8.0.1.
            let dns = NEDNSSettings(servers: ["\(subnetPrefix).1", Self.fallbackPublicDNS])
            // matchDomains = nil routes ALL domains through VPN DNS (full-tunnel DNS behaviour).
            // NEDNSSettings has no matchExcludedDomains — domain-level DNS exclusion is not
            // supported by the iOS NetworkExtension API (confirmed by a real Xcode compile
            // error when this was previously attempted — not a guess). Route-level split
            // tunnel (excludedRoutes, CIDR-based) still applies; see buildSettings above.
            // `excludedDomains` is threaded through from providerConfiguration but is NOT
            // applied here for that reason — see PacketTunnelProvider.startTunnel and
            // SplitTunnelView.swift. True domain-based exclusion would require resolving
            // each domain to its current IP(s) and adding those as excludedRoutes, which is
            // a much larger, ongoing-resolution feature outside this fix's scope.
            settings.dnsSettings = dns
        }

        // H1: IPv6 leak guard (full-tunnel only). The Rust data path only ever
        // handles IPv4 — the TUN reader in ios_tunnel.rs drops any packet whose
        // version nibble isn't 4 — so without ANY NEIPv6Settings a dual-stack
        // network lets IPv6 traffic exit around the tunnel on the physical
        // interface while the user believes they are fully tunneled. Every
        // other platform already defends this: the macOS helper installs a
        // system `route -inet6 -net ::/0 -blackhole` (aivpn-helper/main.swift),
        // and Android assigns a private ULA + captures the default v6 route
        // into the VPN interface (AivpnService.kt) — the same shape used here.
        // A private, non-dialable ULA address is required because
        // NEIPv6Settings(addresses:networkPrefixLengths:) takes non-optional
        // arrays (Apple docs), so at least one address must be supplied even
        // though nothing ever legitimately reaches it: capturing the default
        // route (::/0) into the tunnel interface is what matters — the Rust
        // core silently discards every packet that arrives here, which is
        // functionally the same "blackhole" outcome as the system route used
        // on macOS. Split-tunnel mode intentionally leaves IPv6 untouched (no
        // ipv6Settings assigned) — the user opted out of full capture there,
        // so v6 must not be restricted beyond that either, mirroring how the
        // IPv4 branch above only routes the VPN subnet in split-tunnel mode.
        if fullTunnel {
            let ipv6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [NSNumber(value: 64)])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }
        return settings
    }

    /// M1: first three octets of a dotted-decimal IPv4 (e.g. "10.9.3.7" →
    /// "10.9.3"), or nil when the string is not a well-formed IPv4 address.
    /// Used to derive the split-tunnel route ("<prefix>.0"/24) and the VPN
    /// resolver ("<prefix>.1") from the actually-assigned VPN IP.
    private static func slash24Prefix(of ip: String) -> String? {
        let parts = ip.split(separator: ".")
        guard parts.count == 4,
              parts.allSatisfy({ UInt8($0) != nil }) else { return nil }
        return parts.prefix(3).joined(separator: ".")
    }

    // MARK: - CIDR helpers

    /// Parses a CIDR string (e.g. "192.168.1.0/24") into an NEIPv4Route.
    /// Returns nil for malformed input.
    private func parseCIDR(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLen = Int(parts[1]), prefixLen >= 0, prefixLen <= 32 else {
            return nil
        }
        let address = String(parts[0])
        let mask = prefixLengthToMask(prefixLen)
        // Validate that address looks like an IPv4 dotted-decimal string
        guard address.split(separator: ".").count == 4 else { return nil }
        return NEIPv4Route(destinationAddress: address, subnetMask: mask)
    }

    /// Converts a prefix length (0-32) to a dotted-decimal subnet mask string.
    private func prefixLengthToMask(_ length: Int) -> String {
        let bits: UInt32 = length == 0 ? 0 : ~UInt32(0) << (32 - length)
        let b0 = (bits >> 24) & 0xFF
        let b1 = (bits >> 16) & 0xFF
        let b2 = (bits >>  8) & 0xFF
        let b3 =  bits        & 0xFF
        return "\(b0).\(b1).\(b2).\(b3)"
    }

    // MARK: - Device key (JIT enrollment)

    /// Loads the 32-byte device private key from Keychain, generating and saving it
    /// if this is the first run. Uses SecRandomCopyBytes for cryptographic randomness.
    private func loadOrCreateDeviceKey() -> [UInt8] {
        let account = "aivpn_device_privkey_v1"
        let service = "com.aivpn.client"

        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data, data.count == 32 {
            return Array(data)
        }

        var keyBytes = [UInt8](repeating: 0, count: 32)
        let rngStatus = SecRandomCopyBytes(kSecRandomDefault, 32, &keyBytes)
        if rngStatus != errSecSuccess {
            os_log(.error, "SecRandomCopyBytes failed: %d — device key entropy may be degraded", rngStatus)
        }
        let keyData = Data(keyBytes)

        let deleteQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecAttrService as String:      service,
            kSecValueData as String:        keyData,
            // ThisDeviceOnly: this is the per-DEVICE enrollment identity. Without
            // it the item is eligible for iCloud Keychain sync and encrypted
            // backups, so two devices sharing an iCloud account would end up with
            // the SAME device key — defeating per-device attribution/pinning.
            // AfterFirstUnlock (not WhenUnlocked) is kept so the tunnel extension
            // can still read it while reasserting in the background on a locked device.
            kSecAttrAccessible as String:   kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            os_log(.error, "Failed to save device key to Keychain: %d", addStatus)
        }

        return keyBytes
    }

    // MARK: - Recording feedback (RecordingAck/RecordingComplete/RecordingFailed/RecordingStatus)

    /// Polls aivpn_get_recording_feedback_seq() and, if a new mask-recording
    /// feedback message has arrived since the last call, reads its kind and
    /// fields via the aivpn_get_recording_* FFI getters and updates
    /// recordingPhase/recordingServiceName/recordingMaskId/recordingFailureReason
    /// accordingly. Called from the "get_traffic" IPC handler, which the app
    /// polls once per second (see VPNManager.fetchTrafficStats) — there is no
    /// separate timer here to avoid duplicating that poll loop.
    private func applyPendingRecordingFeedback() {
        let seq = aivpn_get_recording_feedback_seq()
        guard seq != lastSeenRecordingFeedbackSeq else { return }
        lastSeenRecordingFeedbackSeq = seq

        switch aivpn_get_recording_feedback_kind() {
        case 1: // RecordingAck { session_id, status }
            let status = readCString(capacity: 64) { aivpn_get_recording_message($0, $1) }
            switch status {
            case "started":   recordingPhase = "recording"
            case "analyzing": recordingPhase = "analyzing"
            default: break // unrecognized status string; leave phase untouched
            }

        case 2: // RecordingComplete { service, mask_id, confidence }
            let service = readCString(capacity: 128) { aivpn_get_recording_service($0, $1) }
            let maskId  = readCString(capacity: 128) { aivpn_get_recording_message($0, $1) }
            if !service.isEmpty { recordingServiceName = service }
            recordingMaskId = maskId
            recordingPhase = "success"

        case 3: // RecordingFailed { reason }
            recordingFailureReason = readCString(capacity: 256) { aivpn_get_recording_message($0, $1) }
            recordingPhase = "failed"

        case 4: // RecordingStatus { can_record, active_service }
            canRecord = aivpn_recording_can_record() != 0

        default:
            break // 0 = no feedback yet
        }
    }

    /// Calls a C function that fills a buffer with a NUL-terminated UTF-8
    /// string and returns the number of bytes written (or a negative value on
    /// failure/no-data), and converts the result to a Swift String. Mirrors
    /// the withUnsafeMutableBufferPointer idiom already used elsewhere in this
    /// file for FFI byte buffers.
    private func readCString(capacity: Int, _ fill: (UnsafeMutablePointer<CChar>, Int32) -> Int32) -> String {
        var buf = [CChar](repeating: 0, count: capacity)
        let n: Int32 = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return fill(base, Int32(ptr.count))
        }
        guard n >= 0 else { return "" }
        // Defensive: force NUL termination even if the Rust side ever fills the
        // buffer without a trailing NUL — String(cString:) would otherwise read
        // past the end of the array.
        buf[buf.count - 1] = 0
        return String(cString: buf)
    }

    // MARK: - §2 crowdsourced blocking feedback — persisted outcome log
    //
    // `aivpn_run_tunnel` handles exactly one connection attempt per call, so this
    // extension — which is the only thing that ever calls it — is responsible for
    // everything the desktop CLI's `main.rs` + `mask_feedback_log.rs` do together:
    // tracking consecutive per-family failures across attempts, batching unreported
    // outcomes, honoring the server-pushed report interval/threshold, and persisting
    // all of it. Stored in the shared App Group UserDefaults (same suite used for the
    // split-tunnel lists above) rather than this process's memory, since the
    // extension process can be killed and respawned between connection attempts.

    /// App Group key for the persisted, ed25519-signed bootstrap descriptors
    /// (raw JSON array) saved from a prior session's BootstrapDescriptorUpdate
    /// messages. Fed back into aivpn_run_tunnel(cached_descriptors_json=…) so a
    /// COLD-START first handshake is shaped with a COVERT rotated descriptor mask
    /// instead of a public preset. Self-authenticating and re-verified on load.
    private static let bootstrapDescriptorsKey = "aivpn.bootstrap.descriptors_json"

    /// Per-server scoping for the descriptor blob (M1): suffix the base key with a
    /// hex of the (public) server pubkey so each profile keeps its own descriptors
    /// and a profile switch loads only that server's. The pubkey is not secret, so
    /// embedding a truncated hex of it in a UserDefaults key name is fine and needs
    /// no crypto dependency. 16 bytes → 32 hex chars, ample to separate servers.
    private static func perServerDescriptorsKey(_ serverKey: [UInt8]) -> String {
        let suffix = serverKey.prefix(16).map { String(format: "%02x", $0) }.joined()
        return "\(bootstrapDescriptorsKey).\(suffix)"
    }

    /// C1: App Group key (per-server suffixed, like the descriptor blob) for
    /// the persisted consecutive handshake-fail streak. Seeded back into the
    /// Rust core via aivpn_seed_handshake_fail_streak() before the first
    /// attempt of each extension process, so the HANDSHAKE_FALLBACK_THRESHOLD
    /// descriptor→preset fallback works even though iOS tears the extension
    /// process down between failed starts. Cleared (0) once a session
    /// connects.
    private static let handshakeFailStreakBaseKey = "aivpn.handshake_fail_streak"

    private static func perServerFailStreakKey(_ serverKey: [UInt8]) -> String {
        let suffix = serverKey.prefix(16).map { String(format: "%02x", $0) }.joined()
        return "\(handshakeFailStreakBaseKey).\(suffix)"
    }

    private static let feedbackOutcomesKey = "aivpn.feedback.outcomes_json"
    private static let feedbackLastReportKey = "aivpn.feedback.last_report_unix"
    private static let feedbackThresholdKey = "aivpn.feedback.failure_threshold"
    private static let feedbackIntervalKey = "aivpn.feedback.interval_secs"
    private static let feedbackConsecutiveFailsKey = "aivpn.feedback.consecutive_fails_json"
    private static let regionalHintsKey = "aivpn.feedback.regional_hints_json"
    // Mirrors desktop's `MaskFeedbackLog::MAX_ENTRIES`.
    private static let feedbackOutcomesMaxEntries = 128
    // Upper bounds on server-pushed `FeedbackConfig` tuning, mirroring
    // desktop's `MAX_REPORT_INTERVAL_SECS` / `MAX_FAILURE_THRESHOLD`
    // (`mask_feedback_log.rs`). A malicious or misconfigured server could
    // otherwise push a pathologically large interval or threshold; clamp
    // both so the feature stays meaningfully bounded.
    private static let feedbackMaxIntervalSecs: Double = 7 * 24 * 3600
    private static let feedbackMaxFailureThreshold = 10

    private var appGroupDefaults: UserDefaults? { UserDefaults(suiteName: appGroup) }

    private func feedbackFailureThreshold() -> Int {
        let v = appGroupDefaults?.integer(forKey: Self.feedbackThresholdKey) ?? 0
        return v > 0 ? min(v, Self.feedbackMaxFailureThreshold) : 3
    }

    private func feedbackIntervalSecs() -> Double {
        let v = appGroupDefaults?.double(forKey: Self.feedbackIntervalKey) ?? 0
        return v > 0 ? min(v, Self.feedbackMaxIntervalSecs) : 3600
    }

    private func feedbackIntervalElapsed(now: Double) -> Bool {
        let last = appGroupDefaults?.double(forKey: Self.feedbackLastReportKey) ?? 0
        return (now - last) >= feedbackIntervalSecs()
    }

    private func loadConsecutiveFails() -> [String: Int] {
        guard let json = appGroupDefaults?.string(forKey: Self.feedbackConsecutiveFailsKey),
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Int] else {
            return [:]
        }
        return obj
    }

    private func saveConsecutiveFails(_ fails: [String: Int]) {
        guard let data = try? JSONSerialization.data(withJSONObject: fails),
              let json = String(data: data, encoding: .utf8) else { return }
        appGroupDefaults?.set(json, forKey: Self.feedbackConsecutiveFailsKey)
    }

    /// Appends one outcome entry for `family`, bounded to
    /// `feedbackOutcomesMaxEntries` (oldest evicted first, mirroring desktop's
    /// `MaskFeedbackLog::MAX_ENTRIES`). Entries are summed per mask family by
    /// the Rust core (`merge_mask_outcomes`) when a batch is sent, so appending
    /// one small entry per outcome — rather than merging here — matches
    /// desktop's append-then-aggregate-at-send-time design.
    private func appendFeedbackOutcome(family: String, success: Bool) {
        var current: [[String: Any]] = []
        if let json = appGroupDefaults?.string(forKey: Self.feedbackOutcomesKey),
           let data = json.data(using: .utf8),
           let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
            current = arr
        }
        current.append(["mask_id": family, "success": success ? 1 : 0, "fail": success ? 0 : 1])
        if current.count > Self.feedbackOutcomesMaxEntries {
            current.removeFirst(current.count - Self.feedbackOutcomesMaxEntries)
        }
        guard let data = try? JSONSerialization.data(withJSONObject: current),
              let json = String(data: data, encoding: .utf8) else { return }
        appGroupDefaults?.set(json, forKey: Self.feedbackOutcomesKey)
    }

    /// Read the descriptors the core holds after a session and persist them into
    /// the shared App Group so the next COLD START can shape its first handshake
    /// with a COVERT rotated descriptor mask. Called right after
    /// `aivpn_run_tunnel` returns (the descriptor store is process-global and
    /// survives the call). Best-effort — a storage miss never breaks the tunnel.
    /// An empty ("[]") result leaves any previously-persisted blob in place so a
    /// session that received no update doesn't wipe a still-valid descriptor.
    private func persistBootstrapDescriptors() {
        let json = readCString(capacity: 65536) { aivpn_get_bootstrap_descriptors_json($0, $1) }
        guard !json.isEmpty, json != "[]" else { return }
        // L1: a descriptor blob larger than the readCString buffer would be
        // truncated to invalid JSON, and persisting that would silently defeat the
        // next cold start (accept_persisted_descriptors → empty → preset). Only
        // persist when the string actually parses as a JSON array, so a truncated
        // (or otherwise malformed) blob is dropped instead of poisoning the cache.
        guard let data = json.data(using: .utf8),
              (try? JSONSerialization.jsonObject(with: data)) is [Any] else {
            os_log(.error, "persistBootstrapDescriptors: getter JSON invalid/truncated — not persisting")
            return
        }
        // M1: keyed per server so a profile switch never loads another server's blob.
        appGroupDefaults?.set(json, forKey: descriptorStoreKey)
    }

    /// Called right after `aivpn_run_tunnel` returns (success or error) to
    /// process this attempt's §2 outcome. Order of operations mirrors
    /// desktop's split between `client.rs` (tuning/hints/success bookkeeping,
    /// live during a session) and `main.rs`'s reconnect loop (failure
    /// attribution, after the session ends):
    ///  1. Persist any server-pushed `FeedbackConfig` tuning from this session.
    ///  2. Persist any `RegionalMaskHints` received this session.
    ///  3. If a `MaskFeedback` was actually sent, this attempt's own outcome
    ///     was already folded into that batch by Rust — clear the local
    ///     buffer and record the send time.
    ///  4. Otherwise: on success, buffer a success entry locally so a future
    ///     send reports it; on failure, bump the family's consecutive-fail
    ///     counter and, at the server-pushed threshold, buffer a failure
    ///     entry and reset it.
    private func recordFeedbackOutcome() {
        let defaults = appGroupDefaults
        let nowUnix = Date().timeIntervalSince1970

        let threshold = aivpn_get_feedback_threshold()
        let intervalSecs = aivpn_get_feedback_interval_secs()
        if threshold > 0 {
            // Upper-clamp a server-pushed threshold — a malicious server
            // could otherwise push a value so high failure reporting is
            // effectively disabled.
            let clamped = min(max(Int(threshold), 1), Self.feedbackMaxFailureThreshold)
            defaults?.set(clamped, forKey: Self.feedbackThresholdKey)
        }
        if intervalSecs > 0 {
            // Upper-clamp a server-pushed interval — a malicious server
            // could otherwise push a value of years, effectively disabling
            // reporting.
            let clamped = min(Double(intervalSecs), Self.feedbackMaxIntervalSecs)
            defaults?.set(clamped, forKey: Self.feedbackIntervalKey)
        }

        if aivpn_get_regional_hints_seq() > 0 {
            let hintsJson = readCString(capacity: 4096) { aivpn_get_regional_hints_json($0, $1) }
            if !hintsJson.isEmpty {
                defaults?.set(hintsJson, forKey: Self.regionalHintsKey)
            }
        }

        let sent = aivpn_mask_feedback_sent() != 0
        if sent {
            defaults?.set("[]", forKey: Self.feedbackOutcomesKey)
            defaults?.set(nowUnix, forKey: Self.feedbackLastReportKey)
        }

        // Failure attribution + local outcome bookkeeping only applies when the
        // user opted in to sharing and a region is configured (mirrors desktop
        // main.rs's `feedback_share_enabled = args.share_mask_feedback &&
        // country_code.is_some()`), independent of whether THIS attempt's send
        // was suppressed by the interval gate.
        guard shareMaskFeedback, !countryCode.isEmpty else { return }
        let family = readCString(capacity: 128) { aivpn_get_attempted_mask_family($0, $1) }
        guard !family.isEmpty else { return }

        var fails = loadConsecutiveFails()
        if aivpn_ever_connected() != 0 {
            if fails.removeValue(forKey: family) != nil { saveConsecutiveFails(fails) }
            if !sent { appendFeedbackOutcome(family: family, success: true) }
            return
        }
        if sent { return } // sent implies a connected attempt; nothing more to do on failure
        let count = (fails[family] ?? 0) + 1
        if count >= feedbackFailureThreshold() {
            appendFeedbackOutcome(family: family, success: false)
            fails.removeValue(forKey: family)
            os_log(.debug, "aivpn: §2 recorded mask FAILURE for family '%@' (%d consecutive failed attempts)", family, count)
        } else {
            fails[family] = count
        }
        saveConsecutiveFails(fails)
    }

    // MARK: - Helpers

    private func makeError(_ msg: String) -> NSError {
        NSError(domain: "com.aivpn.tunnel", code: -1,
                userInfo: [NSLocalizedDescriptionKey: msg])
    }
}

// MARK: - on_ready trampoline (bridges Rust C callback → Swift completionHandler)

// TunnelReadyBox ensures startTunnel's completionHandler is called exactly once:
// • on_ready (Rust connect success) fires complete(error: nil)
// • Thread fallback fires complete(error: ...) if Rust exits without connecting
// Both paths are idempotent — the first caller wins, subsequent calls are no-ops.
private final class TunnelReadyBox {
    private let handler: (Error?) -> Void
    private let lock = NSLock()
    private var fired = false

    init(_ h: @escaping (Error?) -> Void) { handler = h }

    /// Thread-safe one-shot delivery — only the first call wins.
    /// Returns true when THIS call delivered the handler, false when it had
    /// already fired earlier (so callers can tell "startTunnel already
    /// completed successfully" apart from "this call reported the failure").
    @discardableResult
    func complete(error: Error?) -> Bool {
        lock.lock()
        guard !fired else { lock.unlock(); return false }
        fired = true
        lock.unlock()
        let h = handler
        DispatchQueue.main.async { h(error) }
        return true
    }
}

// Rust calls this C-compatible function when the tunnel becomes ready.
// ctx is a passUnretained pointer — the thread closure owns the strong reference,
// keeping the box alive for the entire duration of aivpn_run_tunnel.
private func tunnelOnReady(_: UnsafePointer<CChar>?, _ ctx: UnsafeMutableRawPointer?) {
    guard let ctx else { return }
    let box = Unmanaged<TunnelReadyBox>.fromOpaque(ctx).takeUnretainedValue()
    box.complete(error: nil)
}

// MARK: - Minimal connection key parser (tunnel extension cannot import App target)

private struct TunnelConnectionKey {
    let serverHost: String
    let serverPort: UInt16
    let serverKey: [UInt8]
    let psk: [UInt8]?
    let vpnIP: String?
    let canRecord: Bool?
    // M3: descriptors ("bd") that BootstrapDiscovery fetched + verified and embedded
    // in the connection key, re-serialized as a JSON array string. Seeded into the
    // per-server descriptor cache in startTunnel so a truly-first-ever connect is
    // covert. nil when the key carries no "bd" field.
    let descriptorsJson: String?

    init?(rawKey: String) {
        var b64 = rawKey
            .replacingOccurrences(of: "aivpn://", with: "")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }

        guard let data = Data(base64Encoded: b64),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let s    = json["s"] as? String else { return nil }

        let parts = s.split(separator: ":").map(String.init)
        guard parts.count >= 2, let port = UInt16(parts.last ?? "") else { return nil }
        var host = parts.dropLast().joined(separator: ":")
        // Strip IPv6 brackets: "[::1]" → "::1" (aivpn_run_tunnel expects a bare address)
        if host.hasPrefix("[") && host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        serverHost = host
        serverPort = port

        // `k` (server X25519 pubkey) and `p` (PSK) are 32 bytes each, encoded as
        // STANDARD base64 by the server (crates/aivpn-server/src/main.rs
        // build_connection_key — 44 chars incl. '='), which is also what the Rust
        // CLI (decode_base64_key) and Android decode. 64-char hex is accepted as
        // a legacy/manual fallback. The decoded raw bytes are exactly what
        // aivpn_run_tunnel expects (it does from_raw_parts(ptr, 32)).
        guard let pkStr = json["k"] as? String,
              let keyBytes = Self.decode32ByteKey(pkStr) else { return nil }
        serverKey = Array(keyBytes)

        if let pskStr = json["p"] as? String, !pskStr.isEmpty {
            // A present-but-malformed PSK is a hard error: silently dropping it
            // would send an unauthenticated handshake the server rejects, which
            // surfaces as an opaque timeout instead of "invalid connection key".
            guard let pskBytes = Self.decode32ByteKey(pskStr) else { return nil }
            psk = Array(pskBytes)
        } else {
            psk = nil
        }

        vpnIP     = json["i"] as? String
        canRecord = json["can_record"] as? Bool

        // M3: capture "bd" (an array of signed BootstrapDescriptor objects that
        // BootstrapDiscovery fetched + verified) and re-serialize it to the JSON
        // array string the core expects. Validity/signature are re-checked in Rust
        // on load, so an unusable payload just degrades to the preset.
        if let bd = json["bd"] as? [Any], !bd.isEmpty,
           JSONSerialization.isValidJSONObject(bd),
           let bdData = try? JSONSerialization.data(withJSONObject: bd),
           let bdStr = String(data: bdData, encoding: .utf8) {
            descriptorsJson = bdStr
        } else {
            descriptorsJson = nil
        }
    }

    /// Decodes a 32-byte key from either STANDARD base64 (44 chars — the
    /// server's real output format) or 64-char ASCII hex (legacy/manual).
    /// Base64 is tried first; a 64-char hex string can never be mistaken for
    /// base64 because 64 base64 chars would decode to 48 bytes, not 32.
    static func decode32ByteKey(_ s: String) -> Data? {
        if let data = Data(base64Encoded: s), data.count == 32 { return data }
        if s.utf8.count == 64, let data = Data(hexString: s), data.count == 32 { return data }
        return nil
    }
}

// MARK: - Keychain tunnel handoff

extension PacketTunnelProvider {
    /// Reads and deletes a one-time secret stored by the app via the shared app group keychain.
    /// Mirrors KeychainStorage.retrieveForTunnel — duplicated here so the tunnel extension
    /// target compiles without access to the App target's ConnectionKey.swift.
    fileprivate func retrieveHandoffSecret(token: String) -> String? {
        let service = "com.aivpn.client.tunnel-handoff"
        let query: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     token,
            kSecAttrAccessGroup: appGroup,
            kSecMatchLimit:      kSecMatchLimitOne,
            kSecReturnData:      true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let secret = String(data: data, encoding: .utf8) else { return nil }
        let del: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     token,
            kSecAttrAccessGroup: appGroup,
        ]
        SecItemDelete(del as CFDictionary)
        return secret
    }

    /// Writes the connection key to a stable Keychain entry that survives tunnel reassertion.
    /// Called after the key is first resolved from a one-time token or direct embed so that
    /// subsequent reassertions (WiFi→cellular, signal loss) can retrieve it directly.
    fileprivate func storePersistentKey(_ keyStr: String) {
        guard let data = keyStr.data(using: .utf8) else { return }
        let service = "com.aivpn.client.tunnel-handoff"
        let account = "aivpn_persistent_connection_key"
        let del: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
        ]
        SecItemDelete(del as CFDictionary)
        let attrs: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData:       data,
        ]
        SecItemAdd(attrs as CFDictionary, nil)
    }

    /// M2: writes the base64 mTLS cert to a stable Keychain entry that survives
    /// tunnel reassertion — the exact mirror of storePersistentKey for the cert,
    /// so a system-initiated restart (consumed one-time token) keeps its mTLS
    /// identity instead of silently connecting certless.
    fileprivate func storePersistentCert(_ certB64: String) {
        guard let data = certB64.data(using: .utf8) else { return }
        let service = "com.aivpn.client.tunnel-handoff"
        let account = "aivpn_persistent_mtls_cert"
        let del: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
        ]
        SecItemDelete(del as CFDictionary)
        let attrs: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData:       data,
        ]
        SecItemAdd(attrs as CFDictionary, nil)
    }

    /// M2: retrieves the persistent mTLS cert written by storePersistentCert.
    /// Returns nil before any cert has been persisted.
    fileprivate func retrievePersistentCert() -> String? {
        let service = "com.aivpn.client.tunnel-handoff"
        let account = "aivpn_persistent_mtls_cert"
        let query: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
            kSecMatchLimit:      kSecMatchLimitOne,
            kSecReturnData:      true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let cert = String(data: data, encoding: .utf8) else { return nil }
        return cert
    }

    /// Retrieves the persistent connection key written by storePersistentKey.
    /// Returns nil on the very first tunnel start (before any key has been persisted).
    fileprivate func retrievePersistentKey() -> String? {
        let service = "com.aivpn.client.tunnel-handoff"
        let account = "aivpn_persistent_connection_key"
        let query: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecAttrAccessGroup: appGroup,
            kSecMatchLimit:      kSecMatchLimitOne,
            kSecReturnData:      true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let key = String(data: data, encoding: .utf8) else { return nil }
        return key
    }
}

private extension Data {
    /// Strict ASCII-only hex decoder (byte-based over UTF-8). Deliberately does
    /// NOT use Character.hexDigitValue, which also matches fullwidth Unicode
    /// digits that the Rust side would reject.
    init?(hexString: String) {
        let ascii = Array(hexString.utf8)
        guard ascii.count % 2 == 0 else { return nil }
        func nibble(_ b: UInt8) -> UInt8? {
            switch b {
            case 0x30...0x39: return b - 0x30            // '0'-'9'
            case 0x41...0x46: return b - 0x41 + 10       // 'A'-'F'
            case 0x61...0x66: return b - 0x61 + 10       // 'a'-'f'
            default: return nil
            }
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(ascii.count / 2)
        var i = 0
        while i < ascii.count {
            guard let hi = nibble(ascii[i]), let lo = nibble(ascii[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
            i += 2
        }
        self.init(bytes)
    }
}
