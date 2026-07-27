import Foundation
import NetworkExtension
import UserNotifications
import Combine
import Darwin
import os.log

// MARK: - Recording state (mirrors macOS VPNManager)

enum MaskRecordingState: Equatable {
    case idle
    case starting(service: String)
    case recording(service: String)
    case stopping(service: String)
    case analyzing(service: String)
    case success(service: String, maskId: String?)
    case failed(service: String, reason: String)
}

struct RecordingResultSummary: Equatable {
    let succeeded: Bool
    let title: String
    let details: String
}

struct BenchResult {
    let p50ms: Int
    let quality: Int
    let serverAddr: String
    let date: Date
}

// MARK: - IPC message types (main app <-> tunnel extension)

/// One entry of the server-pushed mask catalog (matches the JSON the tunnel
/// core exposes: `[{"mask_id","label","generated"},...]`).
struct MaskCatalogEntry: Identifiable, Decodable {
    let mask_id: String
    let label: String
    let generated: Bool
    var id: String { mask_id }
}

private enum TunnelMessageType: String {
    case getTraffic   = "get_traffic"
    case startRecord  = "record_start"
    case stopRecord   = "record_stop"
    case getRecordStatus = "record_status"
}

// MARK: - VPNManager

class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var isConnected: Bool = false
    @Published var isConnecting: Bool = false
    @Published var isDisconnecting: Bool = false
    @Published var lastError: String?
    @Published var bytesSent: Int64 = 0
    @Published var bytesReceived: Int64 = 0
    @Published var connectionDuration: TimeInterval = 0
    @Published var recordingState: MaskRecordingState = .idle
    @Published var canRecordMasks: Bool = false
    @Published var recordingCapabilityKnown: Bool = false
    @Published var lastRecordingResult: RecordingResultSummary?
    @Published var liveQuality: Int = 0
    /// Protocol parity #3: set when the server rejects our mTLS certificate
    /// (CertRejected) — polled from get_traffic. A rejected cert makes the
    /// tunnel retry forever with no other visible signal, so this drives a
    /// one-time local notification prompting the user to re-provision.
    @Published var certRejected: Bool = false
    /// Set when the server sends an AEAD-authenticated `HandshakeReject` —
    /// polled from get_traffic, same pattern as certRejected above. Unlike a
    /// transient disconnect this is a TERMINAL refusal (the extension's
    /// in-process reconnect loop already stopped retrying once it saw this),
    /// so it drives a one-time local notification explaining WHY instead of
    /// leaving the user staring at a tunnel that silently gave up.
    @Published var handshakeRejected: Bool = false
    /// Reason code for the most recent `handshakeRejected`: 0 = unspecified,
    /// 1 = one-time key already used, 2 = client expired, 3 = client disabled.
    @Published var handshakeRejectReason: Int = 0
    /// Server-pushed mask catalog (polled from the tunnel via get_traffic).
    /// Drives the dynamic mask Picker + its "(авто)" marker.
    @Published var maskCatalog: [MaskCatalogEntry] = []
    @Published var serverAdaptiveLevel: Int = 0
    @Published var preferredMask: String = UserDefaults.standard.string(forKey: "preferredMask") ?? "auto" {
        didSet { UserDefaults.standard.set(preferredMask, forKey: "preferredMask") }
    }
    /// §3 Polymorphic masks: when true and `preferredMask` names a concrete mask
    /// (not "auto"), request a per-session polymorphic variant of it. Persisted
    /// and threaded through providerConfiguration exactly like `preferredMask`.
    @Published var polymorphicEnabled: Bool = UserDefaults.standard.bool(forKey: "polymorphicEnabled") {
        didSet { UserDefaults.standard.set(polymorphicEnabled, forKey: "polymorphicEnabled") }
    }
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default.
    @Published var shareMaskFeedback: Bool = UserDefaults.standard.bool(forKey: "shareMaskFeedback") {
        didSet { UserDefaults.standard.set(shareMaskFeedback, forKey: "shareMaskFeedback") }
    }
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default.
    @Published var receiveMaskHints: Bool = UserDefaults.standard.bool(forKey: "receiveMaskHints") {
        didSet { UserDefaults.standard.set(receiveMaskHints, forKey: "receiveMaskHints") }
    }
    /// ISO-3166-1 alpha-2 country code the user believes they are in. Required
    /// for `shareMaskFeedback` to have any effect; validated (2 ASCII letters)
    /// on the Rust side of the FFI boundary, not here.
    @Published var countryCode: String = UserDefaults.standard.string(forKey: "countryCode") ?? "" {
        didSet { UserDefaults.standard.set(countryCode, forKey: "countryCode") }
    }
    @Published var benchResult: BenchResult?
    @Published var isBenchRunning: Bool = false
    /// Set when the user explicitly denied the VPN configuration permission.
    /// retryManagerSetup is skipped while true so the system dialog is not re-shown on every foreground.
    @Published var permissionDenied: Bool = false

    /// True when the VPN profile has been loaded from preferences.
    var isManagerLoaded: Bool { manager != nil }

    var keys: [ConnectionKey] { KeychainStorage.shared.keys }
    var selectedKeyId: String? {
        get { KeychainStorage.shared.selectedKeyId }
        set { KeychainStorage.shared.selectKey(id: newValue) }
    }
    var selectedKey: ConnectionKey? { KeychainStorage.shared.activeKey }

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var trafficTimer: Timer?
    private var durationTimer: Timer?
    private var connectionStartDate: Date?
    // L3: whether THIS process saw the tunnel pass through .connecting /
    // .reasserting before .connected. An app relaunch over a live tunnel
    // adopts .connected directly — the "Connected" notification is
    // suppressed then (see syncStatus).
    private var observedConnecting = false
    /// Session start reported by the tunnel core over IPC (same session scope
    /// as the byte counters). Preferred over NE's connectedDate so the
    /// stopwatch and the traffic counters can never desync.
    private var coreConnectedSince: Date?
    private let bundleId = "com.aivpn.client.tunnel"

    init() {
        loadManager()
        requestNotificationPermission()
    }

    // MARK: - Manager lifecycle

    private func loadManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            if let m = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.bundleId
            }) {
                if m.connection.status == .invalid {
                    // Stale/invalid profile (e.g. from a previous install with wrong entitlements).
                    // Remove it so the system "Allow VPN?" dialog is presented fresh.
                    m.removeFromPreferences { [weak self] _ in
                        self?.createAndSaveProfile()
                    }
                } else {
                    // Existing valid profile found — use it.
                    DispatchQueue.main.async {
                        self.manager = m
                        self.observeStatus()
                        self.syncStatus()
                    }
                }
            } else {
                // No saved profile yet — create one and show the system "Allow VPN?" dialog.
                self.createAndSaveProfile()
            }
        }
    }

    private func createAndSaveProfile() {
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = bundleId
        proto.serverAddress = "aivpn"
        m.protocolConfiguration = proto
        m.localizedDescription = "AIVPN"
        m.isEnabled = true
        // Do NOT set self.manager yet — only set it after the save succeeds.
        // If we set it before and the user denies the VPN dialog,
        // retryManagerSetup() would see manager != nil and never retry.
        m.saveToPreferences { [weak self] saveError in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if let saveError = saveError {
                    self.manager = nil
                    let nsErr = saveError as NSError
                    if nsErr.domain == "NEVPNErrorDomain" {
                        switch nsErr.code {
                        case 5: // configurationReadWriteFailed — usually a missing entitlement in provisioning profile
                            self.lastError = LocalizationManager.shared.t("error_vpn_write_failed")
                        default: // configurationPermissionDenied (7) and other auth errors
                            self.permissionDenied = true
                            self.lastError = LocalizationManager.shared.t("error_permission_denied")
                        }
                    } else {
                        self.lastError = saveError.localizedDescription
                    }
                } else {
                    self.manager = m
                    self.observeStatus()
                    self.syncStatus()
                }
            }
        }
    }

    private func observeStatus() {
        if let obs = statusObserver {
            NotificationCenter.default.removeObserver(obs)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager?.connection, queue: .main
        ) { [weak self] _ in
            self?.syncStatus()
        }
    }

    private func syncStatus() {
        guard let connection = manager?.connection else { return }
        let status = connection.status
        switch status {
        case .connected:
            isConnecting = false
            isDisconnecting = false
            isConnected = true
            // NE owns the connected timestamp: adopt it on EVERY .connected
            // observation so an app relaunch/jetsam over a live tunnel (or a
            // stale cached date surviving a session restart) can't reset the
            // stopwatch while the tunnel-side counters keep running.
            let firstObservation = connectionStartDate == nil
            connectionStartDate = connection.connectedDate ?? Date()
            if firstObservation {
                startTimers()
                // L3: only announce "Connected" when THIS process actually
                // observed the connect happening (a .connecting/.reasserting
                // state). An app relaunch over an already-live tunnel merely
                // ADOPTS the connected state — notifying then is noise.
                if observedConnecting {
                    postConnectionNotification(connected: true)
                }
            }
            observedConnecting = false
        case .connecting, .reasserting:
            isConnecting = true
            isDisconnecting = false
            isConnected = false
            observedConnecting = true
        case .disconnecting:
            isConnecting = false
            isDisconnecting = true
        case .disconnected, .invalid:
            isConnecting = false
            isDisconnecting = false
            if isConnected {
                isConnected = false
                postConnectionNotification(connected: false)
                stopTimers()
                connectionStartDate = nil
                coreConnectedSince = nil
                bytesSent = 0
                bytesReceived = 0
                connectionDuration = 0
                recordingState = .idle
                canRecordMasks = false
                recordingCapabilityKnown = false
                liveQuality = 0
                serverAdaptiveLevel = 0
                certRejected = false
                handshakeRejected = false
                handshakeRejectReason = 0
            }
        @unknown default:
            break
        }
    }

    // MARK: - Connect / Disconnect

    func connect(key: ConnectionKey, fullTunnel: Bool, adaptiveLevel: Int = 0, killSwitch: Bool = false) {
        guard let manager = manager else { return }
        guard !isConnecting else { return }
        guard !isConnected else { return }

        isConnecting = true
        lastError = nil
        bytesSent = 0
        bytesReceived = 0
        connectionDuration = 0
        recordingState = .idle
        canRecordMasks = false
        recordingCapabilityKnown = false
        lastRecordingResult = nil
        certRejected = false

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = bundleId
        proto.serverAddress = key.serverAddress ?? "aivpn"
        proto.includeAllNetworks = killSwitch
        var providerConfig: [String: Any] = [
            "fullTunnel": fullTunnel,
        ]
        // Hand the secret to the tunnel extension exclusively via a one-time
        // shared-Keychain token (App Group, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).
        // If that write fails, the connect attempt is HARD-FAILED rather than
        // falling back to embedding the raw PSK in providerConfiguration: that
        // dict is persisted by the system NE daemon with no Data Protection
        // class and is included in device/iTunes backups, which would defeat
        // the Keychain design entirely under this project's threat model.
        // Capture the token so it can be deleted if saveToPreferences fails.
        let handoffToken: String
        if let keyToken = KeychainStorage.shared.storeForTunnel(secret: key.fullKey) {
            providerConfig["keyToken"] = keyToken
            handoffToken = keyToken
        } else {
            isConnecting = false
            lastError = LocalizationManager.shared.t("error_keychain_write_failed")
            return
        }
        if adaptiveLevel > 0 {
            providerConfig["adaptiveLevel"] = adaptiveLevel
        }
        if killSwitch {
            providerConfig["killSwitch"] = true
        }
        providerConfig["preferred_mask"] = preferredMask

        // §3 Polymorphic masks: only meaningful with a concrete base mask —
        // "auto" has no fixed mask id to perturb, so the toggle is a no-op then.
        if polymorphicEnabled, preferredMask != "auto", !preferredMask.isEmpty {
            providerConfig["polymorphic_base"] = preferredMask
        }
        // §2 crowdsourced blocking feedback — opt-in, OFF unless the user
        // explicitly enables it in Settings.
        if shareMaskFeedback {
            providerConfig["share_mask_feedback"] = true
        }
        if receiveMaskHints {
            providerConfig["receive_mask_hints"] = true
        }
        let trimmedCountryCode = countryCode.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedCountryCode.isEmpty {
            providerConfig["country_code"] = trimmedCountryCode
        }
        // Operator's ed25519 signing public key (base64) for ServerHello /
        // MaskUpdate signature verification — provisioned per connection key,
        // mirroring macOS ConnectionKey.serverSigningKey and desktop's
        // --server-signing-key. Omitted = verification skipped (same opt-in
        // semantics as every other platform).
        if let signingKey = key.serverSigningKey?
            .trimmingCharacters(in: .whitespacesAndNewlines), !signingKey.isEmpty {
            providerConfig["server_signing_key"] = signingKey
        }
        // R2 Phase B: operator's ed25519 mask-verifying public key — provisioned
        // per connection key (the "mop" field), threaded the same way as
        // server_signing_key above so PacketTunnelProvider can pass it to
        // verify_mask_artifact via aivpn_run_tunnel. Omitted = verification
        // stays unconfigured (mirrors desktop with no --mask-operator-pubkey).
        if let maskOpKey = key.maskOperatorPubkey?
            .trimmingCharacters(in: .whitespacesAndNewlines), !maskOpKey.isEmpty {
            providerConfig["mask_operator_pubkey"] = maskOpKey
        }

        let certHandoffToken: String?
        if let cert = key.mtlsCert, !cert.isEmpty {
            if let certToken = KeychainStorage.shared.storeForTunnel(secret: cert) {
                providerConfig["mtlsCertToken"] = certToken
                certHandoffToken = certToken
            } else {
                // Same hard-fail rule as the PSK above: never place the raw
                // mTLS cert in providerConfiguration. Clean up the key token
                // already written above — it will never be consumed now.
                KeychainStorage.shared.deleteHandoffToken(handoffToken)
                isConnecting = false
                lastError = LocalizationManager.shared.t("error_keychain_write_failed")
                return
            }
        } else {
            certHandoffToken = nil
        }

        // Pass split-tunnel lists from App Group UserDefaults to the tunnel extension.
        // The tunnel reads these from providerConfiguration because the extension
        // process cannot share in-memory state with the app process.
        let splitDefaults = UserDefaults(suiteName: "group.com.aivpn.client")
        if let routes = splitDefaults?.stringArray(forKey: "excluded_routes"), !routes.isEmpty {
            providerConfig["excluded_routes"] = routes.joined(separator: ",")
        }
        if let domains = splitDefaults?.stringArray(forKey: "excluded_domains"), !domains.isEmpty {
            providerConfig["excluded_domains"] = domains.joined(separator: ",")
        }

        proto.providerConfiguration = providerConfig
        manager.protocolConfiguration = proto
        manager.localizedDescription = "AIVPN"
        manager.isEnabled = true
        // Client parity #5: without an on-demand rule, iOS never relaunches the
        // tunnel after the extension is jetsam-killed or the device reboots —
        // the user must reopen the app and tap Connect again, unlike every
        // other platform's autostart/self-heal path. NEOnDemandRuleConnect()
        // with the default (.any) interfaceTypeMatch asks the system to bring
        // the tunnel up whenever a network is available. Disabled again in
        // disconnect() below so an intentional user disconnect is never
        // immediately fought by the system reconnecting it (the same "respect
        // user intent" gate that toggling isOnDemandEnabled false achieves —
        // isEnabled/isOnDemandEnabled persist in the saved profile, so this
        // must be re-enabled on every connect(), not just the first one).
        manager.isOnDemandEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]

        manager.saveToPreferences { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                // Clean up Keychain tokens written before saveToPreferences —
                // the tunnel will never start, so they would otherwise leak.
                KeychainStorage.shared.deleteHandoffToken(handoffToken)
                if let token = certHandoffToken { KeychainStorage.shared.deleteHandoffToken(token) }
                DispatchQueue.main.async {
                    self.isConnecting = false
                    self.lastError = error.localizedDescription
                }
                return
            }
            // saveToPreferences callback runs on an arbitrary queue; marshal to main
            // before touching the manager/statusObserver and calling NetworkExtension API.
            DispatchQueue.main.async {
                self.observeStatus()
                do {
                    try (self.manager?.connection as? NETunnelProviderSession)?.startTunnel(options: nil)
                } catch {
                    // startTunnel never launched the extension, so the one-time
                    // handoff tokens were never consumed — delete them here too
                    // (not only on saveToPreferences failure) so they don't
                    // accumulate as orphans in the shared Keychain.
                    KeychainStorage.shared.deleteHandoffToken(handoffToken)
                    if let token = certHandoffToken { KeychainStorage.shared.deleteHandoffToken(token) }
                    self.isConnecting = false
                    self.lastError = error.localizedDescription
                }
            }
        }
    }

    func disconnect() {
        // Client parity #5: disable on-demand before stopping so the system
        // doesn't immediately fight this intentional disconnect by bringing
        // the tunnel back up on the next network-change evaluation —
        // NEOnDemandRuleConnect() only applies while isOnDemandEnabled is
        // true, and that flag persists in the saved profile independent of
        // the stop below. Best-effort or not, stopTunnel() still fires
        // synchronously right after — a user disconnect must never be
        // silently delayed behind a preferences save.
        if let manager = manager, manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            manager.saveToPreferences { _ in }
        }
        (manager?.connection as? NETunnelProviderSession)?.stopTunnel()
    }

    /// Called when app becomes active. Always reloads from preferences so that:
    /// 1. A previously denied VPN permission that was later granted in Settings is picked up.
    /// 2. A profile created externally (or deleted in Settings) is reflected immediately.
    func retryManagerSetup() {
        // Do NOT clear lastError here — the user must explicitly dismiss errors.
        // Clearing it here races with connect()'s error path and can hide failures.
        loadManager()
    }

    // MARK: - Key management (delegates to KeychainStorage)

    func addKey(name: String, keyValue: String, mtlsCert: String? = nil,
                serverSigningKey: String? = nil) -> Bool {
        guard let k = KeychainStorage.shared.addKey(name: name, keyValue: keyValue, mtlsCert: mtlsCert,
                                                    serverSigningKey: serverSigningKey) else {
            return false
        }
        KeychainStorage.shared.selectKey(id: k.id)
        objectWillChange.send()
        return true
    }

    func deleteKey(id: String) {
        KeychainStorage.shared.deleteKey(id: id)
        objectWillChange.send()
    }

    func updateKey(id: String, name: String, keyValue: String, mtlsCert: String? = nil,
                   serverSigningKey: String? = nil) -> Bool {
        let ok = KeychainStorage.shared.updateKey(id: id, name: name, keyValue: keyValue, mtlsCert: mtlsCert,
                                                  serverSigningKey: serverSigningKey)
        if ok { objectWillChange.send() }
        return ok
    }

    func selectKey(id: String) {
        KeychainStorage.shared.selectKey(id: id)
        benchResult = nil
        isBenchRunning = false
        objectWillChange.send()
    }

    // MARK: - Traffic stats (IPC to tunnel extension)

    private func startTimers() {
        trafficTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.fetchTrafficStats()
        }
        durationTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            // Core session start (same scope as the counters) wins; NE's
            // connectedDate is the system fallback; the stored property is
            // the last resort (both survive UI relaunch, unlike Date()).
            guard let start = self.coreConnectedSince
                ?? self.manager?.connection.connectedDate
                ?? self.connectionStartDate else { return }
            self.connectionDuration = Date().timeIntervalSince(start)
        }
    }

    private func stopTimers() {
        trafficTimer?.invalidate(); trafficTimer = nil
        durationTimer?.invalidate(); durationTimer = nil
    }

    private func fetchTrafficStats() {
        sendMessage(type: .getTraffic, body: [:]) { [weak self] response in
            guard let self = self, let r = response else { return }
            if let up = r["upload"] as? Int64 { self.bytesSent = up }
            if let down = r["download"] as? Int64 { self.bytesReceived = down }
            // Core-owned session start (epoch ms, 0 = not established) —
            // exact same session scope as upload/download above, delivered in
            // the same IPC round-trip, so timer and counters can't desync.
            if let sinceMs = r["connected_since"] as? Int64, sinceMs > 0 {
                self.coreConnectedSince = Date(timeIntervalSince1970: TimeInterval(sinceMs) / 1000.0)
            }
            if let q = r["quality_score"] as? Int { self.liveQuality = q }
            if let al = r["adaptive_level"] as? Int { self.serverAdaptiveLevel = al }
            if let catJson = r["mask_catalog"] as? String, !catJson.isEmpty,
               let data = catJson.data(using: .utf8),
               let items = try? JSONDecoder().decode([MaskCatalogEntry].self, from: data) {
                self.maskCatalog = items
            }
            if let canRec = r["can_record"] as? Bool {
                self.canRecordMasks = canRec
                self.recordingCapabilityKnown = true
            }
            if let rejected = r["cert_rejected"] as? Bool, rejected, !self.certRejected {
                self.certRejected = true
                self.postNotification(
                    title: LocalizationManager.shared.t("cert_rejected_title"),
                    body: LocalizationManager.shared.t("cert_rejected_body"))
            }
            if let rejected = r["handshake_rejected"] as? Bool, rejected, !self.handshakeRejected {
                self.handshakeRejected = true
                self.handshakeRejectReason = r["handshake_reject_reason"] as? Int ?? 0
                // The extension's in-process reconnect loop already stopped
                // retrying (see PacketTunnelProvider's aivpn_handshake_was_rejected
                // check) — this is a one-time explanatory notification, not a
                // prompt to retry, so pick body text per reason code.
                let bodyKey: String
                switch self.handshakeRejectReason {
                case 1: bodyKey = "handshake_reject_reason_1"
                case 2: bodyKey = "handshake_reject_reason_2"
                case 3: bodyKey = "handshake_reject_reason_3"
                default: bodyKey = "handshake_reject_reason_0"
                }
                self.postNotification(
                    title: LocalizationManager.shared.t("handshake_rejected_title"),
                    body: LocalizationManager.shared.t(bodyKey))
            }
            if let stateStr = r["recording_state"] as? String {
                // Don't let the tunnel's "idle" overwrite terminal states the user
                // hasn't dismissed yet, or "starting" before the IPC roundtrip completes.
                let shouldApply: Bool
                switch (self.recordingState, stateStr) {
                case (.success, _), (.failed, _): shouldApply = false
                case (.starting, "idle"):          shouldApply = false
                // A genuine terminal result always arrives while the UI is still
                // mid-recording (.recording/.stopping/.analyzing/.starting). If we
                // are already back at .idle, a "success"/"failed" report is a stale
                // echo the user already dismissed — the tunnel keeps returning the
                // last recordingPhase every poll — so re-applying it would resurrect
                // the dismissed card and re-post its notification once per second.
                case (.idle, "success"), (.idle, "failed"): shouldApply = false
                default:                           shouldApply = true
                }
                if shouldApply {
                    self.applyRecordingState(stateStr,
                        service: r["service"] as? String ?? "",
                        maskId: r["mask_id"] as? String,
                        message: r["message"] as? String)
                }
            }
        }
    }

    // MARK: - Mask recording

    func startMaskRecording(serviceName: String) {
        guard isConnected, canRecordMasks else { return }
        let name = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        recordingState = .starting(service: name)
        lastRecordingResult = nil
        sendMessage(type: .startRecord, body: ["service": name]) { [weak self] response in
            guard let self = self, case .starting = self.recordingState else { return }
            if let started = response?["started"] as? Bool, started {
                self.recordingState = .recording(service: name)
            } else {
                self.recordingState = .failed(service: name,
                    reason: LocalizationManager.shared.t("recording_server_rejected"))
            }
        }
    }

    func stopMaskRecording() {
        let svc: String
        switch recordingState {
        case .recording(let s): svc = s
        case .starting(let s):  svc = s
        default: return
        }
        recordingState = .stopping(service: svc)
        sendMessage(type: .stopRecord, body: [:], completion: nil)
    }

    func clearRecordingResult() { lastRecordingResult = nil }

    private func applyRecordingState(_ state: String, service: String, maskId: String?, message: String?) {
        switch state {
        case "recording":  recordingState = .recording(service: service)
        case "stopping":   recordingState = .stopping(service: service)
        case "analyzing":  recordingState = .analyzing(service: service)
        case "success":
            recordingState = .success(service: service, maskId: maskId)
            let details = maskId.map { "ID: \($0)" } ?? service
            lastRecordingResult = RecordingResultSummary(
                succeeded: true,
                title: LocalizationManager.shared.t("recording_result_success_title"),
                details: details)
            postNotification(
                title: LocalizationManager.shared.t("recording_success"),
                body: details)
        case "failed":
            let reason = message ?? service
            recordingState = .failed(service: service, reason: reason)
            lastRecordingResult = RecordingResultSummary(
                succeeded: false,
                title: LocalizationManager.shared.t("recording_result_failed_title"),
                details: reason)
            postNotification(
                title: LocalizationManager.shared.t("recording_failed"),
                body: reason)
        default:
            recordingState = .idle
        }
    }

    // MARK: - IPC helper

    private func sendMessage(type: TunnelMessageType, body: [String: Any],
                             completion: (([String: Any]?) -> Void)?) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let session = manager?.connection as? NETunnelProviderSession,
              manager?.connection.status == .connected else {
            completion?(nil)
            return
        }
        var payload = body
        payload["type"] = type.rawValue
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            os_log(.error, "sendMessage: failed to serialise payload for type %@", type.rawValue)
            completion?(nil)
            return
        }
        do {
            try session.sendProviderMessage(data) { responseData in
                guard let rd = responseData,
                      let json = try? JSONSerialization.jsonObject(with: rd) as? [String: Any]
                else {
                    DispatchQueue.main.async { completion?(nil) }
                    return
                }
                DispatchQueue.main.async { completion?(json) }
            }
        } catch {
            os_log(.error, "sendProviderMessage failed: %@", error.localizedDescription)
            DispatchQueue.main.async { completion?(nil) }
        }
    }

    // MARK: - Notifications

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error = error {
                os_log(.error, "Notification auth error: %@", error.localizedDescription)
            }
            if !granted {
                os_log(.info, "Notification permission denied")
            }
        }
    }

    private func postConnectionNotification(connected: Bool) {
        let body = LocalizationManager.shared.t(connected ? "status_connected" : "status_disconnected")
        postNotification(title: "AIVPN", body: body)
    }

    private func postNotification(title: String, body: String) {
        let c = UNMutableNotificationContent()
        c.title = title; c.body = body; c.sound = .default
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }

    // MARK: - Benchmark

    func runBenchmark() {
        guard let addr = selectedKey?.serverAddress, !addr.isEmpty else { return }
        guard !isBenchRunning else { return }
        isBenchRunning = true
        benchResult = nil
        DispatchQueue.global(qos: .utility).async { [weak self] in
            runBenchPosix(serverAddr: addr) { p50, quality in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.isBenchRunning = false
                    // Always publish a result: p50 == 0 means unreachable, p50 == -1 means IPv6.
                    // The UI reads p50ms <= 0 and renders "unreachable" / "N/A" accordingly.
                    self.benchResult = BenchResult(
                        p50ms: p50, quality: quality,
                        serverAddr: addr, date: Date())
                }
            }
        }
    }

    deinit {
        stopTimers()
        if let obs = statusObserver { NotificationCenter.default.removeObserver(obs) }
    }
}

// MARK: - UDP Latency Probe

/// Sends UDP probes to `serverAddr` (host:port) for 5 seconds and calls
/// completion with (p50ms, qualityScore 0–100) on the calling thread.
/// p50 == 0 means unreachable or parse error. Not called from the main thread.
func runBenchPosix(serverAddr: String, completion: (Int, Int) -> Void) {
    let isIPv6Bracket = serverAddr.hasPrefix("[")
    if isIPv6Bracket {
        completion(-1, 0)
        return
    }

    let colonIdx = serverAddr.lastIndex(of: ":")
    guard let idx = colonIdx else { completion(0, 0); return }
    let host = String(serverAddr[serverAddr.startIndex..<idx])
    let portStr = String(serverAddr[serverAddr.index(after: idx)...])
    guard let portNum = UInt16(portStr) else { completion(0, 0); return }

    var sin = sockaddr_in()
    sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    sin.sin_family = sa_family_t(AF_INET)
    sin.sin_port = portNum.bigEndian
    if inet_pton(AF_INET, host, &sin.sin_addr) != 1 {
        // L4: not an IPv4 literal — a connection key may carry a hostname.
        // Resolve it via getaddrinfo (IPv4 only: the probe socket is AF_INET),
        // mirroring BootstrapDiscovery's getaddrinfo usage. Runs on a utility
        // queue (see runBenchmark), so a blocking resolve is acceptable.
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET,
                             ai_socktype: SOCK_DGRAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0, let first = list else {
            completion(0, 0); return
        }
        defer { freeaddrinfo(first) }
        var resolved: in_addr?
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let cur = node {
            if cur.pointee.ai_family == AF_INET, let sa = cur.pointee.ai_addr {
                resolved = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    $0.pointee.sin_addr
                }
                break
            }
            node = cur.pointee.ai_next
        }
        guard let addr4 = resolved else { completion(0, 0); return }
        sin.sin_addr = addr4
    }

    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { completion(0, 0); return }
    defer { Darwin.close(fd) }

    var tv = timeval(tv_sec: 0, tv_usec: 500_000)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    let probeData = Array("aivpn-bench-probe-v1".utf8)
    var recvBuf = [UInt8](repeating: 0, count: 256)
    let deadline = Date().addingTimeInterval(5.0)
    var rtts: [Double] = []
    var sent = 0

    while Date() < deadline {
        let t0 = Date()
        sent += 1
        withUnsafePointer(to: sin) { sinPtr in
            sinPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                probeData.withUnsafeBytes { bp in
                    _ = sendto(fd, bp.baseAddress, probeData.count, 0, sa,
                               socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        let n = recv(fd, &recvBuf, recvBuf.count, 0)
        let elapsed = -t0.timeIntervalSinceNow * 1000.0
        if n > 0 {
            rtts.append(elapsed)
        }
    }

    guard !rtts.isEmpty else { completion(0, 0); return }
    let sorted = rtts.sorted()
    let p50 = sorted[max(0, Int(Double(sorted.count) * 0.5) - 1)]
    let lossPct = Double(max(0, sent - rtts.count)) / Double(sent) * 100.0
    let quality: Int
    switch (p50, lossPct) {
    case _ where p50 < 50 && lossPct < 1:   quality = 95
    case _ where p50 < 100 && lossPct < 3:  quality = 80
    case _ where p50 < 200 && lossPct < 10: quality = 60
    default: quality = 30
    }
    completion(Int(p50), quality)
}
