import Foundation
import Combine
import UserNotifications
import Network

// MARK: - Helper Protocol Types

struct HelperRequest: Codable {
    let action: String
    let key: String?
    let fullTunnel: Bool?
    let binaryPath: String?
    let service: String?
    let mtlsCertPath: String?
    let excludeRoutes: String?
    let adaptiveLevel: Int?
    let dnsProxy: String?
    let killSwitch: Bool?
    let preferredMask: String?
    // §3 Polymorphic mask: per-session unique traffic-shape variant of a base
    // preset (e.g. "webrtc_zoom_v3"). Takes precedence over preferredMask on
    // the helper/client side when both are present.
    let polymorphicBase: String?
    // §2 Crowdsourced mask feedback opt-ins + region hint.
    let shareMaskFeedback: Bool?
    let receiveMaskHints: Bool?
    let countryCode: String?
    // Advanced/operator bootstrap discovery — lets a client with no working
    // aivpn:// key yet discover a server/mask via signed multi-channel
    // fallback (CDN/Telegram/GitHub).
    let bootstrapCdnUrl: String?
    let bootstrapTelegramToken: String?
    let bootstrapTelegramChat: String?
    let bootstrapGithub: String?
    let serverSigningKey: String?

    init(action: String, key: String?, fullTunnel: Bool?, binaryPath: String?,
         service: String?, mtlsCertPath: String?, excludeRoutes: String?,
         adaptiveLevel: Int?, dnsProxy: String?, killSwitch: Bool?,
         preferredMask: String? = nil,
         polymorphicBase: String? = nil,
         shareMaskFeedback: Bool? = nil,
         receiveMaskHints: Bool? = nil,
         countryCode: String? = nil,
         bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
         bootstrapTelegramChat: String? = nil,
         bootstrapGithub: String? = nil,
         serverSigningKey: String? = nil) {
        self.action = action
        self.key = key
        self.fullTunnel = fullTunnel
        self.binaryPath = binaryPath
        self.service = service
        self.mtlsCertPath = mtlsCertPath
        self.excludeRoutes = excludeRoutes
        self.adaptiveLevel = adaptiveLevel
        self.dnsProxy = dnsProxy
        self.killSwitch = killSwitch
        self.preferredMask = preferredMask
        self.polymorphicBase = polymorphicBase
        self.shareMaskFeedback = shareMaskFeedback
        self.receiveMaskHints = receiveMaskHints
        self.countryCode = countryCode
        self.bootstrapCdnUrl = bootstrapCdnUrl
        self.bootstrapTelegramToken = bootstrapTelegramToken
        self.bootstrapTelegramChat = bootstrapTelegramChat
        self.bootstrapGithub = bootstrapGithub
        self.serverSigningKey = serverSigningKey
    }
}

struct HelperResponse: Codable {
    let status: String
    let message: String
    let connected: Bool?
    let pid: Int?
    let version: String?
    let log: String?
}

struct RecordingInfoSnapshot: Codable {
    let can_record: Bool?
    let state: String
    let service: String?
    let message: String?
    let mask_id: String?
    let confidence: Float?
    let updated_at_ms: UInt64
}

private let recordingStatusPaths = [
    "/var/run/aivpn/recording.status",
    "/tmp/aivpn-recording.status",
]

private func currentTimestampMs() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000)
}

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
    let updatedAtMs: UInt64
}

// MARK: - VPNManager

class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var isConnected: Bool = false
    @Published var isConnecting: Bool = false
    private var connectGeneration: Int = 0
    @Published var lastError: String?
    @Published var bytesSent: Int64 = 0
    @Published var bytesReceived: Int64 = 0
    @Published var qualityScore: Int = 0
    @Published var serverAdaptiveLevel: Int = 0
    @Published var savedKey: String = ""
    @Published var helperAvailable: Bool = false
    @Published var isCheckingHelper: Bool = true
    @Published var helperVersion: String = ""
    @Published var recordingState: MaskRecordingState = .idle
    @Published var canRecordMasks: Bool = false
    @Published var recordingCapabilityKnown: Bool = false
    @Published var lastRecordingResult: RecordingResultSummary?
    
    // Поддержка списка ключей
    @Published var selectedKeyId: String?
    var keys: [ConnectionKey] {
        get { KeychainStorage.shared.keys }
    }

    @Published var isProxyMode: Bool = false

    private var statusPollTimer: Timer?
    private var trafficTimer: Timer?
    // Session epoch (`since:` unix ms) from the last traffic.stats sample;
    // a change marks an in-process client reconnect (counters restarted).
    private var lastTrafficSince: Int64 = 0
    private var minimumRecordingStatusTimestamp: UInt64 = 0
    private var lastRecordingNotificationTimestamp: UInt64 = 0

    // MARK: - Network Path Monitoring (active reconnect trigger)

    private var pathMonitor: NWPathMonitor?
    private let pathMonitorQueue = DispatchQueue(label: "com.aivpn.pathmonitor")
    private var lastPathStatus: NWPath.Status?
    private var lastPathPrimaryInterfaceType: NWInterface.InterfaceType?
    private var networkChangeReconnectWorkItem: DispatchWorkItem?

    // Parameters from the most recent connect()/connectProxy() call, replayed by
    // performFastReconnect() when NWPathMonitor detects a network change. Mirrors
    // what Android's ConnectivityManager.NetworkCallback does (trigger a fast
    // restart instead of waiting on the Rust client's passive 1s->60s backoff).
    private var lastConnectFullTunnel: Bool = false
    private var lastConnectMtlsCertPath: String?
    private var lastConnectExcludeRoutes: String?
    private var lastConnectAdaptiveLevel: Int = 0
    private var lastConnectDnsProxy: String?
    private var lastConnectKillSwitch: Bool = false
    private var lastConnectPreferredMask: String?
    private var lastConnectPolymorphicBase: String?
    private var lastConnectShareMaskFeedback: Bool = false
    private var lastConnectReceiveMaskHints: Bool = false
    private var lastConnectCountryCode: String?
    private var lastConnectProxyPort: Int?

    private var proxyProcess: Process?
    private var proxyPollTimer: Timer?
    private var proxyPollStartTime: Date?
    private let proxyConnectTimeout: TimeInterval = 30.0
    private let proxyLogPath: String = {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("aivpn-proxy.log").path
        return tmp
    }()

    private let socketPath = "/var/run/aivpn/helper.sock"

    // Use UserDefaults instead of Keychain to avoid keychain prompts
    // for ad-hoc signed apps. The key is only useful with the server anyway.
    private let defaults = UserDefaults.standard

    init() {
        // KeychainStorage.shared already calls loadKeys() in its own init
        selectedKeyId = KeychainStorage.shared.selectedKeyId
        
        // Для обратной совместимости: если есть старый ключ и нет новых, добавить его
        if let raw = defaults.string(forKey: "connection_key"), !raw.isEmpty {
            let keyValue = ConnectionKey.normalizeKeyValue(raw)
            if KeychainStorage.shared.keys.isEmpty {
                _ = KeychainStorage.shared.addKey(name: "Default", keyValue: keyValue)
                selectedKeyId = KeychainStorage.shared.selectedKeyId
            }
            defaults.removeObject(forKey: "connection_key")
            defaults.synchronize()
        }

        startNetworkPathMonitor()
    }

    /// Returns the bundled aivpn-client path that is acceptable to the privileged helper.
    /// Only paths inside /Applications/ or /Library/ are in the helper's allowlist.
    /// Returns nil when running from DerivedData/Downloads — helper then uses DEFAULT_CLIENT_PATH.
    private func helperClientBinaryPath() -> String? {
        let candidates = [
            Bundle.main.bundlePath + "/Contents/Resources/aivpn-client",
            Bundle.main.bundlePath + "/Contents/MacOS/aivpn-client",
        ]
        let trustedPrefixes = ["/Applications/", "/Library/"]
        for path in candidates {
            let trusted = trustedPrefixes.contains(where: { path.hasPrefix($0) })
            if trusted, FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    /// Returns the bundled aivpn-client path for use as the current user (proxy mode, no helper).
    /// Does not require a trusted install location — proxy mode runs as the logged-in user.
    private func bundledClientBinaryPath() -> String? {
        let candidates = [
            Bundle.main.bundlePath + "/Contents/Resources/aivpn-client",
            Bundle.main.bundlePath + "/Contents/MacOS/aivpn-client",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    private func runBundledClientCommand(_ args: [String], completion: ((Bool, String) -> Void)? = nil) {
        guard let binaryPath = bundledClientBinaryPath() else {
            completion?(false, "Bundled aivpn-client not found")
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: binaryPath)
            task.arguments = args

            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = outputPipe

            // Drain the pipe CONCURRENTLY with the child. Reading only after
            // waitUntilExit deadlocks once the child writes more than the pipe
            // buffer (~64KB): the child blocks on write, we block on wait.
            var outputData = Data()
            let drainDone = DispatchSemaphore(value: 0)
            let readHandle = outputPipe.fileHandleForReading
            DispatchQueue.global(qos: .utility).async {
                outputData = readHandle.readDataToEndOfFile()
                drainDone.signal()
            }

            do {
                try task.run()
            } catch {
                // Unblock the drain: with no child holding the write end, EOF
                // only arrives after we close our own copy.
                outputPipe.fileHandleForWriting.closeFile()
                _ = drainDone.wait(timeout: .now() + 1)
                DispatchQueue.main.async {
                    completion?(false, error.localizedDescription)
                }
                return
            }

            // Bounded wait — bench can legitimately run for tens of seconds;
            // a child hung beyond that is killed instead of leaking this block
            // (and the child) forever.
            let deadline = Date().addingTimeInterval(60)
            while task.isRunning && Date() < deadline {
                usleep(100_000)
            }
            if task.isRunning {
                task.terminate()
                usleep(500_000)
                if task.isRunning {
                    kill(task.processIdentifier, SIGKILL)
                }
            }
            task.waitUntilExit()
            // After exit all write ends are closed, so the drain finishes
            // promptly; the timeout is a safety bound, not an expected path.
            _ = drainDone.wait(timeout: .now() + 2)
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            DispatchQueue.main.async {
                completion?(task.terminationStatus == 0, output)
            }
        }
    }

    /// Routes a record_* action through the privileged helper. The record CLI
    /// authenticates against a per-uid admin token/socket (/tmp/aivpn-<uid>);
    /// the full-tunnel client runs as root (uid 0), so record commands issued
    /// as the console user target /tmp/aivpn-501 where no daemon listens and
    /// are ALWAYS rejected. Only proxy mode (client runs as the current user)
    /// may keep using runBundledClientCommand for record commands.
    private func sendRecordCommandViaHelper(_ action: String, service: String? = nil,
                                            completion: ((Bool, String) -> Void)? = nil) {
        let request = HelperRequest(action: action, key: nil, fullTunnel: nil,
                                    binaryPath: helperClientBinaryPath(), service: service,
                                    mtlsCertPath: nil, excludeRoutes: nil,
                                    adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil)
        // The helper bounds the record subcommand at 10s; leave headroom.
        sendToHelper(request, timeoutSeconds: 15.0) { response in
            guard let response = response else {
                completion?(false, "Helper not responding")
                return
            }
            completion?(response.status == "ok", response.message)
        }
    }

    private func loadRecordingInfoFromDisk() -> RecordingInfoSnapshot? {
        for path in recordingStatusPaths {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                continue
            }
            if let snapshot = try? JSONDecoder().decode(RecordingInfoSnapshot.self, from: data) {
                return snapshot
            }
        }
        return nil
    }

    private func requestRecordingStatusRefresh() {
        if isProxyMode {
            runBundledClientCommand(["record", "status"], completion: nil)
        } else {
            sendRecordCommandViaHelper("record_status", completion: nil)
        }
    }

    func clearRecordingResult() {
        lastRecordingResult = nil
    }

    private func postConnectionNotification(connected: Bool) {
        let content = UNMutableNotificationContent()
        let loc = LocalizationManager.shared
        content.title = connected ? loc.t("notification_connected") : loc.t("notification_disconnected")
        content.sound = .default
        let id = "aivpn.connection.\(connected ? "on" : "off").\(Int(Date().timeIntervalSince1970))"
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private func postRecordingResultNotification(title: String, body: String, updatedAtMs: UInt64) {
        guard updatedAtMs > lastRecordingNotificationTimestamp else {
            return
        }

        lastRecordingNotificationTimestamp = updatedAtMs

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "aivpn.recording.\(updatedAtMs)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Key Management
    
    /// Выбрать ключ по ID
    func selectKey(id: String?) {
        selectedKeyId = id
        KeychainStorage.shared.selectKey(id: id)
        
        if let key = KeychainStorage.shared.selectedKey {
            savedKey = key.keyValue
        }
    }
    
    /// Добавить новый ключ
    func addKey(name: String, keyValue: String, mtlsCertPath: String? = nil,
                bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
                bootstrapTelegramChat: String? = nil,
                bootstrapGithub: String? = nil,
                serverSigningKey: String? = nil) -> Bool {
        if let newKey = KeychainStorage.shared.addKey(name: name, keyValue: keyValue, mtlsCertPath: mtlsCertPath,
                                                       bootstrapCdnUrl: bootstrapCdnUrl, bootstrapTelegramToken: bootstrapTelegramToken,
                                                       bootstrapTelegramChat: bootstrapTelegramChat,
                                                       bootstrapGithub: bootstrapGithub,
                                                       serverSigningKey: serverSigningKey) {
            KeychainStorage.shared.selectKey(id: newKey.id)
            selectedKeyId = newKey.id
            savedKey = newKey.keyValue
            return true
        }
        return false
    }
    
    /// Удалить ключ
    func deleteKey(id: String) {
        KeychainStorage.shared.deleteKey(id: id)
        if selectedKeyId == id {
            selectedKeyId = KeychainStorage.shared.selectedKeyId
            savedKey = KeychainStorage.shared.selectedKey?.keyValue ?? ""
        }
    }
    
    /// Обновить имя ключа
    func updateKeyName(id: String, newName: String) {
        KeychainStorage.shared.updateKeyName(id: id, newName: newName)
    }
    
    /// Обновить ключ полностью
    func updateKey(id: String, name: String, keyValue: String, mtlsCertPath: String? = nil,
                   bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
                   bootstrapTelegramChat: String? = nil,
                   bootstrapGithub: String? = nil,
                   serverSigningKey: String? = nil) -> Bool {
        let updated = KeychainStorage.shared.updateKey(id: id, name: name, keyValue: keyValue, mtlsCertPath: mtlsCertPath,
                                                        bootstrapCdnUrl: bootstrapCdnUrl, bootstrapTelegramToken: bootstrapTelegramToken,
                                                        bootstrapTelegramChat: bootstrapTelegramChat,
                                                        bootstrapGithub: bootstrapGithub,
                                                        serverSigningKey: serverSigningKey)
        if updated, selectedKeyId == id,
           let key = KeychainStorage.shared.keys.first(where: { $0.id == id }) {
            savedKey = key.keyValue
        }
        return updated
    }

    /// Получить выбранный ключ
    var selectedKey: ConnectionKey? {
        guard let id = selectedKeyId else {
            return nil
        }
        return KeychainStorage.shared.keys.first(where: { $0.id == id })
    }

    // MARK: - Helper Communication

    /// Send a request to the helper daemon via Unix socket with timeout
    private func sendToHelper(_ request: HelperRequest, timeoutSeconds: Double = 3.0,
                              completion: @escaping (HelperResponse?) -> Void) {
        let sockPath = self.socketPath
        DispatchQueue.global(qos: .userInitiated).async {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                NSLog("AIVPN IPC[%@]: socket() failed: %s", request.action, strerror(errno))
                DispatchQueue.main.async {
                    completion(nil)
                }
                return
            }

            // Set connection timeout
            var timeout = timeval(tv_sec: Int(timeoutSeconds), tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                       &timeout, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, socklen_t(MemoryLayout<timeval>.size))

            // Build sockaddr_un
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = Array(sockPath.utf8)
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                for (i, byte) in pathBytes.enumerated() where i < buf.count - 1 {
                    buf[i] = byte
                }
            }
            let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

            let connectResult = withUnsafePointer(to: &addr) {
                Darwin.connect(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), addrLen)
            }

            guard connectResult == 0 else {
                NSLog("AIVPN IPC[%@]: connect() failed: %s", request.action, strerror(errno))
                close(fd)
                DispatchQueue.main.async {
                    completion(nil)
                }
                return
            }

            // Send request with 4-byte big-endian length prefix
            let requestData: Data
            do {
                requestData = try JSONEncoder().encode(request)
            } catch {
                NSLog("AIVPN IPC[%@]: encode failed: %@", request.action, "\(error)")
                close(fd)
                DispatchQueue.main.async { completion(nil) }
                return
            }

            let payloadLen = requestData.count
            var lenBuf: [UInt8] = [
                UInt8((payloadLen >> 24) & 0xFF),
                UInt8((payloadLen >> 16) & 0xFF),
                UInt8((payloadLen >>  8) & 0xFF),
                UInt8( payloadLen        & 0xFF),
            ]
            var lenSent = 0
            while lenSent < 4 {
                let n = lenBuf.withUnsafeBytes { raw in
                    write(fd, raw.baseAddress!.advanced(by: lenSent), 4 - lenSent)
                }
                if n <= 0 {
                    NSLog("AIVPN IPC[%@]: prefix write failed at %d: %s",
                          request.action, lenSent, strerror(errno))
                    close(fd)
                    DispatchQueue.main.async { completion(nil) }
                    return
                }
                lenSent += n
            }
            var payloadSent = 0
            let sendResult = requestData.withUnsafeBytes { rawBuf -> Bool in
                guard let base = rawBuf.baseAddress else { return false }
                while payloadSent < payloadLen {
                    let n = write(fd, base.advanced(by: payloadSent), payloadLen - payloadSent)
                    if n <= 0 { return false }
                    payloadSent += n
                }
                return true
            }
            if !sendResult {
                NSLog("AIVPN IPC[%@]: payload write failed: %s", request.action, strerror(errno))
                close(fd)
                DispatchQueue.main.async { completion(nil) }
                return
            }

            // Read response — loop until EOF (server closes connection after reply).
            // A single read() on SOCK_STREAM is not guaranteed to return the full
            // payload; reading until n == 0 (EOF) is the correct framing strategy.
            var accum = Data()
            var tmpBuf = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(fd, &tmpBuf, tmpBuf.count)
                if n > 0 {
                    accum.append(contentsOf: tmpBuf[0..<n])
                } else {
                    break  // n == 0: EOF; n < 0: error or SO_RCVTIMEO elapsed
                }
            }
            close(fd)

            guard !accum.isEmpty else {
                NSLog("AIVPN IPC[%@]: empty response (read timeout/EOF): %s",
                      request.action, strerror(errno))
                DispatchQueue.main.async { completion(nil) }
                return
            }

            if let response = try? JSONDecoder().decode(HelperResponse.self, from: accum) {
                if response.status != "ok" {
                    NSLog("AIVPN IPC[%@]: helper replied status=%@ message=%@",
                          request.action, response.status, response.message)
                }
                DispatchQueue.main.async { completion(response) }
            } else {
                NSLog("AIVPN IPC[%@]: undecodable response (%d bytes): %@",
                      request.action, accum.count,
                      String(data: accum.prefix(200), encoding: .utf8) ?? "<binary>")
                DispatchQueue.main.async { completion(nil) }
            }
        }
    }

    /// Check if the helper daemon is available
    func checkHelperAvailable() {
        isCheckingHelper = true
        sendToHelper(HelperRequest(action: "ping", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil),                     timeoutSeconds: 2.0) { [weak self] response in
            guard let self = self else { return }
            self.isCheckingHelper = false
            if let response = response, response.status == "ok" {
                self.helperAvailable = true
                self.helperVersion = response.version ?? ""
                // Check if already connected
                if let connected = response.connected, connected {
                    self.isConnected = true
                    self.startStatusPolling()
                    self.startTrafficMonitor()
                } else if response.pid != nil {
                    // A client process exists but isn't connected yet
                    // (connecting or mid-reconnect) — poll to track the
                    // transition. When the helper is idle (no client at all)
                    // do NOT start polling: the 2s loop used to run forever
                    // from app launch with nothing to report.
                    self.startStatusPolling()
                }
            } else {
                self.helperAvailable = false
            }
        }
    }

    // MARK: - Connect / Disconnect

    func connect(key: String, fullTunnel: Bool = false, mtlsCertPath: String? = nil, excludeRoutes: String? = nil, adaptiveLevel: Int = 0, dnsProxy: String? = nil, killSwitch: Bool = false, preferredMask: String? = nil, polymorphicBase: String? = nil, shareMaskFeedback: Bool = false, receiveMaskHints: Bool = false, countryCode: String? = nil, bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil, bootstrapTelegramChat: String? = nil, bootstrapGithub: String? = nil, serverSigningKey: String? = nil) {
        guard !isConnecting else { return }
        guard !isConnected else { return }

        let normalizedKey = ConnectionKey.normalizeKeyValue(key)

        savedKey = normalizedKey
        lastConnectFullTunnel = fullTunnel
        lastConnectMtlsCertPath = mtlsCertPath
        lastConnectExcludeRoutes = excludeRoutes
        lastConnectAdaptiveLevel = adaptiveLevel
        lastConnectDnsProxy = dnsProxy
        lastConnectKillSwitch = killSwitch
        lastConnectPreferredMask = preferredMask
        lastConnectPolymorphicBase = polymorphicBase
        lastConnectShareMaskFeedback = shareMaskFeedback
        lastConnectReceiveMaskHints = receiveMaskHints
        lastConnectCountryCode = countryCode

        connectGeneration += 1
        isConnecting = true
        lastError = nil
        bytesSent = 0
        bytesReceived = 0
        lastTrafficSince = 0
        recordingState = .idle
        canRecordMasks = false
        recordingCapabilityKnown = false
        lastRecordingResult = nil
        minimumRecordingStatusTimestamp = currentTimestampMs()
        serverAdaptiveLevel = 0

        // Determine binary path — prefer the one bundled in the app
        let binaryPath = helperClientBinaryPath()

        let request = HelperRequest(
            action: "connect",
            key: normalizedKey,
            fullTunnel: fullTunnel,
            binaryPath: binaryPath,
            service: nil,
            mtlsCertPath: mtlsCertPath,
            excludeRoutes: excludeRoutes,
            adaptiveLevel: adaptiveLevel > 0 ? adaptiveLevel : nil,
            dnsProxy: dnsProxy.flatMap { $0.isEmpty ? nil : $0 },
            killSwitch: killSwitch ? true : nil,
            preferredMask: preferredMask.flatMap { $0.isEmpty || $0 == "auto" ? nil : $0 },
            polymorphicBase: polymorphicBase.flatMap { $0.isEmpty || $0 == "auto" ? nil : $0 },
            shareMaskFeedback: shareMaskFeedback ? true : nil,
            receiveMaskHints: receiveMaskHints ? true : nil,
            countryCode: countryCode.flatMap { $0.count == 2 ? $0 : nil },
            bootstrapCdnUrl: bootstrapCdnUrl.flatMap { $0.isEmpty ? nil : $0 },
            bootstrapTelegramToken: bootstrapTelegramToken.flatMap { $0.isEmpty ? nil : $0 },
            bootstrapTelegramChat: bootstrapTelegramChat.flatMap { $0.isEmpty ? nil : $0 },
            bootstrapGithub: bootstrapGithub.flatMap { $0.isEmpty ? nil : $0 },
            serverSigningKey: serverSigningKey.flatMap { $0.isEmpty ? nil : $0 }
        )

        sendToHelper(request) { [weak self] response in
            guard let self = self else { return }

            if let response = response, response.status == "ok" {
                // Start polling for status changes
                self.startStatusPolling()
                self.requestRecordingStatusRefresh()
            } else {
                self.isConnecting = false
                if let response = response {
                    self.lastError = response.message
                } else {
                    self.lastError = "Helper not responding"
                    self.checkHelperAvailable()
                }
            }
        }
    }

    // MARK: - Proxy Mode (no root required for ports > 1024)

    /// Launch aivpn-client directly as current user in SOCKS5 proxy mode.
    /// Does NOT go through the privileged helper — root is not needed for high ports.
    func connectProxy(key: String, proxyPort: Int, preferredMask: String? = nil, polymorphicBase: String? = nil, shareMaskFeedback: Bool = false, receiveMaskHints: Bool = false, countryCode: String? = nil) {
        guard !isConnecting else { return }

        let normalizedKey = ConnectionKey.normalizeKeyValue(key)

        savedKey = normalizedKey
        lastConnectProxyPort = proxyPort
        lastConnectPreferredMask = preferredMask
        lastConnectPolymorphicBase = polymorphicBase
        lastConnectShareMaskFeedback = shareMaskFeedback
        lastConnectReceiveMaskHints = receiveMaskHints
        lastConnectCountryCode = countryCode

        // Warn if an mTLS cert is configured — it is silently ignored in proxy mode
        if let certPath = selectedKey?.mtlsCertPath, !certPath.isEmpty {
            print("Warning: mTLS certificate '\(certPath)' is not used in SOCKS5 proxy mode")
        }

        isConnecting = true
        isProxyMode = true
        lastError = nil
        bytesSent = 0
        bytesReceived = 0
        lastTrafficSince = 0

        guard let binaryPath = bundledClientBinaryPath() else {
            isConnecting = false
            isProxyMode = false
            lastError = "aivpn-client binary not found in app bundle"
            return
        }

        // Clear log file with secure permissions
        if !FileManager.default.createFile(atPath: proxyLogPath, contents: nil, attributes: [.posixPermissions: 0o600]) {
            isConnecting = false
            isProxyMode = false
            lastError = "Cannot create proxy log file"
            return
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: proxyLogPath)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        // The connection key (contains the PSK) goes via the AIVPN_CONNECTION_KEY
        // environment variable, NOT argv — argv is visible to every same-uid
        // process via `ps`. The Rust client falls back to the env var when -k
        // is absent and scrubs it from its own environment after parsing
        // (crates/aivpn-client/src/main.rs). Mirrors the Linux/Windows GUIs.
        var processArgs = ["--proxy-listen", "127.0.0.1:\(proxyPort)"]
        // Polymorphic base takes precedence over preferredMask, mirroring the
        // helper's startClient() behavior for the full-tunnel connect path.
        // Same pattern gate as aivpn-helper/main.swift's isAcceptableMaskId —
        // this path has no privileged helper in front of it (SOCKS5/no-admin
        // mode launches aivpn-client directly), so it must validate itself.
        // A pattern (not a preset allow-list) because mask ids come from the
        // server-pushed catalog, including generated ids; Process passes argv
        // directly with no shell. An id that fails the gate is logged, not
        // silently dropped.
        if let polyBase = polymorphicBase, !polyBase.isEmpty, polyBase != "auto" {
            if Self.isAcceptableMaskId(polyBase) {
                processArgs += ["--polymorphic-base", polyBase]
            } else {
                NSLog("AIVPN: invalid polymorphic base '%@' — ignored", polyBase)
            }
        } else if let mask = preferredMask, !mask.isEmpty, mask != "auto" {
            if Self.isAcceptableMaskId(mask) {
                processArgs += ["--preferred-mask", mask]
            } else {
                NSLog("AIVPN: invalid preferred mask '%@' — ignored", mask)
            }
        }
        if shareMaskFeedback {
            processArgs += ["--share-mask-feedback"]
        }
        if receiveMaskHints {
            processArgs += ["--receive-mask-hints"]
        }
        // Require exactly two ASCII A-Z letters — matches the helper's rule
        // and the CLI's own validation (rejects Cyrillic/Greek confusables
        // that `.count == 2` alone would let through).
        if let cc = countryCode, !cc.isEmpty {
            let normalizedCc = cc.uppercased()
            if normalizedCc.count == 2, normalizedCc.allSatisfy({ $0.isASCII && $0.isLetter }) {
                processArgs += ["--country-code", normalizedCc]
            }
        }
        process.arguments = processArgs
        var env = ProcessInfo.processInfo.environment
        env["RUST_LOG"] = "info"
        env["AIVPN_CONNECTION_KEY"] = normalizedKey
        process.environment = env

        let logHandle = FileHandle(forWritingAtPath: proxyLogPath)
        if let fh = logHandle {
            process.standardOutput = fh
            process.standardError = fh
        }

        let logPath = self.proxyLogPath
        process.terminationHandler = { [weak self] _ in
            logHandle?.closeFile()
            try? FileManager.default.removeItem(atPath: logPath)
            DispatchQueue.main.async {
                guard let self = self, self.isProxyMode else { return }
                self.stopProxyPoll()
                self.proxyProcess = nil
                self.isConnected = false
                self.isConnecting = false
                self.isProxyMode = false
            }
        }

        do {
            try process.run()
            proxyProcess = process
            startProxyPoll()
        } catch {
            logHandle?.closeFile()
            try? FileManager.default.removeItem(atPath: proxyLogPath)
            isConnecting = false
            isProxyMode = false
            lastError = "Failed to start proxy: \(error.localizedDescription)"
        }
    }

    private func stopProxyMode() {
        proxyProcess?.terminate()
        proxyProcess = nil
        stopProxyPoll()
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.isConnected = false
            self.isConnecting = false
            self.isProxyMode = false
        }
    }

    private func startProxyPoll() {
        proxyPollTimer?.invalidate()
        proxyPollStartTime = Date()
        proxyPollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.pollProxyLog()
        }
    }

    private func stopProxyPoll() {
        proxyPollTimer?.invalidate()
        proxyPollTimer = nil
    }

    private func pollProxyLog() {
        // Timeout check is cheap and must happen on the main thread to mutate state.
        if let start = proxyPollStartTime, Date().timeIntervalSince(start) > proxyConnectTimeout {
            lastError = "Proxy connection timed out"
            // Tear the spawned client down too — flipping UI state alone
            // leaked the process, which kept running detached forever.
            stopProxyMode()
            return
        }
        // File I/O is dispatched off the main thread to avoid blocking the RunLoop.
        let path = proxyLogPath
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let log = try? String(contentsOfFile: path, encoding: .utf8) else { return }
            DispatchQueue.main.async { [weak self] in
                guard let self = self, self.isConnecting else { return }
                if log.contains("SOCKS5 proxy listening") {
                    self.stopProxyPoll()
                    self.isConnected = true
                    self.isConnecting = false
                } else {
                    // Only a real ERROR-level tracing record counts as failure —
                    // a bare substring match ("error") would abort the connect on
                    // ordinary INFO lines containing URLs, counters or hostnames.
                    let lines = log.components(separatedBy: "\n").filter { !$0.isEmpty }
                    if let errLine = lines.last(where: { Self.isErrorLogLine($0) }) {
                        self.lastError = String(errLine.prefix(200))
                        // Mirror the timeout path: terminate the client we
                        // spawned instead of leaking it after a declared
                        // connect failure.
                        self.stopProxyMode()
                    }
                }
            }
        }
    }

    /// Run `aivpn-client bench --server <addr> --json` and return parsed result.
    /// Calls completion on the main thread; passes nil on failure.
    func runBench(serverAddr: String, completion: @escaping (BenchDisplayResult?) -> Void) {
        runBundledClientCommand(["bench", "--server", serverAddr, "--json"]) { success, output in
            guard success,
                  let data = output.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(nil)
                return
            }
            let result = BenchDisplayResult(
                p50: json["latency_p50_ms"] as? Double ?? 0,
                p95: json["latency_p95_ms"] as? Double ?? 0,
                p99: json["latency_p99_ms"] as? Double ?? 0,
                lossPct: json["packet_loss_pct"] as? Double ?? 0,
                qualityScore: json["quality_score"] as? Int ?? 0
            )
            completion(result)
        }
    }

    /// - Parameter completion: optional, called on the main thread once disconnect state
    ///   has actually settled (after the helper IPC round-trip, or immediately for proxy
    ///   mode). Used by performFastReconnect() to sequence a reconnect without racing
    ///   isConnected/isConnecting, which are only flipped once the helper responds.
    func disconnect(completion: (() -> Void)? = nil) {
        if isProxyMode {
            stopProxyMode()
            completion?()
            return
        }

        let request = HelperRequest(action: "disconnect", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil)
        let disconnectGen = connectGeneration
        sendToHelper(request) { [weak self] _ in
            guard let self = self else { return }
            // Guard: skip all state resets if connect() was called again before this
            // callback fired (stale disconnect clobbering new connection state).
            guard self.connectGeneration == disconnectGen else {
                completion?()
                return
            }
            self.stopStatusPolling()
            self.trafficTimer?.invalidate()
            self.trafficTimer = nil
            self.recordingState = .idle
            self.canRecordMasks = false
            self.recordingCapabilityKnown = false
            self.lastRecordingResult = nil
            self.minimumRecordingStatusTimestamp = 0
            self.isConnecting = false
            self.isConnected = false
            self.serverAdaptiveLevel = 0
            // Re-ping helper after disconnect so connectButtonEnabled stays true.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.checkHelperAvailable()
            }
            completion?()
        }
    }

    /// Synchronous best-effort disconnect used on app termination (Quit button /
    /// applicationWillTerminate). The regular disconnect() is fully async — its
    /// helper IPC runs on a background queue and its completion hops back to the
    /// main thread — so calling it right before NSApp.terminate() races process
    /// exit and can leave the VPN up. This variant performs the socket round-trip
    /// inline on the calling thread with a short timeout instead. It deliberately
    /// does NOT touch @Published state: the process is about to exit.
    func disconnectBlocking(timeoutSeconds: Double = 1.5) {
        if isProxyMode {
            proxyProcess?.terminate()
            proxyProcess = nil
            return
        }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var timeout = timeval(tv_sec: Int(timeoutSeconds),
                              tv_usec: Int32((timeoutSeconds.truncatingRemainder(dividingBy: 1)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, byte) in pathBytes.enumerated() where i < buf.count - 1 {
                buf[i] = byte
            }
        }
        let connected = withUnsafePointer(to: &addr) {
            Darwin.connect(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self),
                           socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
        }
        guard connected else { return }

        let request = HelperRequest(action: "disconnect", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil)
        guard let requestData = try? JSONEncoder().encode(request) else { return }
        let payloadLen = requestData.count
        var lenBuf: [UInt8] = [
            UInt8((payloadLen >> 24) & 0xFF),
            UInt8((payloadLen >> 16) & 0xFF),
            UInt8((payloadLen >>  8) & 0xFF),
            UInt8( payloadLen        & 0xFF),
        ]
        guard write(fd, &lenBuf, 4) == 4 else { return }
        let sentAll = requestData.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress else { return false }
            var sent = 0
            while sent < payloadLen {
                let n = write(fd, base.advanced(by: sent), payloadLen - sent)
                if n <= 0 { return false }
                sent += n
            }
            return true
        }
        guard sentAll else { return }
        // Wait (bounded by SO_RCVTIMEO) until the helper has processed the
        // disconnect and closed the connection — this is the whole point of the
        // blocking variant: the client process is down before we return.
        var tmpBuf = [UInt8](repeating: 0, count: 1024)
        while read(fd, &tmpBuf, tmpBuf.count) > 0 {}
    }

    /// True for a well-formed mask id: lowercase alphanumerics + underscore,
    /// bounded length. Mirrors the helper's isAcceptableMaskId — accepts every
    /// server-catalog id (presets, generated, recorded) without a preset list.
    static func isAcceptableMaskId(_ id: String) -> Bool {
        return id.range(of: "^[a-z0-9_]{1,64}$", options: .regularExpression) != nil
    }

    /// True when an (ANSI-stripped) log line is an actual ERROR-level tracing
    /// record — level token at/near line start — rather than any line merely
    /// containing the substring "error".
    static func isErrorLogLine(_ rawLine: String) -> Bool {
        let line = rawLine.replacingOccurrences(
            of: "\u{001b}\\[[0-9;]*m", with: "", options: .regularExpression
        )
        if line.hasPrefix("ERROR") { return true }
        return line.range(of: #"^\S+\s+ERROR\s"#, options: .regularExpression) != nil
    }

    func startMaskRecording(serviceName: String) {
        let trimmedService = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedService.isEmpty else {
            lastError = "Mask service name is required"
            return
        }
        guard isConnected else {
            lastError = "Connect before recording a mask"
            return
        }
        guard selectedKey != nil else {
            lastError = "No connection key selected"
            return
        }
        guard canRecordMasks else {
            lastError = "Server did not grant recording access for this key"
            return
        }

        minimumRecordingStatusTimestamp = currentTimestampMs()
        lastRecordingResult = nil
        recordingState = .starting(service: trimmedService)

        let onResult: (Bool, String) -> Void = { [weak self] ok, output in
            guard let self = self else { return }
            if !ok {
                self.recordingState = .failed(service: trimmedService, reason: output.isEmpty ? "Failed to start recording" : output)
            }
        }
        if isProxyMode {
            runBundledClientCommand(["record", "start", "--service", trimmedService], completion: onResult)
        } else {
            sendRecordCommandViaHelper("record_start", service: trimmedService, completion: onResult)
        }
    }

    func stopMaskRecording() {
        let currentService: String
        switch recordingState {
        case .recording(let service), .starting(let service):
            currentService = service
        default:
            lastError = "No active recording to stop"
            return
        }

        minimumRecordingStatusTimestamp = currentTimestampMs()
        recordingState = .stopping(service: currentService)
        let onResult: (Bool, String) -> Void = { [weak self] ok, output in
            guard let self = self else { return }
            if !ok {
                self.recordingState = .failed(service: currentService, reason: output.isEmpty ? "Failed to stop recording" : output)
            }
        }
        if isProxyMode {
            runBundledClientCommand(["record", "stop"], completion: onResult)
        } else {
            sendRecordCommandViaHelper("record_stop", completion: onResult)
        }
    }

    // MARK: - Status Polling (replaces log file monitoring)

    private func startStatusPolling() {
        statusPollTimer?.invalidate()
        // Poll every 2 seconds
        statusPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.pollStatus()
        }
    }

    private func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
    }

    private func pollStatus() {
        sendToHelper(HelperRequest(action: "status", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil),                     timeoutSeconds: 2.0) { [weak self] response in
            guard let self = self, let response = response else { return }

            // Proxy mode has its own process + poll timer (proxyPollTimer). The helper
            // manages no client in proxy mode, so it reports connected:false — which this
            // handler would misread as an unexpected drop and tear down the proxy UI state.
            guard !self.isProxyMode else { return }

            guard response.status == "ok" else { return }

            let connected = response.connected ?? false
            let message = response.message

            // G-A4: authenticated terminal handshake refusal — the helper's
            // getStatus() surfaces this as a well-known
            // "AIVPN-STATUS rejected <token>" message (see rejectToken() in
            // aivpn-helper/main.swift, itself scanning for the exact line
            // client.rs's HandshakeReject arm prints — see
            // handshake_reject_token there). Checked before the connected/
            // failure branching below so it fires whether the poll still
            // sees the pid alive (still-connecting window) or already
            // reports "Process exited" (the client's own terminal_rejected
            // reconnect-loop break in main.rs usually wins that race).
            // Mirrors the Linux GUI's parse_status_line "rejected" arm,
            // just localized here instead of hardcoded English.
            if message.hasPrefix("AIVPN-STATUS rejected ") {
                let token = String(message.dropFirst("AIVPN-STATUS rejected ".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                self.isConnecting = false
                self.isConnected = false
                self.lastError = LocalizationManager.shared.rejectReasonText(token: token)
                self.stopStatusPolling()
                self.trafficTimer?.invalidate()
                self.trafficTimer = nil
                self.serverAdaptiveLevel = 0
                self.postConnectionNotification(connected: false)
                // The client already exited on its own (terminal_rejected
                // stops main.rs's reconnect loop before it ever retries) —
                // this just reaps any leftover helper-side pid/state so a
                // stale entry can't linger; a no-op if it's already gone.
                self.sendToHelper(HelperRequest(action: "disconnect", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil)) { _ in }
                return
            }

            if connected && !self.isConnected {
                // Transition: connecting → connected
                self.isConnecting = false
                self.isConnected = true
                self.lastError = nil
                self.startTrafficMonitor()
                self.postConnectionNotification(connected: true)
            } else if !connected && self.isConnected {
                // Transition: connected → disconnected (unexpected drop)
                self.isConnecting = false
                self.isConnected = false
                self.lastError = message
                self.stopStatusPolling()
                self.trafficTimer?.invalidate()
                self.trafficTimer = nil
                self.serverAdaptiveLevel = 0
                self.postConnectionNotification(connected: false)
                // Re-ping so the Connect button is re-enabled immediately.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                    self?.checkHelperAvailable()
                }
            } else if !connected && self.isConnecting {
                // Still connecting — check if process died (error message).
                // The bare-substring "error" check is gone: helper status
                // messages for errors either start with "ERROR" (extracted from
                // an ERROR-level log record by getStatus) or contain the
                // explicit words below — matching "error" anywhere misclassified
                // benign progress lines as failures.
                let lowerMsg = message.lowercased()
                let isFailure = lowerMsg.contains("exited") ||
                                lowerMsg.contains("failed") ||
                                message.hasPrefix("ERROR") ||
                                message.contains(" ERROR ") ||
                                lowerMsg.contains("not found")

                if isFailure {
                    self.isConnecting = false
                    self.isConnected = false
                    self.lastError = message
                    self.stopStatusPolling()
                    // A transient ERROR line does not mean the root client
                    // died — after declaring failure to the user, actually
                    // tear the client down instead of leaving it running
                    // detached from the UI state. No-op if it already exited.
                    self.sendToHelper(HelperRequest(action: "disconnect", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil)) { _ in }
                } else {
                    // Still connecting — update status message for user
                    self.lastError = nil
                }
            }

            if connected || self.isConnected {
                self.refreshRecordingInfo()
            }
        }
    }

    private func refreshRecordingInfo() {
        if let snapshot = loadRecordingInfoFromDisk() {
            let applied = applyRecordingInfo(snapshot)
            if !applied || snapshot.can_record == nil {
                requestRecordingStatusRefresh()
            }
        } else {
            requestRecordingStatusRefresh()
        }
    }

    @discardableResult
    private func applyRecordingInfo(_ snapshot: RecordingInfoSnapshot) -> Bool {
        if snapshot.updated_at_ms < minimumRecordingStatusTimestamp {
            return false
        }

        minimumRecordingStatusTimestamp = snapshot.updated_at_ms
        recordingCapabilityKnown = snapshot.can_record != nil
        canRecordMasks = snapshot.can_record ?? false

        let service = snapshot.service ?? selectedKey?.name ?? "mask"
        switch snapshot.state {
        case "recording":
            recordingState = .recording(service: service)
        case "stopping":
            recordingState = .stopping(service: service)
        case "analyzing":
            recordingState = .analyzing(service: service)
        case "success":
            recordingState = .success(service: service, maskId: snapshot.mask_id)
            let loc = LocalizationManager.shared
            let successTitle = loc.t("recording_result_success_title")
            let successDetails: String
            if let maskId = snapshot.mask_id, !maskId.isEmpty {
                successDetails = "ID: \(maskId)"
            } else {
                successDetails = service
            }
            lastRecordingResult = RecordingResultSummary(
                succeeded: true,
                title: successTitle,
                details: successDetails,
                updatedAtMs: snapshot.updated_at_ms
            )
            postRecordingResultNotification(title: successTitle, body: successDetails, updatedAtMs: snapshot.updated_at_ms)
        case "failed":
            let reason = snapshot.message ?? service
            recordingState = .failed(service: service, reason: reason)
            let loc = LocalizationManager.shared
            let failTitle = loc.t("recording_result_failed_title")
            lastRecordingResult = RecordingResultSummary(
                succeeded: false,
                title: failTitle,
                details: reason,
                updatedAtMs: snapshot.updated_at_ms
            )
            postRecordingResultNotification(title: failTitle, body: reason, updatedAtMs: snapshot.updated_at_ms)
        default:
            recordingState = .idle
        }

        return true
    }

    // MARK: - Traffic Monitor

    private func startTrafficMonitor() {
        trafficTimer?.invalidate()
        trafficTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.updateTrafficStats()
        }
    }
    
    /// Update traffic statistics from helper logs
    private func updateTrafficStats() {
        // Get log from helper and parse traffic stats
        sendToHelper(HelperRequest(action: "traffic", key: nil, fullTunnel: nil, binaryPath: nil, service: nil, mtlsCertPath: nil, excludeRoutes: nil, adaptiveLevel: nil, dnsProxy: nil, killSwitch: nil),                     timeoutSeconds: 1.0) { [weak self] response in
            guard let self = self,
                  let response = response,
                  response.status == "ok" else {
                return
            }
            
            // Response message contains "sent:X,received:Y,since:E,quality:Z"
            let parts = response.message.components(separatedBy: ",")

            // The client stamps its stats with a per-session `since:` epoch
            // (unix ms). A CHANGE in since means the client silently
            // re-established in-process: reset the displayed counters first so
            // the new (lower) absolute values are an intentional restart, not
            // a glitch, regardless of field order in the message.
            for part in parts {
                let kv = part.components(separatedBy: ":")
                if kv.count == 2, kv[0] == "since", let value = Int64(kv[1]) {
                    if self.lastTrafficSince != 0 && value != self.lastTrafficSince {
                        self.bytesSent = 0
                        self.bytesReceived = 0
                    }
                    self.lastTrafficSince = value
                }
            }

            for part in parts {
                let kv = part.components(separatedBy: ":")
                if kv.count == 2 {
                    let key = kv[0]
                    let valStr = kv[1]
                    if key == "sent", let value = Int64(valStr) {
                        self.bytesSent = value
                    } else if key == "received", let value = Int64(valStr) {
                        self.bytesReceived = value
                    } else if key == "quality", let value = Int(valStr) {
                        self.qualityScore = value
                    } else if key == "adaptive", let value = Int(valStr) {
                        self.serverAdaptiveLevel = value
                    }
                }
            }
        }
    }

    // MARK: - Network Path Monitoring

    /// Starts watching for network path changes (wifi<->cellular switches, sleep/wake,
    /// connectivity drops/restores). Runs for the lifetime of the app — the handler only
    /// acts when the VPN is supposed to be connected. This is the macOS analog of
    /// Android's ConnectivityManager.NetworkCallback-driven fast restart: instead of
    /// waiting for the Rust client's passive reconnect backoff to notice the network
    /// changed, we proactively cycle disconnect()/connect() (or connectProxy()) so the
    /// tunnel re-establishes on the new path immediately.
    private func startNetworkPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.handlePathUpdate(path)
            }
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
    }

    private func handlePathUpdate(_ path: NWPath) {
        let previousStatus = lastPathStatus
        let previousPrimary = lastPathPrimaryInterfaceType
        // availableInterfaces is priority-ordered; the first entry is the one
        // traffic actually rides. Comparing the whole SET restarted the tunnel
        // whenever any SECONDARY interface appeared or vanished (iPhone hotspot
        // plugged in, dock ethernet blip, Wi-Fi re-validating while Ethernet is
        // primary) even though the ridden path never changed — the same
        // reconnect ping-pong fixed on Android for standby-SIM announcements.
        let currentPrimary = path.availableInterfaces.first?.type

        lastPathStatus = path.status
        lastPathPrimaryInterfaceType = currentPrimary

        // First callback only establishes the baseline — nothing has changed yet.
        guard let previousStatus = previousStatus else { return }

        // Network came back after being unreachable (e.g. wifi drop -> reconnect),
        // or the interface traffic rides changed while still online (e.g.
        // wifi -> cellular handover, or waking from sleep on a different network).
        let networkRestored = previousStatus != .satisfied && path.status == .satisfied
        let interfaceSwitched = path.status == .satisfied
            && previousPrimary != nil && currentPrimary != nil
            && currentPrimary != previousPrimary

        guard networkRestored || interfaceSwitched else { return }
        guard isConnected, !isConnecting else { return }

        scheduleFastReconnect()
    }

    private func scheduleFastReconnect() {
        networkChangeReconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            self?.performFastReconnect()
        }
        networkChangeReconnectWorkItem = workItem
        // Short debounce: a real network switch (old interface down, new interface up)
        // can fire NWPathMonitor's handler several times in quick succession.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0, execute: workItem)
    }

    /// Re-establishes the tunnel using the parameters from the most recent connect()
    /// or connectProxy() call. Triggered by a detected network change rather than the
    /// user; safe to call no-op if the VPN is no longer connected by the time it runs.
    private func performFastReconnect() {
        guard isConnected, !isConnecting else { return }
        guard !savedKey.isEmpty else { return }

        if isProxyMode {
            let key = savedKey
            let port = lastConnectProxyPort ?? 1080
            let mask = lastConnectPreferredMask
            let polymorphicBase = lastConnectPolymorphicBase
            let shareMaskFeedback = lastConnectShareMaskFeedback
            let receiveMaskHints = lastConnectReceiveMaskHints
            let countryCode = lastConnectCountryCode
            stopProxyMode()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.connectProxy(key: key, proxyPort: port, preferredMask: mask,
                                    polymorphicBase: polymorphicBase,
                                    shareMaskFeedback: shareMaskFeedback,
                                    receiveMaskHints: receiveMaskHints,
                                    countryCode: countryCode)
            }
        } else {
            let key = savedKey
            let fullTunnel = lastConnectFullTunnel
            let mtlsCertPath = lastConnectMtlsCertPath
            let excludeRoutes = lastConnectExcludeRoutes
            let adaptiveLevel = lastConnectAdaptiveLevel
            let dnsProxy = lastConnectDnsProxy
            let killSwitch = lastConnectKillSwitch
            let preferredMask = lastConnectPreferredMask
            let polymorphicBase = lastConnectPolymorphicBase
            let shareMaskFeedback = lastConnectShareMaskFeedback
            let receiveMaskHints = lastConnectReceiveMaskHints
            let countryCode = lastConnectCountryCode
            // Wait for disconnect's helper round-trip to actually flip isConnected/isConnecting
            // before reconnecting — connect() no-ops while isConnected is still true.
            disconnect { [weak self] in
                self?.connect(key: key, fullTunnel: fullTunnel, mtlsCertPath: mtlsCertPath,
                               excludeRoutes: excludeRoutes, adaptiveLevel: adaptiveLevel,
                               dnsProxy: dnsProxy, killSwitch: killSwitch, preferredMask: preferredMask,
                               polymorphicBase: polymorphicBase, shareMaskFeedback: shareMaskFeedback,
                               receiveMaskHints: receiveMaskHints, countryCode: countryCode)
            }
        }
    }

}
