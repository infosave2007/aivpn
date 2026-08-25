import Darwin
import Foundation
import Security
import SwiftUI

// MARK: - Bootstrap Descriptor Discovery
//
// Lets a user who has no working `aivpn://` connection key yet discover a
// server by fetching signed "bootstrap descriptors" from one or more
// distribution channels (CDN, GitHub release asset, Telegram bot) — the
// same multi-channel concept implemented server-side in
// `crates/aivpn-server/src/bootstrap_publish.rs` and client-side (CLI) in
// `crates/aivpn-client/src/bootstrap_loader.rs`.
//
// IMPORTANT ARCHITECTURAL NOTE — read before changing this file:
// `BootstrapDescriptor` (crates/aivpn-common/src/mask.rs) carries only
// traffic-mimicry MASK material (candidate masks + a KDF salt) — it does
// NOT carry a server host, port, or public key. So fetching descriptors
// alone cannot "discover a server" from nothing; the operator must still
// hand the user a server address + server public key + the descriptor
// signing public key through some other short, low-bandwidth channel
// (word of mouth, SMS, a QR code — anything that's harder to block than a
// full `aivpn://` blob with masks baked in). What this flow actually
// automates is fetching *fresh, signed, rotating* mask material for that
// known server, instead of requiring the operator to hand out a brand-new
// full connection key every time a mask gets DPI-fingerprinted.
//
// This runs entirely in the main app process (never in the
// NEPacketTunnelProvider extension) per the project's design constraint:
// a multi-channel HTTP fetch with retries must not race the extension's
// tunnel-startup completion handler.

// MARK: - Hex helpers (server key / PSK / signing key are entered as hex,
// matching TunnelConnectionKey's own hex parsing in PacketTunnelProvider.swift
// — note this differs from the CLI/Android connection-key format, which
// uses base64 for "k"/"p". Keys built here are consumed exclusively by this
// app's own PacketTunnelProvider, so hex is the correct format here.)

enum HexCodec {
    static func decode(_ string: String) -> [UInt8]? {
        let clean = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let byte = UInt8(clean[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        return bytes
    }

    static func encode(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

func base64URLNoPad(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// MARK: - Persisted channel configuration
//
// Only non-secret operator-distributed values (URLs, repo names, a public
// signing key) are persisted, so the user doesn't have to retype them on
// every launch. Server address / server key / PSK are NOT persisted here —
// once a discovery run succeeds they live only inside the resulting
// ConnectionKey, protected by Keychain via KeychainStorage (the same
// mechanism every other connection key already uses).
struct BootstrapChannelSettings: Equatable {
    var cdnURL: String = ""
    var githubRepo: String = ""
    /// A REAL credential — possession grants control of the bootstrap-
    /// distribution bot — unlike the other fields here, which are just
    /// distribution endpoints/public keys. Deliberately excluded from this
    /// struct's Codable payload below (see CodingKeys) so it is never
    /// written into the plaintext UserDefaults blob the other fields use;
    /// it is persisted separately in the Keychain by
    /// BootstrapChannelSettingsStore instead.
    var telegramBotToken: String = ""
    var telegramChatId: String = ""
    var signingPublicKeyHex: String = ""
}

// Manual Codable conformance (not derived): `telegramBotToken` is
// intentionally omitted from both encode(to:) and init(from:) so it can
// never round-trip through the UserDefaults-backed JSON blob. Decoding
// always leaves it at "" — callers (BootstrapChannelSettingsStore.init)
// are responsible for filling it in from the Keychain afterwards.
extension BootstrapChannelSettings: Codable {
    private enum CodingKeys: String, CodingKey {
        case cdnURL, githubRepo, telegramChatId, signingPublicKeyHex
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cdnURL = try c.decodeIfPresent(String.self, forKey: .cdnURL) ?? ""
        githubRepo = try c.decodeIfPresent(String.self, forKey: .githubRepo) ?? ""
        telegramChatId = try c.decodeIfPresent(String.self, forKey: .telegramChatId) ?? ""
        signingPublicKeyHex = try c.decodeIfPresent(String.self, forKey: .signingPublicKeyHex) ?? ""
        telegramBotToken = ""
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(cdnURL, forKey: .cdnURL)
        try c.encode(githubRepo, forKey: .githubRepo)
        try c.encode(telegramChatId, forKey: .telegramChatId)
        try c.encode(signingPublicKeyHex, forKey: .signingPublicKeyHex)
    }
}

/// Stores the Telegram bootstrap-discovery bot token in the Keychain
/// instead of plaintext UserDefaults (which is an unencrypted plist,
/// included in local/iCloud device backups). Uses the same access class
/// as ConnectionKey.swift's primary Keychain items —
/// kSecAttrAccessibleWhenUnlockedThisDeviceOnly — since this is app-local
/// state, not shared with the tunnel extension (no access group needed).
private enum BootstrapTokenKeychain {
    private static let service = "com.aivpn.client.bootstrap-telegram-token"
    private static let account = "telegram_bot_token"

    static func load() -> String? {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit:  kSecMatchLimitOne,
            kSecReturnData:  true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ token: String) {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        guard !token.isEmpty, let data = token.data(using: .utf8) else {
            SecItemDelete(query as CFDictionary)
            return
        }
        let update: [CFString: Any] = [kSecValueData: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var attrs = query
            attrs[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            attrs[kSecValueData] = data
            SecItemAdd(attrs as CFDictionary, nil)
        }
    }
}

final class BootstrapChannelSettingsStore: ObservableObject {
    static let shared = BootstrapChannelSettingsStore()

    @Published var settings: BootstrapChannelSettings

    private let defaultsKey = "bootstrap_discovery_channels_v1"

    init() {
        if let data = UserDefaults.standard.data(forKey: defaultsKey),
           let decoded = try? JSONDecoder().decode(BootstrapChannelSettings.self, from: data) {
            settings = decoded
        } else {
            settings = BootstrapChannelSettings()
        }
        settings.telegramBotToken = BootstrapTokenKeychain.load() ?? ""
    }

    func save() {
        guard let data = try? JSONEncoder().encode(settings) else { return }
        UserDefaults.standard.set(data, forKey: defaultsKey)
        BootstrapTokenKeychain.save(settings.telegramBotToken)
    }
}

// MARK: - Discovery results

enum BootstrapChannelKind: String {
    case cdn = "CDN"
    case github = "GitHub"
    case telegram = "Telegram"
}

struct BootstrapChannelResult: Identifiable {
    let id = UUID()
    let channel: BootstrapChannelKind
    let success: Bool
    let descriptorsFound: Int
    let error: String?
}

struct BootstrapDiscoveryOutcome {
    /// Verified, non-expired descriptor JSON objects, ready to embed as the
    /// connection key's "bd" (inline bootstrap descriptors) field.
    let validDescriptors: [[String: Any]]
    let channelResults: [BootstrapChannelResult]
}

// MARK: - Fetch + verify service

enum BootstrapDiscoveryService {
    /// Re-applies the SSRF guard to every redirect hop. URLSession follows
    /// redirects automatically, and isURLAllowed alone only vets the INITIAL
    /// URL — without this a compromised CDN could 302 to
    /// https://169.254.169.254/… and reach a private host. Passing nil to the
    /// completion handler rejects the hop: the task then completes with the
    /// 3xx response itself, which the callers' 2xx status checks turn into a
    /// clean channel failure. Mirrors the Android per-hop re-guard.
    private final class RedirectGuard: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession,
                        task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            if let target = request.url?.absoluteString,
               BootstrapDiscoveryService.isURLAllowed(target) {
                completionHandler(request)
            } else {
                completionHandler(nil)
            }
        }
    }

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        return URLSession(configuration: config, delegate: RedirectGuard(), delegateQueue: nil)
    }()

    /// Rejects everything except HTTPS with a host that resolves exclusively
    /// to public addresses — mirrors (in spirit, not byte-for-byte) the SSRF
    /// guard already applied server/CLI-side in bootstrap_loader.rs's
    /// validate_bootstrap_url.
    static func isURLAllowed(_ urlString: String) -> Bool {
        guard urlString.lowercased().hasPrefix("https://") else { return false }
        guard let url = URL(string: urlString), let host = url.host?.lowercased() else { return false }
        let blockedExact: Set<String> = ["localhost", "::1"]
        if blockedExact.contains(host) { return false }
        if host.hasPrefix("127.") || host.hasPrefix("10.") || host.hasPrefix("192.168.")
            || host.hasPrefix("169.254.") { return false }
        if host.hasPrefix("172.") {
            let parts = host.split(separator: ".")
            if parts.count > 1, let second = Int(parts[1]), (16...31).contains(second) { return false }
        }
        // The literal string checks above are only a cheap fast-fail: they
        // miss decimal/octal/hex loopback spellings ("2130706433",
        // "0177.0.0.1", "0x7f.0.0.1"), IPv6 link-local/ULA, IPv4-mapped IPv6,
        // and any hostname that RESOLVES to a private address (DNS
        // rebinding). Resolve the host and verify the actual addresses.
        // Residual: URLSession re-resolves at fetch time, so a fast-fluxing
        // rebinder can still swap records between this check and the fetch —
        // impact stays bounded because responses must carry valid
        // ed25519-signed descriptors to be used at all.
        return hostResolvesToPublicAddressesOnly(host)
    }

    /// Resolves `host` via getaddrinfo and returns true only when it
    /// resolves to at least one address and NONE of the resolved addresses
    /// is private/loopback/link-local/ULA. getaddrinfo also canonicalizes
    /// the exotic IPv4 literal spellings (single-decimal, octal, hex), so
    /// they cannot dodge the dotted-prefix checks above. Unresolvable hosts
    /// fail closed.
    private static func hostResolvesToPublicAddressesOnly(_ host: String) -> Bool {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC,
                             ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0, let first = list else {
            return false
        }
        defer { freeaddrinfo(first) }
        var sawAddress = false
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let cur = node {
            if let sa = cur.pointee.ai_addr {
                sawAddress = true
                if isPrivateSockaddr(sa) { return false }
            }
            node = cur.pointee.ai_next
        }
        return sawAddress
    }

    /// True when `sa` is a loopback / RFC1918 / link-local / CGNAT /
    /// broadcast IPv4 address, or a loopback / unspecified / link-local /
    /// site-local / unique-local / IPv4-mapped-private IPv6 address —
    /// anything a bootstrap fetch must never be pointed at. Unknown address
    /// families fail closed.
    private static func isPrivateSockaddr(_ sa: UnsafePointer<sockaddr>) -> Bool {
        func privateV4(_ a: UInt8, _ b: UInt8) -> Bool {
            switch a {
            case 0, 10, 127, 255: return true
            case 169: return b == 254
            case 172: return (16...31).contains(b)
            case 192: return b == 168
            case 100: return (64...127).contains(b) // CGNAT 100.64.0.0/10
            default: return false
            }
        }
        switch Int32(sa.pointee.sa_family) {
        case AF_INET:
            let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            return privateV4(UInt8(ip >> 24), UInt8((ip >> 16) & 0xFF))
        case AF_INET6:
            let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                withUnsafeBytes(of: $0.pointee.sin6_addr) { Array($0) }
            }
            guard bytes.count == 16 else { return true }
            // ::1 loopback / :: unspecified
            if bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] <= 1 { return true }
            // fe80::/10 link-local, fec0::/10 (deprecated site-local)
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { return true }
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0 { return true }
            // fc00::/7 unique-local
            if (bytes[0] & 0xfe) == 0xfc { return true }
            // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d):
            // re-check the embedded IPv4 against the same private ranges.
            if bytes[0..<10].allSatisfy({ $0 == 0 })
                && ((bytes[10] == 0xff && bytes[11] == 0xff)
                    || (bytes[10] == 0 && bytes[11] == 0)) {
                return privateV4(bytes[12], bytes[13])
            }
            return false
        default:
            return true
        }
    }

    /// Runs every configured channel, verifies each returned descriptor's
    /// ed25519 signature + expiry via the Rust FFI, and returns only the
    /// descriptors that passed. Channels are independent — one failing
    /// never blocks the others.
    static func fetchAndVerify(
        settings: BootstrapChannelSettings,
        signingKey: [UInt8]
    ) async -> BootstrapDiscoveryOutcome {
        var results: [BootstrapChannelResult] = []
        var valid: [[String: Any]] = []

        if !settings.cdnURL.trimmingCharacters(in: .whitespaces).isEmpty {
            let (descriptors, result) = await fetchCDN(url: settings.cdnURL, signingKey: signingKey)
            valid.append(contentsOf: descriptors)
            results.append(result)
        }

        if !settings.githubRepo.trimmingCharacters(in: .whitespaces).isEmpty {
            let (descriptors, result) = await fetchGitHub(repo: settings.githubRepo, signingKey: signingKey)
            valid.append(contentsOf: descriptors)
            results.append(result)
        }

        if !settings.telegramBotToken.trimmingCharacters(in: .whitespaces).isEmpty {
            let (descriptors, result) = await fetchTelegram(
                botToken: settings.telegramBotToken,
                chatId: settings.telegramChatId,
                signingKey: signingKey)
            valid.append(contentsOf: descriptors)
            results.append(result)
        }

        return BootstrapDiscoveryOutcome(validDescriptors: valid, channelResults: results)
    }

    // MARK: CDN

    private static func fetchCDN(url: String, signingKey: [UInt8]) async -> ([[String: Any]], BootstrapChannelResult) {
        guard isURLAllowed(url), let requestURL = URL(string: url) else {
            return ([], BootstrapChannelResult(channel: .cdn, success: false, descriptorsFound: 0,
                                                error: "URL rejected — must be https:// and not a private host"))
        }
        do {
            let (data, response) = try await session.data(from: requestURL)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                return ([], BootstrapChannelResult(channel: .cdn, success: false, descriptorsFound: 0,
                                                    error: "unexpected HTTP status"))
            }
            let valid = verifyAll(data, signingKey: signingKey)
            return (valid, BootstrapChannelResult(channel: .cdn, success: true, descriptorsFound: valid.count, error: nil))
        } catch {
            return ([], BootstrapChannelResult(channel: .cdn, success: false, descriptorsFound: 0,
                                                error: error.localizedDescription))
        }
    }

    // MARK: GitHub release asset
    //
    // Mirrors bootstrap_loader.rs's load_from_github: hit
    // /repos/{repo}/releases/latest, find the asset whose name contains
    // "bootstrap", download it, and validate the download URL is HTTPS
    // before fetching (the release JSON's browser_download_url is
    // server-controlled by GitHub but not by us, so it still gets the same
    // SSRF guard as any other channel URL).

    private static func fetchGitHub(repo: String, signingKey: [UInt8]) async -> ([[String: Any]], BootstrapChannelResult) {
        let trimmedRepo = repo.trimmingCharacters(in: .whitespaces)
        guard let releaseURL = URL(string: "https://api.github.com/repos/\(trimmedRepo)/releases/latest") else {
            return ([], BootstrapChannelResult(channel: .github, success: false, descriptorsFound: 0,
                                                error: "invalid repo"))
        }
        var request = URLRequest(url: releaseURL)
        request.setValue("aivpn-ios", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                return ([], BootstrapChannelResult(channel: .github, success: false, descriptorsFound: 0,
                                                    error: "unexpected HTTP status"))
            }
            guard let release = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let assets = release["assets"] as? [[String: Any]] else {
                return ([], BootstrapChannelResult(channel: .github, success: false, descriptorsFound: 0,
                                                    error: "malformed release JSON"))
            }
            for asset in assets {
                guard let name = asset["name"] as? String, name.contains("bootstrap"),
                      let downloadURLString = asset["browser_download_url"] as? String,
                      isURLAllowed(downloadURLString),
                      let downloadURL = URL(string: downloadURLString) else { continue }
                let (assetData, assetResponse) = try await session.data(from: downloadURL)
                guard let assetHttp = assetResponse as? HTTPURLResponse,
                      (200...299).contains(assetHttp.statusCode) else { continue }
                let valid = verifyAll(assetData, signingKey: signingKey)
                return (valid, BootstrapChannelResult(channel: .github, success: true,
                                                       descriptorsFound: valid.count, error: nil))
            }
            return ([], BootstrapChannelResult(channel: .github, success: false, descriptorsFound: 0,
                                                error: "no bootstrap asset found in latest release"))
        } catch {
            return ([], BootstrapChannelResult(channel: .github, success: false, descriptorsFound: 0,
                                                error: error.localizedDescription))
        }
    }

    // MARK: Telegram
    //
    // Simplified vs. the Rust reference implementation: uses the Bot API's
    // getUpdates long-poll endpoint to scan recent messages/channel posts
    // for a document attachment (matching how bootstrap_publish.rs's
    // publish_telegram sends the descriptor array via sendDocument), then
    // downloads that document through the file API. getUpdates only
    // returns messages since the bot's last poll offset — a known
    // limitation of this simplified client-side implementation, not a bug;
    // a production deployment would more likely use a fixed, pinned
    // message ID or a webhook instead.

    private static func fetchTelegram(
        botToken: String,
        chatId: String,
        signingKey: [UInt8]
    ) async -> ([[String: Any]], BootstrapChannelResult) {
        let token = botToken.trimmingCharacters(in: .whitespaces)
        let wantChat = chatId.trimmingCharacters(in: .whitespaces)
        guard let updatesURL = URL(string: "https://api.telegram.org/bot\(token)/getUpdates?limit=50") else {
            return ([], BootstrapChannelResult(channel: .telegram, success: false, descriptorsFound: 0,
                                                error: "invalid bot token"))
        }
        do {
            let (data, response) = try await session.data(from: updatesURL)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                return ([], BootstrapChannelResult(channel: .telegram, success: false, descriptorsFound: 0,
                                                    error: "unexpected HTTP status"))
            }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let updates = json["result"] as? [[String: Any]] else {
                return ([], BootstrapChannelResult(channel: .telegram, success: false, descriptorsFound: 0,
                                                    error: "malformed getUpdates response"))
            }

            for update in updates.reversed() {
                guard let message = (update["message"] as? [String: Any])
                        ?? (update["channel_post"] as? [String: Any]) else { continue }
                if !wantChat.isEmpty, let chat = message["chat"] as? [String: Any] {
                    let idMatches = chat["id"].map { "\($0)" } == wantChat
                    let usernameMatches = (chat["username"] as? String).map { "@\($0)" == wantChat } ?? false
                    if !idMatches && !usernameMatches { continue }
                }
                guard let document = message["document"] as? [String: Any],
                      let fileId = document["file_id"] as? String else { continue }

                guard let getFileURL = URL(string: "https://api.telegram.org/bot\(token)/getFile?file_id=\(fileId)") else {
                    continue
                }
                let (fileMetaData, _) = try await session.data(from: getFileURL)
                guard let fileMetaJSON = try? JSONSerialization.jsonObject(with: fileMetaData) as? [String: Any],
                      let fileResult = fileMetaJSON["result"] as? [String: Any],
                      let filePath = fileResult["file_path"] as? String,
                      let downloadURL = URL(string: "https://api.telegram.org/file/bot\(token)/\(filePath)") else {
                    continue
                }
                let (docData, docResponse) = try await session.data(from: downloadURL)
                guard let docHttp = docResponse as? HTTPURLResponse,
                      (200...299).contains(docHttp.statusCode) else { continue }
                let valid = verifyAll(docData, signingKey: signingKey)
                if !valid.isEmpty {
                    return (valid, BootstrapChannelResult(channel: .telegram, success: true,
                                                           descriptorsFound: valid.count, error: nil))
                }
            }
            return ([], BootstrapChannelResult(channel: .telegram, success: false, descriptorsFound: 0,
                                                error: "no verifiable bootstrap document found in recent updates"))
        } catch {
            return ([], BootstrapChannelResult(channel: .telegram, success: false, descriptorsFound: 0,
                                                error: error.localizedDescription))
        }
    }

    // MARK: - Parsing + FFI verification

    /// Splits a channel response body into individual descriptor JSON
    /// objects (the body may be a JSON array or, per
    /// parse_descriptors_from_json's Rust behaviour, a single object) and
    /// keeps only the ones that verify.
    private static func verifyAll(_ data: Data, signingKey: [UInt8]) -> [[String: Any]] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) else { return [] }
        let dicts: [[String: Any]]
        if let array = obj as? [[String: Any]] {
            dicts = array
        } else if let single = obj as? [String: Any] {
            dicts = [single]
        } else {
            dicts = []
        }
        return dicts.filter { verifyOne($0, signingKey: signingKey) }
    }

    /// Re-serializes a single descriptor dictionary and calls
    /// `aivpn_verify_bootstrap_descriptor` (crates/aivpn-ios-core) to check
    /// its ed25519 signature and expiry, reusing
    /// `BootstrapDescriptor::verify_signature` from aivpn-common instead of
    /// reimplementing crypto in Swift.
    private static func verifyOne(_ dict: [String: Any], signingKey: [UInt8]) -> Bool {
        guard signingKey.count == 32,
              JSONSerialization.isValidJSONObject(dict),
              let json = try? JSONSerialization.data(withJSONObject: dict) else { return false }

        var jsonBytes = [UInt8](json)
        var key = signingKey
        let verified: Bool = jsonBytes.withUnsafeMutableBufferPointer { jsonBuf in
            key.withUnsafeMutableBufferPointer { keyBuf in
                guard let jsonBase = jsonBuf.baseAddress, let keyBase = keyBuf.baseAddress else {
                    return false
                }
                return aivpn_verify_bootstrap_descriptor(jsonBase, jsonBuf.count, keyBase) == 1
            }
        }
        return verified
    }
}

// MARK: - Discover Server sheet

struct BootstrapDiscoveryView: View {
    @EnvironmentObject private var vpn: VPNManager
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = BootstrapChannelSettingsStore.shared

    @State private var serverAddress: String = ""
    @State private var serverPublicKeyHex: String = ""
    @State private var pskHex: String = ""
    @State private var keyName: String = ""

    @State private var isDiscovering: Bool = false
    @State private var errorMessage: String?
    @State private var successMessage: String?
    @State private var channelResults: [BootstrapChannelResult] = []

    var body: some View {
        NavigationStack {
            Form {
                Section(header: Text(loc.t("bootstrap_server_section")),
                        footer: Text(loc.t("advanced_hint")).font(.caption2).foregroundColor(.secondary)) {
                    TextField(loc.t("bootstrap_server_address"), text: $serverAddress)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    TextField(loc.t("bootstrap_server_pubkey"), text: $serverPublicKeyHex)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 12, design: .monospaced))
                    TextField(loc.t("bootstrap_server_psk"), text: $pskHex)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 12, design: .monospaced))
                    TextField(loc.t("bootstrap_key_name"), text: $keyName)
                        .autocorrectionDisabled()
                }

                Section(header: Text(loc.t("bootstrap_channels_section"))) {
                    TextField(loc.t("bootstrap_signing_pubkey"), text: $store.settings.signingPublicKeyHex)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 12, design: .monospaced))
                    TextField(loc.t("bootstrap_cdn_url"), text: $store.settings.cdnURL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    TextField(loc.t("bootstrap_github_repo"), text: $store.settings.githubRepo)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField(loc.t("bootstrap_telegram_bot_token"), text: $store.settings.telegramBotToken)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField(loc.t("bootstrap_telegram_chat"), text: $store.settings.telegramChatId)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                Section {
                    if isDiscovering {
                        HStack {
                            ProgressView()
                            Text(loc.t("bootstrap_discovering"))
                        }
                    } else {
                        Button(loc.t("bootstrap_discover_button")) {
                            runDiscovery()
                        }
                        .disabled(!canDiscover)
                    }
                }

                if let error = errorMessage {
                    Section {
                        Text(error).foregroundColor(.red).font(.caption)
                    }
                }
                if let success = successMessage {
                    Section {
                        Text(success).foregroundColor(.green).font(.caption)
                    }
                }
                if !channelResults.isEmpty {
                    Section(header: Text(loc.t("bootstrap_channel_results"))) {
                        ForEach(channelResults) { result in
                            HStack {
                                Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundColor(result.success ? .green : .red)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(result.channel.rawValue).font(.caption).bold()
                                    if result.success {
                                        Text("\(result.descriptorsFound)").font(.caption2).foregroundColor(.secondary)
                                    } else if let err = result.error {
                                        Text(err).font(.caption2).foregroundColor(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(loc.t("bootstrap_discovery_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
            .onDisappear { store.save() }
        }
    }

    private var canDiscover: Bool {
        !isDiscovering
            && !serverAddress.trimmingCharacters(in: .whitespaces).isEmpty
            && !serverPublicKeyHex.trimmingCharacters(in: .whitespaces).isEmpty
            && !store.settings.signingPublicKeyHex.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func runDiscovery() {
        errorMessage = nil
        successMessage = nil
        channelResults = []

        guard let serverKeyBytes = HexCodec.decode(serverPublicKeyHex), serverKeyBytes.count == 32 else {
            errorMessage = loc.t("bootstrap_invalid_server_key")
            return
        }
        guard let signingKeyBytes = HexCodec.decode(store.settings.signingPublicKeyHex),
              signingKeyBytes.count == 32 else {
            errorMessage = loc.t("bootstrap_invalid_signing_key")
            return
        }
        let trimmedAddress = serverAddress.trimmingCharacters(in: .whitespaces)
        guard !trimmedAddress.isEmpty else {
            errorMessage = loc.t("bootstrap_missing_fields")
            return
        }

        isDiscovering = true
        store.save()
        let settingsSnapshot = store.settings

        Task {
            let outcome = await BootstrapDiscoveryService.fetchAndVerify(
                settings: settingsSnapshot, signingKey: signingKeyBytes)

            await MainActor.run {
                isDiscovering = false
                channelResults = outcome.channelResults

                guard !outcome.validDescriptors.isEmpty else {
                    errorMessage = loc.t("bootstrap_result_failure")
                    return
                }

                var payload: [String: Any] = [
                    "s": trimmedAddress,
                    "k": HexCodec.encode(serverKeyBytes),
                ]
                if let pskBytes = HexCodec.decode(pskHex), pskBytes.count == 32 {
                    payload["p"] = HexCodec.encode(pskBytes)
                }
                payload["bd"] = outcome.validDescriptors

                guard JSONSerialization.isValidJSONObject(payload),
                      let jsonData = try? JSONSerialization.data(withJSONObject: payload) else {
                    errorMessage = loc.t("bootstrap_encode_failed")
                    return
                }

                let blob = base64URLNoPad(jsonData)
                let trimmedName = keyName.trimmingCharacters(in: .whitespaces)
                let name = trimmedName.isEmpty
                    ? "\(loc.t("bootstrap_default_key_name")) \(DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .short))"
                    : trimmedName

                guard vpn.addKey(name: name, keyValue: blob) else {
                    errorMessage = loc.t("duplicate_key")
                    return
                }

                let successCount = outcome.channelResults.filter { $0.success }.count
                successMessage = loc.t("bootstrap_result_success")
                    .replacingOccurrences(of: "{n}", with: "\(outcome.validDescriptors.count)")
                    .replacingOccurrences(of: "{m}", with: "\(successCount)")
                    .replacingOccurrences(of: "{name}", with: name)
            }
        }
    }
}
