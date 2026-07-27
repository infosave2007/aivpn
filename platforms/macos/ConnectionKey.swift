import Foundation

/// Модель ключа подключения
struct ConnectionKey: Identifiable, Codable, Equatable {
    let id: String  // UUID для идентификации
    var name: String  // Пользовательское имя
    let keyValue: String  // Сам ключ (без aivpn://)
    let serverAddress: String?  // Извлеченный адрес сервера
    let vpnIP: String?  // Извлеченный VPN IP
    let canRecord: Bool?  // Права на запись масок (из поля can_record в ключе)
    var mtlsCertPath: String?  // Путь к mTLS-сертификату клиента (опционально)

    // Advanced/operator bootstrap discovery settings (opt-in, per key). Lets a
    // client with no working aivpn:// connection yet discover a usable
    // server/mask via signed multi-channel fallback (CDN/Telegram/GitHub).
    // Not needed by ordinary users who already have a key — see ContentView's
    // "Advanced (bootstrap discovery)" disclosure group.
    var bootstrapCdnUrl: String?
    var bootstrapTelegramToken: String?
    var bootstrapTelegramChat: String?
    var bootstrapGithub: String?
    var serverSigningKey: String?

    init(id: String = UUID().uuidString, name: String, keyValue: String, mtlsCertPath: String? = nil,
         bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
         bootstrapTelegramChat: String? = nil,
         bootstrapGithub: String? = nil,
         serverSigningKey: String? = nil) {
        self.id = id
        self.name = name
        self.keyValue = Self.normalizeKeyValue(keyValue)
        self.mtlsCertPath = mtlsCertPath
        self.bootstrapCdnUrl = bootstrapCdnUrl
        self.bootstrapTelegramToken = bootstrapTelegramToken
        self.bootstrapTelegramChat = bootstrapTelegramChat
        self.bootstrapGithub = bootstrapGithub
        self.serverSigningKey = serverSigningKey

        // Извлекаем данные из ключа (URL-safe base64 без padding)
        var server: String? = nil
        var ip: String? = nil
        var record: Bool? = nil

        // Metadata extraction is deliberately NOT gated on the `k` format check:
        // even if `k` is malformed, the server address / VPN IP / can_record /
        // embedded `sk` signing key must still be adopted so that (a) the UI can
        // display something useful and (b) ed25519 signature verification is never
        // silently disabled by an unrelated validation detail. Strict format
        // enforcement happens in isValidKeyString() at add/edit time.
        if let json = Self.decodePayload(self.keyValue) {
            server = json["s"] as? String
            ip = json["i"] as? String
            record = json["can_record"] as? Bool
            // Adopt the embedded signing key ("sk") unless one was passed explicitly.
            if self.serverSigningKey == nil,
               let sk = json["sk"] as? String, !sk.isEmpty {
                self.serverSigningKey = sk
            }
        }

        self.serverAddress = server
        self.vpnIP = ip
        self.canRecord = record
    }

    /// Strips surrounding whitespace and a single LEADING "aivpn://" scheme
    /// prefix. `replacingOccurrences` would also delete the substring from the
    /// MIDDLE of the payload — silently corrupting any key that happened to
    /// contain it — so only a prefix strip is correct.
    static func normalizeKeyValue(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("aivpn://") {
            value = String(value.dropFirst("aivpn://".count))
        }
        return value
    }

    // MARK: - Strict validation (mirrors the tunnel/client parser requirements)

    /// Decodes the base64url JSON payload of a normalized key value (no "aivpn://" prefix).
    private static func decodePayload(_ keyValue: String) -> [String: Any]? {
        // Convert URL-safe base64 to standard base64 for Foundation decoding
        var b64 = keyValue
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Add padding if needed
        let remainder = b64.count % 4
        if remainder > 0 {
            b64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: b64) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    /// True when `s` encodes exactly 32 bytes in one of the two on-the-wire
    /// formats:
    ///   1. STANDARD base64 (44 chars incl. padding) — the format the server
    ///      actually emits for `k`/`p` (crates/aivpn-server/src/main.rs
    ///      build_connection_key: base64 STANDARD of the X25519 pubkey) and the
    ///      format the Rust client (decode_base64_key) and Android decode.
    ///   2. 64-char ASCII hex — accepted as a legacy/manual fallback.
    /// Base64 is tried first because it is the real-world format.
    static func isValid32ByteKey(_ s: String) -> Bool {
        if let data = Data(base64Encoded: s), data.count == 32 { return true }
        return strictHex32(s) != nil
    }

    /// Strict ASCII-only hex decode of exactly 64 hex chars → 32 bytes.
    /// Deliberately byte-based (UTF-8), NOT Character.hexDigitValue, which also
    /// matches fullwidth Unicode digits that the Rust side would reject.
    static func strictHex32(_ s: String) -> Data? {
        let ascii = Array(s.utf8)
        guard ascii.count == 64 else { return nil }
        var bytes = [UInt8](); bytes.reserveCapacity(32)
        var i = 0
        while i < 64 {
            guard let hi = Self.hexNibble(ascii[i]), let lo = Self.hexNibble(ascii[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
            i += 2
        }
        return Data(bytes)
    }

    private static func hexNibble(_ b: UInt8) -> UInt8? {
        switch b {
        case 0x30...0x39: return b - 0x30            // '0'-'9'
        case 0x41...0x46: return b - 0x41 + 10       // 'A'-'F'
        case 0x61...0x66: return b - 0x61 + 10       // 'a'-'f'
        default: return nil
        }
    }

    /// Strict add/edit validation: the key must be base64(JSON) containing a
    /// non-empty server address `s` and a server public key `k` decoding to
    /// exactly 32 bytes (standard base64 — the server's real format — or
    /// 64-char hex). Rejecting bad keys here surfaces a clear error at add
    /// time instead of an opaque connect failure later.
    static func isValidKeyString(_ raw: String) -> Bool {
        let norm = normalizeKeyValue(raw)
        guard let json = decodePayload(norm),
              let s = json["s"] as? String, !s.isEmpty,
              let k = json["k"] as? String, isValid32ByteKey(k) else { return false }
        return true
    }

    /// Полный ключ с префиксом
    var fullKey: String {
        return "aivpn://\(keyValue)"
    }
    
    /// Отображаемое имя с сервером
    var displayName: String {
        if let server = serverAddress {
            return "\(name) (\(server))"
        }
        return name
    }

    var isRecordingAdminKey: Bool {
        return canRecord ?? false
    }

    /// Host-only portion of serverAddress, with IPv6 brackets stripped.
    /// "[::1]:443"   → "::1"
    /// "1.2.3.4:443" → "1.2.3.4"
    /// Returns nil when serverAddress is nil.
    var serverHost: String? {
        guard let addr = serverAddress else { return nil }
        if addr.hasPrefix("[") {
            // IPv6 bracketed form: "[::1]:443"
            if let closeBracket = addr.firstIndex(of: "]") {
                return String(addr[addr.index(after: addr.startIndex)..<closeBracket])
            }
            return addr
        }
        // IPv4 or bare hostname: take the part before the last colon
        return addr.components(separatedBy: ":").dropLast().joined(separator: ":").nonEmpty ?? addr
    }
}

private extension String {
    /// Returns nil when the string is empty (convenience for coalescing).
    var nonEmpty: String? { isEmpty ? nil : self }
}

/// Менеджер хранения ключей
class KeychainStorage: ObservableObject {
    static let shared = KeychainStorage()

    @Published var keys: [ConnectionKey] = []
    @Published var selectedKeyId: String?

    private let keychain = KeychainHelper()
    private let keychainKey = "connection_keys_v1"
    private let defaults = UserDefaults.standard
    private let selectedKeyKey = "selected_connection_key_id"

    // True when the Keychain REFUSED access during loadKeys (e.g. after an
    // ad-hoc re-signed update changed the app's code identity). The store is
    // then "locked", NOT empty: the UI shows no keys, but saveKeys() must
    // refuse to write — a save from this state would delete/overwrite items
    // that still exist and silently empty the user's key list.
    private var storeAccessFailed = false

    init() {
        loadKeys()
    }

    /// Загрузить ключи из Keychain (с миграцией из старого blob-формата и UserDefaults)
    func loadKeys() {
        // A fresh load attempt re-evaluates store accessibility.
        storeAccessFailed = false
        // Migration: if old single-blob key exists, migrate to per-key format and remove it
        if let json = keychain.load(key: keychainKey),
           let data = json.data(using: .utf8),
           let decoded = try? JSONDecoder().decode([ConnectionKey].self, from: data) {
            keys = decoded
            keychain.delete(key: keychainKey)
            saveKeys()
        } else {
            // Load per-key format: ck_0, ck_1, ... until a slot is MISSING.
            // A slot that exists but fails to decode is skipped, not treated as
            // the end of the list — otherwise one corrupted entry would hide the
            // whole tail and the next saveKeys() would irrevocably delete it.
            // An ACCESS FAILURE (not "missing") marks the whole store as locked.
            var loaded: [ConnectionKey] = []
            var i = 0
            var reachedEnd = false
            while !reachedEnd {
                switch keychain.loadResult(key: "ck_\(i)") {
                case .found(let json):
                    if let data = json.data(using: .utf8),
                       let key = try? JSONDecoder().decode(ConnectionKey.self, from: data) {
                        loaded.append(key)
                    } else {
                        NSLog("AIVPN: skipping corrupted Keychain slot ck_%d", i)
                    }
                    i += 1
                case .missing:
                    reachedEnd = true
                case .failure(let status):
                    NSLog("AIVPN: Keychain denied access to slot ck_%d (OSStatus %d) — treating key store as locked, not empty", i, status)
                    storeAccessFailed = true
                    reachedEnd = true
                }
            }
            // Legacy migration: UserDefaults → per-key Keychain. Never migrate
            // over a locked store — "loaded is empty" is not evidence of an
            // empty store when reads were refused.
            if loaded.isEmpty, !storeAccessFailed,
               let data = defaults.data(forKey: "saved_connection_keys"),
               let decoded = try? JSONDecoder().decode([ConnectionKey].self, from: data) {
                loaded = decoded
                defaults.removeObject(forKey: "saved_connection_keys")
                keys = loaded
                saveKeys()
            } else {
                keys = loaded
            }
        }

        // selectedKeyId хранится в UserDefaults — это UI-состояние, не секрет
        selectedKeyId = defaults.string(forKey: selectedKeyKey)

        if selectedKeyId != nil && !keys.contains(where: { $0.id == selectedKeyId }) {
            selectedKeyId = nil
        }

        if selectedKeyId == nil && !keys.isEmpty {
            selectedKeyId = keys.first?.id
            defaults.set(selectedKeyId, forKey: selectedKeyKey)
        }
    }

    /// Сохранить ключи в Keychain (per-key format: ck_0, ck_1, ...)
    /// Each key is stored as a separate Keychain item so corruption of one entry
    /// does not affect the others. Entries beyond the current count are deleted.
    private func saveKeys() {
        // Never write from an empty-after-error state: if the Keychain refused
        // reads at load time the items are likely still there, and this write
        // path (delete+add per slot, then trailing-slot cleanup) would destroy
        // them. Losing one session's edits is recoverable; wiping the store on
        // every ad-hoc re-signed update is not.
        guard !storeAccessFailed else {
            NSLog("AIVPN: key store is locked (Keychain access error at load) — refusing to save")
            return
        }
        for (i, key) in keys.enumerated() {
            if let encoded = try? JSONEncoder().encode(key),
               let json = String(data: encoded, encoding: .utf8) {
                keychain.save(key: "ck_\(i)", value: json)
            }
        }
        // Remove any leftover entries beyond current count (handles deletions)
        var next = keys.count
        while keychain.load(key: "ck_\(next)") != nil {
            keychain.delete(key: "ck_\(next)")
            next += 1
        }
    }
    
    /// Добавить новый ключ
    func addKey(name: String, keyValue: String, mtlsCertPath: String? = nil,
                bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
                bootstrapTelegramChat: String? = nil,
                bootstrapGithub: String? = nil,
                serverSigningKey: String? = nil) -> ConnectionKey? {
        // Проверить дубликат по значению ключа
        if keys.contains(where: { $0.keyValue == ConnectionKey.normalizeKeyValue(keyValue) }) {
            return nil
        }

        let newKey = ConnectionKey(name: name, keyValue: keyValue, mtlsCertPath: mtlsCertPath,
                                    bootstrapCdnUrl: bootstrapCdnUrl, bootstrapTelegramToken: bootstrapTelegramToken,
                                    bootstrapTelegramChat: bootstrapTelegramChat,
                                    bootstrapGithub: bootstrapGithub,
                                    serverSigningKey: serverSigningKey)
        keys.append(newKey)
        saveKeys()
        
        // Если это первый ключ, выбрать его
        if keys.count == 1 {
            selectedKeyId = newKey.id
        }
        
        return newKey
    }
    
    /// Обновить имя ключа
    func updateKeyName(id: String, newName: String) {
        if let index = keys.firstIndex(where: { $0.id == id }) {
            keys[index].name = newName
            saveKeys()
        }
    }

    /// Обновить ключ полностью (имя + keyValue)
    func updateKey(id: String, name: String, keyValue: String, mtlsCertPath: String? = nil,
                   bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil,
                   bootstrapTelegramChat: String? = nil,
                   bootstrapGithub: String? = nil,
                   serverSigningKey: String? = nil) -> Bool {
        guard let index = keys.firstIndex(where: { $0.id == id }) else {
            return false
        }

        let normalizedKey = ConnectionKey.normalizeKeyValue(keyValue)

        if normalizedKey != keys[index].keyValue &&
           keys.contains(where: { $0.id != id && $0.keyValue == normalizedKey }) {
            return false
        }

        keys[index] = ConnectionKey(id: id, name: name, keyValue: keyValue, mtlsCertPath: mtlsCertPath,
                                     bootstrapCdnUrl: bootstrapCdnUrl, bootstrapTelegramToken: bootstrapTelegramToken,
                                     bootstrapTelegramChat: bootstrapTelegramChat,
                                     bootstrapGithub: bootstrapGithub,
                                     serverSigningKey: serverSigningKey)
        saveKeys()
        return true
    }
    
    /// Удалить ключ
    func deleteKey(id: String) {
        keys.removeAll { $0.id == id }
        saveKeys()
        
        // Если удалили выбранный, выбрать другой
        if selectedKeyId == id {
            selectedKeyId = keys.first?.id
            defaults.set(selectedKeyId, forKey: selectedKeyKey)
        }
    }

    /// Выбрать ключ
    func selectKey(id: String?) {
        selectedKeyId = id
        defaults.set(id, forKey: selectedKeyKey)
    }
    
    /// Получить выбранный ключ
    var selectedKey: ConnectionKey? {
        guard let id = selectedKeyId,
              let key = keys.first(where: { $0.id == id }) else {
            return nil
        }
        return key
    }
}
