import Foundation
import Security

struct ConnectionKey: Identifiable, Codable, Equatable {
    let id: String
    var name: String
    let keyValue: String
    let serverAddress: String?
    let vpnIP: String?
    let canRecord: Bool?
    var mtlsCert: String?
    /// Operator's ed25519 signing public key (base64, 32 bytes) used to verify
    /// ServerHello/MaskUpdate signatures. Sourced from the aivpn:// connection
    /// key's `sk` field (embedded by the server), falling back to an explicit
    /// value passed to the initializer.
    var serverSigningKey: String?
    /// R2 Phase B: operator's ed25519 mask-verifying public key (base64, 32
    /// bytes) used to check the embedded operator signature on mask artifacts
    /// pushed via MaskUpdate. Sourced purely from the aivpn:// connection
    /// key's `mop` field — like `vpnIP`/`canRecord` below, it is re-derived
    /// from `keyValue` on every init rather than persisted separately, since
    /// it always stays in sync with the key it came from (mirrors desktop
    /// main.rs's `mop` connection-key field / `--mask-operator-pubkey`).
    let maskOperatorPubkey: String?

    init(id: String = UUID().uuidString, name: String, keyValue: String, mtlsCert: String? = nil,
         serverSigningKey: String? = nil) {
        self.id = id
        self.name = name
        self.keyValue = keyValue.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")
        self.mtlsCert = mtlsCert
        self.serverSigningKey = serverSigningKey

        var server: String? = nil
        var ip: String? = nil
        var record: Bool? = nil
        var mop: String? = nil

        // Metadata extraction is deliberately NOT gated on the `k` format check:
        // even if `k` is malformed, the server address / VPN IP / can_record /
        // embedded `sk` signing key must still be adopted so that (a) the UI can
        // display something useful and (b) signature verification is never
        // silently disabled by an unrelated validation detail. Strict format
        // enforcement happens in isValidKeyString() at add/edit time.
        if let json = Self.decodePayload(self.keyValue) {
            if let s = json["s"] as? String, !s.isEmpty { server = s }
            ip = json["i"] as? String
            record = json["can_record"] as? Bool
            // Adopt the embedded signing key ("sk") unless one was passed explicitly.
            if self.serverSigningKey == nil,
               let sk = json["sk"] as? String, !sk.isEmpty {
                self.serverSigningKey = sk
            }
            // R2 Phase B: operator mask-verifying pubkey ("mop"), same shape/
            // precedent as "sk" above (embedded, public, non-secret).
            if let m = json["mop"] as? String, !m.isEmpty {
                mop = m
            }
        }

        self.serverAddress = server
        self.vpnIP = ip
        self.maskOperatorPubkey = mop
        self.canRecord = record
    }

    // MARK: - Strict validation (mirrors Tunnel/PacketTunnelProvider.swift TunnelConnectionKey)

    /// Decodes the base64url JSON payload of a normalized key value (no "aivpn://" prefix).
    private static func decodePayload(_ keyValue: String) -> [String: Any]? {
        var b64 = keyValue
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }
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

    /// Strict add/edit validation, mirroring the tunnel's own parser
    /// (TunnelConnectionKey.init in PacketTunnelProvider.swift): the key must be
    /// base64(JSON) containing a non-empty server address `s` and a server public
    /// key `k` decoding to exactly 32 bytes (standard base64 — the server's real
    /// format — or 64-char hex). Rejecting bad keys here surfaces a clear error
    /// at add time instead of an opaque connect failure.
    static func isValidKeyString(_ raw: String) -> Bool {
        let norm = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")
        guard let json = decodePayload(norm),
              let s = json["s"] as? String, !s.isEmpty,
              let k = json["k"] as? String, isValid32ByteKey(k) else { return false }
        return true
    }

    var fullKey: String { "aivpn://\(keyValue)" }

    var displayName: String {
        if let s = serverAddress { return "\(name) (\(s))" }
        return name
    }

    var isRecordingAdminKey: Bool { canRecord ?? false }
}

// MARK: - Storage (Keychain — shared with tunnel extension via kSecAttrAccessGroup)
//
// Each ConnectionKey is stored as a single Keychain item using kSecClassGenericPassword.
// The account attribute is the key's UUID; the service attribute is a fixed constant.
// The keyValue and mtlsCert are encoded together as JSON in the secret data field so
// that both sensitive values are protected by the Secure Enclave-backed Keychain.
// The non-secret metadata (name, serverAddress, vpnIP, canRecord) is stored in the
// kSecAttrLabel and kSecAttrGeneric attributes to allow listing without decrypting.
//
// Access: kSecAttrAccessibleWhenUnlockedThisDeviceOnly — data is accessible only when
// the device is unlocked and cannot be transferred to another device via backup.
//
// The selected key ID is stored in a separate Keychain item with account = "selected_id"
// to avoid falling back to UserDefaults for any sensitive selection state.

private struct KeychainPayload: Codable {
    let id: String
    let name: String
    let keyValue: String
    let mtlsCert: String?
    // Optional — absent in payloads written by older app versions, which
    // JSONDecoder decodes as nil (backward compatible).
    let serverSigningKey: String?
}

class KeychainStorage: ObservableObject {
    static let shared = KeychainStorage()

    @Published var keys: [ConnectionKey] = []
    @Published var selectedKeyId: String?

    private let service = "com.aivpn.client"
    private let selectedAccount = "__selected_id__"

    init() { loadKeys() }

    // MARK: - Load

    func loadKeys() {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecMatchLimit:       kSecMatchLimitAll,
            kSecReturnAttributes: true,
            kSecReturnData:       true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let items = result as? [[CFString: Any]] else {
            keys = []
            selectedKeyId = nil
            return
        }

        var loaded: [ConnectionKey] = []
        var rawSelectedId: String?

        for item in items {
            guard let account = item[kSecAttrAccount] as? String,
                  let data    = item[kSecValueData]   as? Data else { continue }

            // The selected-ID item is stored alongside the key items in the same service.
            if account == selectedAccount {
                rawSelectedId = String(data: data, encoding: .utf8)
                continue
            }

            guard let payload = try? JSONDecoder().decode(KeychainPayload.self, from: data) else { continue }
            let ck = ConnectionKey(id: payload.id, name: payload.name,
                                   keyValue: payload.keyValue, mtlsCert: payload.mtlsCert,
                                   serverSigningKey: payload.serverSigningKey)
            loaded.append(ck)
        }

        keys = loaded.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        selectedKeyId = rawSelectedId

        if let sid = selectedKeyId, !keys.contains(where: { $0.id == sid }) {
            selectedKeyId = nil
        }
        if selectedKeyId == nil, let first = keys.first {
            selectedKeyId = first.id
            persistSelectedId(first.id)
        }
    }

    // MARK: - Add

    @discardableResult
    func addKey(name: String, keyValue: String, mtlsCert: String? = nil,
                serverSigningKey: String? = nil) -> ConnectionKey? {
        let norm = keyValue.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")
        if keys.contains(where: { $0.keyValue == norm }) { return nil }
        let k = ConnectionKey(name: name, keyValue: keyValue, mtlsCert: mtlsCert,
                              serverSigningKey: serverSigningKey)
        guard keychainAdd(k) else { return nil }
        keys.append(k)
        if keys.count == 1 { selectKey(id: k.id) }
        return k
    }

    // MARK: - Update

    @discardableResult
    func updateKey(id: String, name: String, keyValue: String, mtlsCert: String? = nil,
                   serverSigningKey: String? = nil) -> Bool {
        guard let idx = keys.firstIndex(where: { $0.id == id }) else { return false }
        let norm = keyValue.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")
        if norm != keys[idx].keyValue,
           keys.contains(where: { $0.id != id && $0.keyValue == norm }) { return false }
        let updated = ConnectionKey(id: id, name: name, keyValue: keyValue, mtlsCert: mtlsCert,
                                    serverSigningKey: serverSigningKey)
        guard keychainUpdate(updated) else { return false }
        keys[idx] = updated
        return true
    }

    // MARK: - Delete

    func deleteKey(id: String) {
        keychainDelete(account: id)
        keys.removeAll { $0.id == id }
        if selectedKeyId == id {
            selectedKeyId = keys.first?.id
            persistSelectedId(selectedKeyId)
        }
    }

    // MARK: - Select

    func selectKey(id: String?) {
        selectedKeyId = id
        persistSelectedId(id)
    }

    var activeKey: ConnectionKey? {
        guard let id = selectedKeyId else { return nil }
        return keys.first(where: { $0.id == id })
    }

    // MARK: - Keychain primitives

    private func payloadData(_ key: ConnectionKey) -> Data? {
        let payload = KeychainPayload(id: key.id, name: key.name,
                                     keyValue: key.keyValue, mtlsCert: key.mtlsCert,
                                     serverSigningKey: key.serverSigningKey)
        return try? JSONEncoder().encode(payload)
    }

    private func keychainAdd(_ key: ConnectionKey) -> Bool {
        guard let data = payloadData(key) else { return false }
        let attrs: [CFString: Any] = [
            kSecClass:                   kSecClassGenericPassword,
            kSecAttrService:             service,
            kSecAttrAccount:             key.id,
            kSecAttrAccessible:          kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData:               data,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Break mutual recursion: call SecItemUpdate directly instead of keychainUpdate.
            let q: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: key.id,
            ]
            let upd: [CFString: Any] = [kSecValueData: data]
            return SecItemUpdate(q as CFDictionary, upd as CFDictionary) == errSecSuccess
        }
        return status == errSecSuccess
    }

    private func keychainUpdate(_ key: ConnectionKey) -> Bool {
        guard let data = payloadData(key) else { return false }
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key.id,
        ]
        let update: [CFString: Any] = [
            kSecValueData: data,
        ]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            // Break mutual recursion: call SecItemAdd directly instead of keychainAdd.
            let attrs: [CFString: Any] = [
                kSecClass:          kSecClassGenericPassword,
                kSecAttrService:    service,
                kSecAttrAccount:    key.id,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData:      data,
            ]
            return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }

    private func keychainDelete(account: String) {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Tunnel key handoff

    private let tunnelHandoffService = "com.aivpn.client.tunnel-handoff"
    private let accessGroup = "group.com.aivpn.client"

    func storeForTunnel(secret: String) -> String? {
        guard let data = secret.data(using: .utf8) else { return nil }
        let token = UUID().uuidString
        let attrs: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     tunnelHandoffService,
            kSecAttrAccount:     token,
            kSecAttrAccessGroup: accessGroup,
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData:       data,
        ]
        var status = SecItemAdd(attrs as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let del: [CFString: Any] = [
                kSecClass:           kSecClassGenericPassword,
                kSecAttrService:     tunnelHandoffService,
                kSecAttrAccount:     token,
                kSecAttrAccessGroup: accessGroup,
            ]
            SecItemDelete(del as CFDictionary)
            status = SecItemAdd(attrs as CFDictionary, nil)
        }
        guard status == errSecSuccess else { return nil }
        return token
    }

    func retrieveForTunnel(token: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      tunnelHandoffService,
            kSecAttrAccount:      token,
            kSecAttrAccessGroup:  accessGroup,
            kSecMatchLimit:       kSecMatchLimitOne,
            kSecReturnData:       true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let secret = String(data: data, encoding: .utf8) else { return nil }
        let del: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     tunnelHandoffService,
            kSecAttrAccount:     token,
            kSecAttrAccessGroup: accessGroup,
        ]
        SecItemDelete(del as CFDictionary)
        return secret
    }

    /// Deletes a handoff token that was stored by storeForTunnel but never consumed
    /// (e.g. because saveToPreferences failed before the tunnel could start).
    func deleteHandoffToken(_ token: String) {
        let del: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     tunnelHandoffService,
            kSecAttrAccount:     token,
            kSecAttrAccessGroup: accessGroup,
        ]
        SecItemDelete(del as CFDictionary)
    }

    private func persistSelectedId(_ id: String?) {
        // Store the selected key ID as a Keychain item alongside the key items.
        keychainDelete(account: selectedAccount)
        guard let id = id, let data = id.data(using: .utf8) else { return }
        let attrs: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    service,
            kSecAttrAccount:    selectedAccount,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData:      data,
        ]
        SecItemAdd(attrs as CFDictionary, nil)
    }
}
