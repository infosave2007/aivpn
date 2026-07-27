import Foundation
import Security

class KeychainHelper {
    /// Distinguishes "the item is genuinely absent" from "the Keychain refused
    /// to hand it over". With ad-hoc signing every rebuild gets a new code
    /// identity, and the Keychain can then deny access to items the previous
    /// build created (errSecAuthFailed / interaction-required) — which must
    /// NOT be treated the same as an empty slot, or the caller will conclude
    /// the store is empty and overwrite it.
    enum LoadResult {
        case found(String)
        case missing            // errSecItemNotFound — the slot is truly empty
        case failure(OSStatus)  // access denied etc. — the item may still exist
    }

    func loadResult(key: String) -> LoadResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aivpn.client",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess {
            if let data = result as? Data, let value = String(data: data, encoding: .utf8) {
                return .found(value)
            }
            // Present but undecodable — surface as a corrupted (skippable)
            // slot, not as end-of-list and not as an access failure.
            return .found("")
        }
        if status == errSecItemNotFound {
            return .missing
        }
        return .failure(status)
    }

    func save(key: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }

        // Delete existing
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aivpn.client"
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add new
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aivpn.client",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        _ = SecItemAdd(addQuery as CFDictionary, nil)
    }

    func load(key: String) -> String? {
        if case .found(let value) = loadResult(key: key), !value.isEmpty {
            return value
        }
        return nil
    }

    func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aivpn.client"
        ]
        SecItemDelete(query as CFDictionary)
    }
}
