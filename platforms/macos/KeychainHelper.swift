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

    /// Writes (delete + add) one Keychain item. Returns false when the item
    /// was NOT written — encoding failed, or SecItemAdd was refused (e.g.
    /// errSecAuthFailed / errSecInteractionNotAllowed while the machine is
    /// locked or after an ad-hoc re-sign changed our code identity).
    ///
    /// The result MUST NOT be ignored by slot-indexed callers (`ck_0`,
    /// `ck_1`, …): the delete above has already happened by then, so a
    /// discarded failure leaves a HOLE in the slot sequence, and
    /// `loadKeys()` treats the first missing slot as end-of-list — every
    /// key after it disappears from the app for good. See
    /// `KeychainStorage.saveKeys()`, which aborts the whole sequence on a
    /// false return instead of writing past the hole.
    @discardableResult
    func save(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }

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
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            NSLog("AIVPN: Keychain refused to write item (OSStatus %d)", status)
            return false
        }
        return true
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
