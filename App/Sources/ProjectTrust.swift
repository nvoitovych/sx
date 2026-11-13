import Foundation
import Security
import SxCore

/// Digests of `.sx.toml` files a human approved. Stored in the keychain (this Mac only, not synced),
/// where neither agents nor other apps can write — unlike files or UserDefaults.
enum ProjectTrust {
    enum Result {
        case trusted(ProjectPolicy)
        case untrusted(String)
    }

    private static let service = "dev.nvlab.sx.trust"

    private static func query(_ path: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: path,
            kSecAttrAccessGroup as String: SX.keychainAccessGroup,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func trust(_ path: String, data: Data) throws {
        let digest = Data(ProjectPolicy.digest(data).utf8)
        SecItemDelete(query(path) as CFDictionary)
        var add = query(path)
        add[kSecValueData as String] = digest
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainStore.Failure("trust \(path)", status) }
    }

    static func check(_ path: String) -> Result {
        guard let data = FileManager.default.contents(atPath: path) else { return .untrusted("cannot read \(path)") }
        var q = query(path)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let stored = out as? Data else {
            return .untrusted("\(path) is not trusted yet")
        }
        guard String(decoding: stored, as: UTF8.self) == ProjectPolicy.digest(data) else {
            return .untrusted("\(path) changed since it was trusted")
        }
        guard let policy = try? ProjectPolicy.parse(String(decoding: data, as: UTF8.self)) else {
            return .untrusted("\(path) does not parse")
        }
        return .trusted(policy)
    }
}
