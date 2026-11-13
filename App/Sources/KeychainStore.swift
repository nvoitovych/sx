import Foundation
import Security
import SxCore

/// Secrets live in the data-protection keychain, synchronized through iCloud Keychain,
/// in the team access group so only Sx.app (this team, this group) can read them.
enum KeychainStore {
    struct Failure: Error, CustomStringConvertible {
        let description: String

        init(_ op: String, _ status: OSStatus) {
            let msg = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
            description = "\(op): \(msg)"
        }
    }

    private static func base() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SX.keychainService,
            kSecAttrAccessGroup as String: SX.keychainAccessGroup,
            kSecAttrSynchronizable as String: kCFBooleanTrue!,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static func query(_ name: String) -> [String: Any] {
        var q = base()
        q[kSecAttrAccount as String] = name
        return q
    }

    static func exists(_ name: String) -> Bool {
        var q = query(name)
        q[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }

    static func put(_ name: String, value: Data, tags: [String]) throws {
        let meta = try JSONEncoder().encode(tags)
        let attrs: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrGeneric as String: meta,
            kSecAttrLabel as String: "sx: \(name)",
        ]
        var status = SecItemUpdate(query(name) as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = query(name).merging(attrs) { _, b in b }
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure("save \(name)", status) }
    }

    /// Changes only the tags; the value is untouched.
    static func setTags(_ name: String, _ tags: [String]) throws {
        let attrs: [String: Any] = [kSecAttrGeneric as String: try JSONEncoder().encode(tags)]
        let status = SecItemUpdate(query(name) as CFDictionary, attrs as CFDictionary)
        guard status == errSecSuccess else { throw Failure("tag \(name)", status) }
    }

    static func get(_ name: String) throws -> Data {
        var q = query(name)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else { throw Failure("read \(name)", status) }
        return data
    }

    static func tags(_ name: String) -> [String] {
        var q = query(name)
        q[kSecReturnAttributes as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let dict = out as? [String: Any] else { return [] }
        return decodeTags(dict[kSecAttrGeneric as String])
    }

    static func list() throws -> [SecretInfo] {
        var q = base()
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else { throw Failure("list", status) }
        return items.compactMap { item in
            guard let name = item[kSecAttrAccount as String] as? String else { return nil }
            return SecretInfo(name: name, tags: decodeTags(item[kSecAttrGeneric as String]),
                              modified: item[kSecAttrModificationDate as String] as? Date)
        }.sorted { $0.name < $1.name }
    }

    static func remove(_ name: String) throws {
        let status = SecItemDelete(query(name) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure("delete \(name)", status) }
    }

    private static func decodeTags(_ raw: Any?) -> [String] {
        guard let data = raw as? Data else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }
}

extension SecretInfo: Identifiable {
    public var id: String { name }
}
