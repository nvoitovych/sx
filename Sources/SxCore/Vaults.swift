import Foundation

/// A named secret store. Several can be active at once; each project path routes to one.
public struct VaultConfig: Equatable {
    public enum Backend: Equatable {
        case keychain
        case bitwarden(server: String?)
        case onePassword(account: String?)
        /// External executable speaking the sx backend protocol (JSON over stdin/stdout).
        case plugin(command: String)
    }

    public var name: String
    public var backend: Backend
    public var settings: [String: String]

    public init(name: String, backend: Backend, settings: [String: String] = [:]) {
        self.name = name
        self.backend = backend
        self.settings = settings
    }

    public var kind: String {
        switch backend {
        case .keychain: return "keychain"
        case .bitwarden: return "bitwarden"
        case .onePassword: return "1password"
        case let .plugin(command): return "plugin (\(command))"
        }
    }
}

public struct SxConfig: Equatable {
    public static let personal = VaultConfig(name: "personal", backend: .keychain)

    public var vaults: [String: VaultConfig]
    public var defaultVault: String
    /// Path glob → vault name. `**` at the end matches any subpath.
    public var routes: [(pattern: String, vault: String)]

    public static func == (a: SxConfig, b: SxConfig) -> Bool {
        a.vaults == b.vaults && a.defaultVault == b.defaultVault
            && a.routes.map { "\($0.pattern)=\($0.vault)" } == b.routes.map { "\($0.pattern)=\($0.vault)" }
    }

    /// `SX_CONFIG` overrides the location (tests, alternate setups).
    public static var path: String {
        ProcessInfo.processInfo.environment["SX_CONFIG"] ?? "\(SX.realHome)/.config/sx/config.toml"
    }

    public static func load(path: String = SxConfig.path) throws -> SxConfig {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return SxConfig(vaults: ["personal": personal], defaultVault: "personal", routes: [])
        }
        return try parse(text)
    }

    public static func parse(_ text: String) throws -> SxConfig {
        var vaults: [String: VaultConfig] = ["personal": personal]
        var defaultVault = "personal"
        var routes: [(String, String)] = []
        for (section, values) in try MiniTOML.parse(text) {
            if section.isEmpty {
                if let d = values["default"]?.string { defaultVault = d }
            } else if section == "route" {
                for (pattern, v) in values {
                    guard let vault = v.string else { throw ConfigError("route \(pattern) must name a vault") }
                    routes.append((pattern, vault))
                }
            } else if section.hasPrefix("vault.") {
                let name = String(section.dropFirst("vault.".count))
                let s = values.compactMapValues(\.string)
                let backend: VaultConfig.Backend
                switch s["backend"] ?? "keychain" {
                case "keychain": backend = .keychain
                case "bitwarden": backend = .bitwarden(server: s["server"])
                case "1password", "onepassword": backend = .onePassword(account: s["account"])
                case "plugin":
                    guard let cmd = s["command"] ?? s["type"].map({ "sx-backend-\($0)" }) else {
                        throw ConfigError("vault \(name): plugin needs `command` or `type`")
                    }
                    backend = .plugin(command: cmd)
                case let other:
                    backend = .plugin(command: "sx-backend-\(other)")
                }
                vaults[name] = VaultConfig(name: name, backend: backend, settings: s)
            }
        }
        guard vaults[defaultVault] != nil else { throw ConfigError("default vault \(defaultVault) is not defined") }
        for (p, v) in routes where vaults[v] == nil { throw ConfigError("route \(p) → unknown vault \(v)") }
        // Longest pattern first, so the most specific route wins.
        routes.sort { $0.0.count > $1.0.count }
        return SxConfig(vaults: vaults, defaultVault: defaultVault, routes: routes)
    }

    public func vault(forPath path: String) -> VaultConfig {
        for (pattern, name) in routes where Self.matches(pattern: pattern, path: path) {
            if let v = vaults[name] { return v }
        }
        return vaults[defaultVault] ?? Self.personal
    }

    static func matches(pattern: String, path: String) -> Bool {
        var p = (pattern as NSString).expandingTildeInPath
        if p.hasPrefix("~") { p = SX.realHome + p.dropFirst() }
        if p.hasSuffix("/**") {
            let base = String(p.dropLast(3))
            return path == base || path.hasPrefix(base + "/")
        }
        if p.hasSuffix("**") { return path.hasPrefix(String(p.dropLast(2))) }
        return fnmatch(p, path, 0) == 0
    }
}

public struct ConfigError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// `sx://name` (vault chosen by route) or `sx://@vault/name` (explicit vault).
public struct SecretRef: Equatable, Hashable {
    public var vault: String?
    public var name: String

    public init(vault: String?, name: String) {
        self.vault = vault
        self.name = name
    }

    public init?(reference: String) {
        guard !reference.isEmpty else { return nil }
        if reference.hasPrefix("@") {
            guard let slash = reference.firstIndex(of: "/") else { return nil }
            let v = String(reference[reference.index(after: reference.startIndex)..<slash])
            let n = String(reference[reference.index(after: slash)...])
            guard !v.isEmpty, !n.isEmpty else { return nil }
            vault = v
            name = n
        } else {
            vault = nil
            name = reference
        }
    }

    public var display: String { vault.map { "@\($0)/\(name)" } ?? name }
}
