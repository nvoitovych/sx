import Foundation

/// One request per connection, newline-terminated JSON. Secret values travel base64-encoded.
public struct BrokerRequest: Codable, Equatable {
    public enum Op: String, Codable {
        case ping, list, put, resolve, hash, remove
        /// Human approves a project's `.sx.toml` (Touch ID); stores its digest.
        case trust
    }

    public var op: Op
    public var name: String?
    public var names: [String]?
    public var value: String?
    public var tags: [String]?
    public var argv: [String]?
    public var cwd: String?
    /// Name of the AI agent detected in the caller's process ancestry, if any.
    public var agent: String?
    /// Secrets from other vaults (Bitwarden, 1Password, plugins) included in the approval card.
    /// The CLI fetches those itself after the broker approves.
    public var external: [String]?
    /// Absolute path of the project's `.sx.toml`, if any. The broker reads and verifies it itself.
    public var projectFile: String?

    public init(op: Op, name: String? = nil, names: [String]? = nil, value: String? = nil,
                tags: [String]? = nil, argv: [String]? = nil, cwd: String? = nil, agent: String? = nil,
                external: [String]? = nil, projectFile: String? = nil) {
        self.external = external
        self.projectFile = projectFile
        self.op = op
        self.name = name
        self.names = names
        self.value = value
        self.tags = tags
        self.argv = argv
        self.cwd = cwd
        self.agent = agent
    }
}

public struct SecretInfo: Codable, Equatable {
    public var name: String
    public var tags: [String]
    public var modified: Date?

    public init(name: String, tags: [String], modified: Date?) {
        self.name = name
        self.tags = tags
        self.modified = modified
    }
}

public struct BrokerResponse: Codable, Equatable {
    public var ok: Bool
    public var error: String?
    public var values: [String: String]?
    public var secrets: [SecretInfo]?
    public var hash: String?
    public var version: String?

    public init(ok: Bool, error: String? = nil, values: [String: String]? = nil,
                secrets: [SecretInfo]? = nil, hash: String? = nil, version: String? = nil) {
        self.ok = ok
        self.error = error
        self.values = values
        self.secrets = secrets
        self.hash = hash
        self.version = version
    }

    public static func fail(_ message: String) -> BrokerResponse {
        BrokerResponse(ok: false, error: message)
    }
}

public enum Wire {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        var data = try enc.encode(value)
        data.append(0x0A)
        return data
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let trimmed = data.last == 0x0A ? data.dropLast() : data[...]
        return try dec.decode(type, from: Data(trimmed))
    }
}
