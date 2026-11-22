import Foundation

/// One request per connection, newline-terminated JSON. Secret values travel base64-encoded.
public struct BrokerRequest: Codable, Equatable {
    public enum Op: String, Codable {
        case ping, list, put, resolve, hash, remove
        /// Human approves a project's `.sx.toml` (Touch ID); stores its digest.
        case trust
        /// Human-only: return one value so the CLI can write it to a file (restoring key files on a new Mac).
        case reveal
        /// Requests waiting for a human (`sx pending`). Names and context only, never values.
        case pending
        /// Approve waiting requests by id with the account password typed in a terminal (`sx approve`).
        case approve
        /// Remembered approvals (`sx grants`) and their removal (`sx revoke`).
        case grants, revoke
        /// Terminal approvals switch: `name` = "on" (Touch ID), "off", or nil for status.
        case approvals
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
    /// `approve`: pending request ids exactly as shown to the human.
    public var ids: [Int]?
    /// `approve`: the token of each id, as listed. An entry with the same number but another token
    /// (Sx.app restarted, numbers reused) is refused.
    public var tokens: [String]?
    /// `approve`: the account password, typed at a terminal. Never logged or stored.
    public var password: String?
    /// `approve`: remember for this many seconds (capped at 24 h) instead of approving once.
    public var seconds: Int?
    /// `approve --for`: for SSH, cover the key for any server rather than this server only.
    public var anyHost: Bool?
    /// `revoke`: grant ids (or prefixes); empty with `name == "all"` revokes everything.
    public var grantIDs: [String]?

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
    public var pending: [PendingInfo]?
    public var grants: [GrantInfo]?
    /// Human-readable lines (results of `approve`, `revoke`, `approvals`).
    public var lines: [String]?

    public init(ok: Bool, error: String? = nil, values: [String: String]? = nil,
                secrets: [SecretInfo]? = nil, hash: String? = nil, version: String? = nil,
                pending: [PendingInfo]? = nil, grants: [GrantInfo]? = nil, lines: [String]? = nil) {
        self.pending = pending
        self.grants = grants
        self.lines = lines
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

/// A request waiting for (or recently missed by) a human. Shown by `sx pending`.
public struct PendingInfo: Codable, Equatable {
    public enum State {
        public static let waiting = "waiting"
        /// Nobody answered in time, or the program gave up; still approvable for a while.
        public static let expired = "expired"
        public static let approved = "approved"
        public static let denied = "denied"
    }

    public var id: Int
    /// Unguessable, per request: `sx approve` sends it back so the approval applies to this request only.
    public var token: String
    /// "ssh-sign", "secrets", or "other" (deletes, exports, trust…: Touch ID only).
    public var kind: String
    /// One line: what would happen, e.g. "sign in with ssh/id_ed25519 to batman".
    public var what: String
    public var who: String
    public var agent: String?
    /// Caller's process chain, nearest first (e.g. ssh ← git ← zsh ← claude).
    public var chain: [String]
    public var command: String?
    /// The command as separate arguments (`sx run`), shown shell-quoted.
    public var argv: [String]?
    public var cwd: String?
    public var names: [String]
    /// SSH: the destination as the caller typed it (an alias anyone can repoint: display only) and the
    /// fingerprint of the host key the server proved (session-bind), which is what a grant is tied to.
    public var host: String?
    public var hostKey: String?
    public var prod: Bool
    /// Can be approved with `sx approve` (otherwise Touch ID at the Mac only).
    public var terminal: Bool
    /// `--for` is possible (not prod, not Touch-ID-only). For SSH without a verified host also `--any-host`.
    public var canGrant: Bool
    /// After it timed out it can still be approved for its retry (false when its class is unique to it:
    /// an SSH login whose server is not verified, or unknown data).
    public var retryable: Bool
    public var created: Date
    /// When the live request gives up (waiting only).
    public var deadline: Date?
    public var ended: Date?
    public var state: String

    public init(id: Int = 0, token: String = "", kind: String, what: String, who: String, agent: String?, chain: [String],
                command: String?, argv: [String]? = nil, cwd: String?, names: [String], host: String? = nil, hostKey: String? = nil,
                prod: Bool, terminal: Bool, canGrant: Bool, retryable: Bool = true, created: Date = Date(), deadline: Date? = nil,
                ended: Date? = nil, state: String = State.waiting) {
        self.id = id
        self.token = token
        self.kind = kind
        self.what = what
        self.who = who
        self.agent = agent
        self.chain = chain
        self.command = command
        self.argv = argv
        self.cwd = cwd
        self.names = names
        self.host = host
        self.hostKey = hostKey
        self.prod = prod
        self.terminal = terminal
        self.canGrant = canGrant
        self.retryable = retryable
        self.created = created
        self.deadline = deadline
        self.ended = ended
        self.state = state
    }
}

/// A remembered approval (`sx grants`).
public struct GrantInfo: Codable, Equatable {
    public var id: String
    public var who: String
    /// What it covers, e.g. "ssh/id_ed25519 → batman (SHA256:…)" or "`npm test` in ~/app".
    public var scope: String
    public var names: [String]
    public var until: Date
    public var usesLeft: Int?
    /// "card" (Touch ID on the Mac) or "terminal" (`sx approve --for`).
    public var via: String

    public init(id: String = "", who: String, scope: String, names: [String], until: Date, usesLeft: Int? = nil, via: String) {
        self.id = id
        self.who = who
        self.scope = scope
        self.names = names
        self.until = until
        self.usesLeft = usesLeft
        self.via = via
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
