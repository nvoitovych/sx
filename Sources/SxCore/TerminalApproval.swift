import Foundation

/// Approving waiting requests from a terminal with the macOS account password (`sx approve`),
/// for when the owner reaches this Mac only through a remote terminal and cannot touch Touch ID.
/// Everything here is pure policy; Sx.app does the checks against the real peer process.
public enum TerminalApproval {
    /// `--for` never grants longer than this, whatever the app's own "remember" setting says.
    public static let maxGrant: TimeInterval = 24 * 3600
    /// A request that timed out can still be approved for this long; its retry then passes once.
    public static let keepExpired: TimeInterval = 30 * 60
    /// How long that single retry has, after approval.
    public static let onceWindow: TimeInterval = 15 * 60

    /// Parses `8h`, `30m`, `1h30m`, `2d` is refused (over the cap). Nil on garbage, zero or > maxGrant.
    public static func duration(_ text: String) -> TimeInterval? {
        var total: TimeInterval = 0
        var number = ""
        var sawUnit = false
        for c in text.lowercased() {
            if c.isASCII, c.isNumber {
                number.append(c)
            } else if let unit = ["h": 3600.0, "m": 60.0, "d": 86400.0][String(c)], let n = Double(number) {
                total += n * unit
                number = ""
                sawUnit = true
            } else {
                return nil
            }
        }
        guard number.isEmpty, sawUnit, total >= 60, total <= maxGrant else { return nil }
        return total
    }

    /// Why the process asking to approve may not, or nil: it must have a controlling terminal and its
    /// stdin must be that terminal, so the password is typed there, never piped or passed in argv/env.
    /// Who started the process does not matter (an agent may run `sx pending` and even start
    /// `sx approve`); the gate is the password, which only the owner knows.
    public static func refusal(controllingTTY: String?, stdinPath: String?) -> String? {
        guard let tty = controllingTTY else { return noTerminal }
        guard let stdin = stdinPath, stdin == "/dev/" + tty else {
            return "stdin is not the terminal (\(stdinPath ?? "a pipe")): the password must be typed at the terminal, not piped"
        }
        return nil
    }

    public static let noTerminal = "no terminal: `sx approve` asks for the owner's password at a real terminal. Agent: give the command to the owner to run in a terminal they opened"
}

/// Persistent switch and password-attempt limiter. Lives in this Mac's keychain (not UserDefaults,
/// which any process of the user can rewrite).
public struct TerminalApprovalState: Codable, Equatable {
    public var enabled = false
    public var failures: [Date] = []
    /// Set when too many wrong passwords turned terminal approvals off; Touch ID turns them back on.
    public var disabledReason: String?

    public static let shortWindow: TimeInterval = 15 * 60
    public static let shortLimit = 5
    public static let longWindow: TimeInterval = 24 * 3600
    public static let longLimit = 10

    public init(enabled: Bool = false) { self.enabled = enabled }

    /// Why a password may not be tried now, or nil.
    public func refusal(now: Date = Date()) -> String? {
        guard enabled else {
            return disabledReason.map { "terminal approvals are off: \($0). Turn them on at the Mac: `sx approvals on` (Touch ID)" }
                ?? "terminal approvals are off. Turn them on once at the Mac: `sx approvals on` (Touch ID)"
        }
        let recent = failures.filter { now.timeIntervalSince($0) < Self.shortWindow }
        if recent.count >= Self.shortLimit, let oldest = recent.min() {
            let wait = Int((Self.shortWindow - now.timeIntervalSince(oldest)) / 60) + 1
            return "\(recent.count) wrong passwords in 15 min; try again in \(wait) min"
        }
        return nil
    }

    public func attemptsLeft(now: Date = Date()) -> Int {
        let recent = failures.filter { now.timeIntervalSince($0) < Self.shortWindow }.count
        let day = failures.filter { now.timeIntervalSince($0) < Self.longWindow }.count
        return max(0, min(Self.shortLimit - recent, Self.longLimit - day))
    }

    public mutating func recordFailure(now: Date = Date()) {
        failures = failures.filter { now.timeIntervalSince($0) < Self.longWindow } + [now]
        if failures.count >= Self.longLimit {
            enabled = false
            disabledReason = "\(failures.count) wrong passwords in 24 h"
            failures = []
        }
    }

    public mutating func recordSuccess() { failures = [] }

    public mutating func turnOn() {
        enabled = true
        failures = []
        disabledReason = nil
    }
}

/// Remembered approvals. A grant is keyed by the request class it covers; `uses == nil` lasts until
/// `until`, `uses == 1` lets exactly one matching request through (the retry of a timed-out request).
public struct GrantTable {
    public struct Grant: Equatable {
        public var key: String
        public var info: GrantInfo
        public var uses: Int?
    }

    public private(set) var grants: [String: Grant] = [:]

    public init() {}

    public static func shortID(_ key: String) -> String { String(key.prefix(8)) }

    public mutating func add(key: String, info: GrantInfo, uses: Int? = nil) {
        var info = info
        info.id = Self.shortID(key)
        info.usesLeft = uses
        grants[key] = Grant(key: key, info: info, uses: uses)
    }

    /// True when a grant covers `key`; a single-use grant is consumed.
    public mutating func take(_ key: String, now: Date = Date()) -> Bool {
        guard var g = grants[key] else { return false }
        guard g.info.until > now else {
            grants[key] = nil
            return false
        }
        if let uses = g.uses {
            if uses <= 1 { grants[key] = nil } else {
                g.uses = uses - 1
                g.info.usesLeft = uses - 1
                grants[key] = g
            }
        }
        return true
    }

    public func active(now: Date = Date()) -> [GrantInfo] {
        grants.values.map(\.info).filter { $0.until > now }.sorted { $0.until > $1.until }
    }

    /// Removes grants whose short id starts with `prefix` (at least 4 characters). Returns how many.
    public mutating func revoke(prefix: String) -> Int {
        guard prefix.count >= 4 else { return 0 }
        let hits = grants.keys.filter { $0.hasPrefix(prefix.lowercased()) }
        for k in hits { grants[k] = nil }
        return hits.count
    }

    public mutating func revoke(key: String) { grants[key] = nil }

    public mutating func removeAll() { grants.removeAll() }
}

/// Requests waiting for a human, numbered so they are easy to type on a phone.
public struct PendingTable {
    public struct Entry {
        public var info: PendingInfo
        /// What a single approval, or `--for`, covers.
        public var classKey: String
        /// What `--for … --any-host` covers (SSH: this key for any server). Nil when not offered.
        public var wideKey: String?
        public var approvedInTerminal = false
    }

    public enum Pick: Equatable {
        case waiting
        case expired
    }

    public private(set) var entries: [Int: Entry] = [:]
    private var nextID = 1

    public init() {}

    public mutating func add(_ info: PendingInfo, classKey: String, wideKey: String?, now: Date = Date()) -> Int {
        prune(now: now)
        var info = info
        info.id = nextID
        info.created = now
        info.state = PendingInfo.State.waiting
        entries[nextID] = Entry(info: info, classKey: classKey, wideKey: wideKey)
        nextID += 1
        return info.id
    }

    public func entry(_ id: Int) -> Entry? { entries[id] }

    /// The waiting request finished (answered on the card, timed out, its program exited…).
    public mutating func end(_ id: Int, state: String, now: Date = Date()) {
        guard var e = entries[id], e.info.state == PendingInfo.State.waiting else { return }
        e.info.state = state
        e.info.ended = now
        entries[id] = e
    }

    public mutating func setDeadline(_ id: Int, _ deadline: Date) {
        entries[id]?.info.deadline = deadline
    }

    /// Marks a waiting request approved from the terminal; the waiting broker thread picks it up.
    public mutating func approveLive(_ id: Int) {
        entries[id]?.approvedInTerminal = true
    }

    public mutating func prune(now: Date = Date()) {
        entries = entries.filter { _, e in
            guard let ended = e.info.ended else { return true }
            return now.timeIntervalSince(ended) < TerminalApproval.keepExpired
        }
    }

    public func list(now: Date = Date()) -> [PendingInfo] {
        entries.values.filter { e in
            guard let ended = e.info.ended else { return true }
            return now.timeIntervalSince(ended) < TerminalApproval.keepExpired
        }.map(\.info).sorted { $0.id < $1.id }
    }

    /// Checks that `id` can be approved from a terminal now, and whether it is still waiting.
    public func pick(_ id: Int, now: Date = Date()) -> Result<Pick, PickError> {
        guard let e = entries[id] else { return .failure(.init("#\(id): no such request (see `sx pending`)")) }
        guard e.info.terminal else { return .failure(.init("#\(id): \(e.info.what) needs Touch ID at the Mac")) }
        switch e.info.state {
        case PendingInfo.State.waiting:
            return e.approvedInTerminal ? .failure(.init("#\(id): already approved")) : .success(.waiting)
        case PendingInfo.State.expired:
            guard let ended = e.info.ended, now.timeIntervalSince(ended) < TerminalApproval.keepExpired else {
                return .failure(.init("#\(id): too old; let the program ask again"))
            }
            return .success(.expired)
        default:
            return .failure(.init("#\(id): already \(e.info.state)"))
        }
    }

    public mutating func markApprovedAfterExpiry(_ id: Int) {
        entries[id]?.info.state = PendingInfo.State.approved
    }

    public struct PickError: Error, Equatable, CustomStringConvertible {
        public let description: String
        public init(_ d: String) { description = d }
    }
}
