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
    /// Wrong passwords in the last 24 h. A correct password does not clear them: guesses spread
    /// between the owner's own approvals still add up (and are reported to the owner).
    public var failures: [Date] = []
    /// Set when too many wrong passwords turned terminal approvals off; Touch ID turns them back on.
    public var disabledReason: String?
    public var lastSuccess: Date?
    /// An attempt in progress counts as failed until it succeeds, so a crash mid-check still counts.
    public var attemptStarted: Date?

    public static let shortWindow: TimeInterval = 15 * 60
    public static let shortLimit = 5
    public static let longWindow: TimeInterval = 24 * 3600
    public static let longLimit = 10

    public init(enabled: Bool = false) { self.enabled = enabled }

    private func counted(now: Date) -> [Date] {
        (failures + (attemptStarted.map { [$0] } ?? [])).filter { now.timeIntervalSince($0) < Self.longWindow }
    }

    /// Why a password may not be tried now, or nil.
    public func refusal(now: Date = Date()) -> String? {
        guard enabled else {
            return disabledReason.map { "terminal approvals are off: \($0). Turn them on at the Mac: `sx approvals on` (Touch ID)" }
                ?? "terminal approvals are off. Turn them on once at the Mac: `sx approvals on` (Touch ID)"
        }
        let day = counted(now: now)
        if day.count >= Self.longLimit {
            return "\(day.count) wrong passwords in 24 h: terminal approvals are blocked. Turn them on again at the Mac: `sx approvals on` (Touch ID)"
        }
        let recent = day.filter { now.timeIntervalSince($0) < Self.shortWindow }
        if recent.count >= Self.shortLimit, let oldest = recent.min() {
            let wait = Int((Self.shortWindow - now.timeIntervalSince(oldest)) / 60) + 1
            return "\(recent.count) wrong passwords in 15 min; try again in \(wait) min"
        }
        return nil
    }

    public func attemptsLeft(now: Date = Date()) -> Int {
        let day = counted(now: now)
        let recent = day.filter { now.timeIntervalSince($0) < Self.shortWindow }.count
        return max(0, min(Self.shortLimit - recent, Self.longLimit - day.count))
    }

    /// Wrong passwords since the last correct one (shown to the owner after approving).
    public func failuresSinceSuccess(now: Date = Date()) -> Int {
        counted(now: now).filter { $0 > (lastSuccess ?? .distantPast) }.count
    }

    public mutating func beginAttempt(now: Date = Date()) {
        if let started = attemptStarted { failures.append(started) } // an earlier attempt never finished
        attemptStarted = now
        failures = failures.filter { now.timeIntervalSince($0) < Self.longWindow }
    }

    /// Ends the attempt begun with `beginAttempt`. Returns the wrong passwords since the previous success.
    @discardableResult
    public mutating func finishAttempt(ok: Bool, now: Date = Date()) -> Int {
        let started = attemptStarted ?? now
        attemptStarted = nil
        if ok {
            let since = failuresSinceSuccess(now: now)
            lastSuccess = now
            return since
        }
        failures = failures.filter { now.timeIntervalSince($0) < Self.longWindow } + [started]
        if failures.count >= Self.longLimit {
            enabled = false
            disabledReason = "\(failures.count) wrong passwords in 24 h"
        }
        return failuresSinceSuccess(now: now)
    }

    /// Touch ID at the Mac: on, and the counters start over.
    public mutating func turnOn() {
        enabled = true
        failures = []
        attemptStarted = nil
        disabledReason = nil
    }

    public mutating func turnOff() {
        enabled = false
        disabledReason = nil
    }
}

/// Remembered approvals. A grant is keyed by the request class it covers; `uses == nil` lasts until
/// `until`, `uses == 1` lets exactly one matching request through (the retry of a timed-out request).
/// Single-use grants live under `onceKey(class)`, apart from timed ones, so prod requests (which never
/// honor timed grants) can still take the one retry a human approved.
public struct GrantTable {
    public struct Grant: Equatable {
        public var key: String
        public var info: GrantInfo
        public var uses: Int?
    }

    public private(set) var grants: [String: Grant] = [:]

    public init() {}

    public static func onceKey(_ classKey: String) -> String { "once:" + classKey }

    public static func shortID(_ key: String) -> String {
        key.hasPrefix("once:") ? "1" + String(key.dropFirst(5).prefix(7)) : String(key.prefix(8))
    }

    /// Adding to an existing grant keeps the wider of the two: the later expiry, unlimited uses over counted.
    public mutating func add(key: String, info: GrantInfo, uses: Int? = nil) {
        var info = info
        var uses = uses
        if let old = grants[key] {
            if old.info.until > info.until { info.until = old.info.until }
            uses = old.uses == nil || uses == nil ? nil : (old.uses ?? 0) + (uses ?? 0)
        }
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

    /// Removes grants whose short id (as `sx grants` shows it) starts with `prefix`, at least 4 characters.
    public mutating func revoke(prefix: String) -> Int {
        let p = prefix.lowercased()
        guard p.count >= 4 else { return 0 }
        let hits = grants.filter { $0.value.info.id.hasPrefix(p) }.map(\.key)
        for k in hits { grants[k] = nil }
        return hits.count
    }

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

    /// More waiting requests than this are refused at once (a flood must not bury real requests).
    public static let maxWaiting = 32
    /// Finished requests kept for `sx pending` (the oldest go first).
    public static let maxKept = 200

    public private(set) var entries: [Int: Entry] = [:]
    private var nextID = 1

    public init() {}

    /// Nil when too many requests are already waiting.
    public mutating func add(_ info: PendingInfo, classKey: String, wideKey: String?, now: Date = Date()) -> Int? {
        prune(now: now)
        guard entries.values.filter({ $0.info.state == PendingInfo.State.waiting }).count < Self.maxWaiting else { return nil }
        var info = info
        info.id = nextID
        info.token = UUID().uuidString
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
        let ended = entries.values.filter { $0.info.ended != nil }.sorted { $0.info.id < $1.info.id }
        for e in ended.prefix(max(0, ended.count - Self.maxKept)) { entries[e.info.id] = nil }
    }

    public func list(now: Date = Date()) -> [PendingInfo] {
        entries.values.filter { e in
            guard let ended = e.info.ended else { return true }
            return now.timeIntervalSince(ended) < TerminalApproval.keepExpired
        }.map(\.info).sorted { $0.id < $1.id }
    }

    /// Checks that `id` (with the token `sx pending` showed for it) can be approved from a terminal now,
    /// and whether it is still waiting.
    public func pick(_ id: Int, token: String, now: Date = Date()) -> Result<Pick, PickError> {
        guard let e = entries[id] else { return .failure(.init("#\(id): no such request (see `sx pending`)")) }
        guard !token.isEmpty, e.info.token == token else {
            return .failure(.init("#\(id) is not the request you were shown (Sx.app restarted or the list changed); run `sx pending` again"))
        }
        guard e.info.terminal else { return .failure(.init("#\(id): \(e.info.what) needs Touch ID at the Mac")) }
        switch e.info.state {
        case PendingInfo.State.waiting:
            return e.approvedInTerminal ? .failure(.init("#\(id): already approved")) : .success(.waiting)
        case PendingInfo.State.expired:
            guard let ended = e.info.ended, now.timeIntervalSince(ended) < TerminalApproval.keepExpired else {
                return .failure(.init("#\(id): too old; let the program ask again"))
            }
            guard e.info.retryable else {
                return .failure(.init("#\(id) gave up already and has nothing its retry could be matched by (server not verified, or unknown data): let it ask again and approve it while it waits"))
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
