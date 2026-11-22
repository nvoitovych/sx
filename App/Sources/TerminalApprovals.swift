import Foundation
import OpenDirectory
import Security
import SxCore

/// Requests waiting for a human. The broker thread that asked keeps waiting while `sx approve`
/// (another connection) marks its entry approved; requests that timed out stay approvable for a
/// while so their retry passes.
final class PendingRegistry {
    static let shared = PendingRegistry()

    private var table = PendingTable()
    private let lock = NSLock()

    /// Nil when too many requests are already waiting.
    func add(_ info: PendingInfo, classKey: String, wideKey: String?) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        return table.add(info, classKey: classKey, wideKey: wideKey)
    }

    /// The waiting request finished. If `sx approve` approved it at the same moment the program gave up,
    /// the approval carries over to its retry.
    func end(_ id: Int, state: String) {
        lock.lock()
        let lost = state == PendingInfo.State.expired ? table.entry(id).flatMap { $0.approvedInTerminal && $0.info.state == PendingInfo.State.waiting ? $0 : nil } : nil
        table.end(id, state: lost == nil ? state : PendingInfo.State.approved)
        lock.unlock()
        if let lost { Self.rememberOnce(lost) }
    }

    func setDeadline(_ id: Int, _ deadline: Date) {
        lock.lock()
        table.setDeadline(id, deadline)
        lock.unlock()
    }

    /// True once `sx approve` approved this live request.
    func approvedInTerminal(_ id: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return table.entry(id)?.approvedInTerminal == true
    }

    func list() -> [PendingInfo] {
        lock.lock()
        defer { lock.unlock() }
        table.prune()
        return table.list()
    }

    /// Validates every (id, token) before anything is approved (and before a password attempt is spent).
    func check(_ ids: [Int], tokens: [String], seconds: Int?, anyHost: Bool) -> Result<[PendingTable.Entry], PendingTable.PickError> {
        guard ids.count == tokens.count else { return .failure(.init("each id needs its token; update sx")) }
        lock.lock()
        defer { lock.unlock() }
        var out: [PendingTable.Entry] = []
        for (id, token) in zip(ids, tokens) {
            if case let .failure(e) = table.pick(id, token: token) { return .failure(e) }
            guard let e = table.entry(id) else { return .failure(.init("#\(id): gone")) }
            if seconds != nil {
                if e.info.prod { return .failure(.init("#\(id): \(e.info.names.joined(separator: ", ")) is tagged prod — approve it once, without --for")) }
                if anyHost, e.wideKey == nil { return .failure(.init("#\(id): --any-host is only for SSH keys")) }
                if !anyHost, !e.info.canGrant {
                    return .failure(.init("#\(id): this request has no class to remember (server not verified, or not a login or signed-data request); approve it once, or add --any-host to allow this key for everything"))
                }
            }
            out.append(e)
        }
        return .success(out)
    }

    /// Applies an approval checked by `check`. Returns one line per request for the terminal.
    func apply(_ entries: [PendingTable.Entry], seconds: Int?, anyHost: Bool) -> [String] {
        var lines: [String] = []
        for e in entries {
            let id = e.info.id
            // Decide under one lock, so a request cannot change state between the check and the approval.
            lock.lock()
            let pick = table.pick(id, token: e.info.token)
            switch pick {
            case .success(.waiting): table.approveLive(id)
            case .success(.expired): table.markApprovedAfterExpiry(id)
            case .failure: break
            }
            lock.unlock()
            guard case let .success(state) = pick else {
                lines.append("#\(id): no longer approvable")
                continue
            }
            if let seconds {
                let until = Date().addingTimeInterval(TimeInterval(seconds))
                let key = anyHost ? (e.wideKey ?? e.classKey) : e.classKey
                Approver.shared.remember(key, info: GrantInfo(who: e.info.who, scope: Self.scope(e.info, anyHost: anyHost),
                                                              names: e.info.names, until: until, via: "terminal"))
                if state == .expired { Self.rememberOnce(e) } // prod never reaches here; keeps the retry independent of the class
                lines.append("✓ #\(id) approved\(state == .expired ? " — its next try passes" : ""); the same kind of request passes until \(Self.clock(until))")
            } else if state == .expired {
                let until = Self.rememberOnce(e)
                lines.append("✓ #\(id) approved — its next try passes (once, until \(Self.clock(until)))")
            } else {
                lines.append("✓ #\(id) approved")
            }
        }
        return lines
    }

    /// A single-use approval of the request's class: its retry passes (prod included).
    @discardableResult
    static func rememberOnce(_ e: PendingTable.Entry) -> Date {
        let until = Date().addingTimeInterval(TerminalApproval.onceWindow)
        Approver.shared.remember(GrantTable.onceKey(e.classKey),
                                 info: GrantInfo(who: e.info.who, scope: scope(e.info, anyHost: false) + " (next try only)",
                                                 names: e.info.names, until: until, via: "terminal"), uses: 1)
        return until
    }

    /// What a grant covers, in words (sanitized: the parts come from the requester).
    static func scope(_ p: PendingInfo, anyHost: Bool) -> String {
        if p.kind == "ssh-sign" {
            let key = p.names.first ?? "?"
            if anyHost { return "\(key) → anything (any server, any data)" }
            if let hk = p.hostKey { return "\(key) → server with host key \(hk) (caller called it \(DisplayText.safe(p.host ?? "?")))" }
            return "\(key) → \(DisplayText.safe(p.what))"
        }
        let command = p.argv.map(DisplayText.shellQuoted) ?? DisplayText.safe(p.command ?? "?")
        return "`\(command)` in \(DisplayText.safe(((p.cwd ?? "?") as NSString).abbreviatingWithTildeInPath))"
    }

    static func clock(_ d: Date) -> String { d.formatted(date: .omitted, time: .shortened) }
}

/// On/off switch and wrong-password counter, in this Mac's keychain (not synced; agents cannot write it).
enum TerminalApprovalStore {
    private static let service = "dev.nvlab.sx.terminal-approvals"
    private static let lock = NSLock()

    private static func query() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "state",
            kSecAttrAccessGroup as String: SX.keychainAccessGroup,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func load() -> TerminalApprovalState {
        var q = query()
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data,
              let state = try? Wire.decode(TerminalApprovalState.self, from: data) else { return TerminalApprovalState() }
        return state
    }

    static func save(_ state: TerminalApprovalState) throws {
        let data = try Wire.encode(state)
        var status = SecItemUpdate(query() as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = query()
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainStore.Failure("save terminal approvals", status) }
    }

    /// Load-modify-save under one lock.
    @discardableResult
    static func update(_ change: (inout TerminalApprovalState) -> Void) throws -> TerminalApprovalState {
        lock.lock()
        defer { lock.unlock() }
        var s = load()
        change(&s)
        try save(s)
        return s
    }
}

/// Checks the password of the user Sx.app runs as, through Open Directory (no UI, no root).
/// Calls are serialized and a wrong password costs a second, so guessing is slow even before the limiter.
enum AccountPassword {
    private static let gate = NSLock()

    static func verify(_ password: String) -> Bool {
        gate.lock()
        defer { gate.unlock() }
        guard !password.isEmpty else { return false }
        do {
            let session = ODSession.default()
            let node = try ODNode(session: session, type: ODNodeType(kODNodeTypeAuthentication))
            let record = try node.record(withRecordType: kODRecordTypeUsers, name: NSUserName(), attributes: nil)
            try record.verifyPassword(password)
            return true
        } catch {
            sleep(1)
            return false
        }
    }
}
