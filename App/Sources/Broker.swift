import CryptoKit
import Foundation
import Security
import SxCore

/// Unix-socket broker in the app group container. Accepts only clients whose code signature
/// satisfies `SX.clientRequirement`, then applies approval policy before releasing any value.
final class Broker {
    static let shared = Broker()

    private var listenFD: Int32 = -1
    private let workers = DispatchQueue(label: "dev.nvlab.sx.broker", attributes: .concurrent)
    /// One Touch ID prompt at a time; concurrent requests for the same approval wait and reuse it.
    private let approvalGate = NSLock()
    private(set) var startError: String?

    func start() {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SX.appGroup) else {
            startError = "no app group container"
            return
        }
        let path = container.appendingPathComponent("broker.sock").path
        do {
            listenFD = try UnixSocket.listen(path)
        } catch {
            startError = "\(error)"
            return
        }
        Thread.detachNewThread { [self] in
            while true {
                let fd = accept(listenFD, nil, nil)
                if fd < 0 {
                    if errno == EINTR { continue }
                    break
                }
                UnixSocket.noSigPipe(fd)
                workers.async { self.serve(fd) }
            }
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        let peer = PeerIdentity(fd: fd)
        let response: BrokerResponse
        if let problem = peer.problem {
            response = .fail("client rejected: \(problem)")
            AuditLog.shared.record(.init(time: Date(), op: "connect", client: peer.label, names: [], outcome: "rejected: \(problem)"))
        } else if let line = try? UnixSocket.readLine(fd), let req = try? Wire.decode(BrokerRequest.self, from: line) {
            response = handle(req, peer: peer, fd: fd)
        } else {
            response = .fail("malformed request")
        }
        if let data = try? Wire.encode(response) { try? UnixSocket.writeAll(fd, data) }
    }

    private func handle(_ req: BrokerRequest, peer: PeerIdentity, fd: Int32) -> BrokerResponse {
        func approve(_ card: ApprovalPanel.Request, reason: String, key: String?, context: ApprovalContext? = nil) -> String? {
            self.approve(card, reason: reason, key: key, clientFD: fd, context: context)
        }
        func audit(_ names: [String], _ outcome: String) {
            AuditLog.shared.record(.init(time: Date(), op: req.op.rawValue, client: peer.label, agent: req.agent,
                                         command: req.argv?.joined(separator: " "), cwd: req.cwd, names: names, outcome: outcome))
        }
        do {
            switch req.op {
            case .ping:
                return BrokerResponse(ok: true, version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)

            case .list:
                return BrokerResponse(ok: true, secrets: try KeychainStore.list())

            case .hash:
                guard let name = req.name else { return .fail("name required") }
                let data = try KeychainStore.get(name)
                return BrokerResponse(ok: true, hash: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined().prefix(16).description)

            case .put:
                guard let name = req.name, SecretName.isValid(name) else { return .fail("invalid name") }
                guard let b64 = req.value, let value = Data(base64Encoded: b64), !value.isEmpty else { return .fail("empty value") }
                if KeychainStore.exists(name) {
                    let who = req.agent ?? "Terminal"
                    let card = ApprovalPanel.Request(title: "wants to overwrite a key", who: who, isAgent: req.agent != nil, command: nil,
                                                     project: nil, secrets: [name], alwaysAsk: true)
                    if let why = approve(card, reason: "\(who) wants to OVERWRITE secret \(name)", key: nil) {
                        audit([name], "denied overwrite: \(why)")
                        return .fail("overwrite of \(name) was not approved: \(why)")
                    }
                }
                try KeychainStore.put(name, value: value, tags: req.tags ?? [])
                audit([name], "stored")
                DispatchQueue.main.async { SecretsModel.shared.reload() }
                return BrokerResponse(ok: true)

            case .remove:
                guard let name = req.name else { return .fail("name required") }
                let who = req.agent ?? "Terminal"
                let card = ApprovalPanel.Request(title: "wants to delete a key", who: who, isAgent: req.agent != nil, command: nil,
                                                 project: nil, secrets: [name], alwaysAsk: true)
                if let why = approve(card, reason: "Delete secret \(name)", key: nil) {
                    audit([name], "denied delete: \(why)")
                    return .fail("delete was not approved: \(why)")
                }
                try KeychainStore.remove(name)
                audit([name], "deleted")
                DispatchQueue.main.async { SecretsModel.shared.reload() }
                return BrokerResponse(ok: true)

            case .resolve:
                let names = Array(Set(req.names ?? [])).sorted()
                let external = Array(Set(req.external ?? [])).sorted()
                guard !names.isEmpty || !external.isEmpty else { return BrokerResponse(ok: true, values: [:]) }
                let shown = names.filter { !$0.hasPrefix(SX.internalPrefix) } + external
                let argv = req.argv ?? []
                if req.agent != nil, let why = Policy.agentDenial(argv: argv) {
                    audit(shown, "refused: \(why)")
                    return .fail("refused: \(why)")
                }
                let prod = names.contains { KeychainStore.tags($0).contains("prod") }
                let who = req.agent ?? "Terminal"

                // Project allowlist: binding for agents once a human has trusted the file.
                var preApproved = false
                if req.agent != nil, let file = req.projectFile {
                    switch ProjectTrust.check(file) {
                    case let .untrusted(why):
                        audit(shown, "refused: \(why)")
                        return .fail("refused: \(why) — a human must run `sx trust` in this project")
                    case let .trusted(policy):
                        if policy.allows(argv) {
                            preApproved = true
                        } else if policy.require {
                            audit(shown, "refused: not in .sx.toml allowlist")
                            return .fail("refused: `\(argv.joined(separator: " "))` is not in \(file) [agents].allow")
                        }
                    }
                }

                if !(preApproved && !prod) {
                    let reason = "\(who) runs `\(argv.prefix(4).joined(separator: " "))` in \(((req.cwd ?? "?") as NSString).lastPathComponent) with \(shown.joined(separator: ", "))"
                    let classKey = Approver.shared.key(cwd: req.cwd ?? "", argv: argv, names: names + external)
                    let key = prod ? nil : classKey
                    let context = ApprovalContext(kind: "secrets", what: "use \(shown.count) secret\(shown.count == 1 ? "" : "s") for a command",
                                                  terminal: true, classKey: classKey, chain: Self.chain(peer.pid), argv: argv, canGrant: !prod)
                    let card = ApprovalPanel.Request(title: "wants to use \(shown.count) \(shown.count == 1 ? "key" : "keys")", who: who, isAgent: req.agent != nil,
                                                     command: argv.joined(separator: " "),
                                                     project: req.cwd, secrets: shown, alwaysAsk: prod, isProduction: prod,
                                                     note: "Keys go to this command only. Its output is masked.")
                    if let why = approve(card, reason: reason, key: key, context: context) {
                        audit(shown, "denied: \(why)")
                        return .fail("not approved: \(why)")
                    }
                }
                var values: [String: String] = [:]
                for n in names { values[n] = try KeychainStore.get(n).base64EncodedString() }
                audit(shown, preApproved && !prod ? "released (allowed by .sx.toml)" : "released")
                return BrokerResponse(ok: true, values: values)

            case .reveal:
                guard let name = req.name else { return .fail("name required") }
                if let agent = req.agent {
                    audit([name], "refused: export is human-only")
                    return .fail("refused for \(agent): exporting a value to a file is human-only")
                }
                let card = ApprovalPanel.Request(title: "wants to write a key to a file", who: "Terminal", command: req.argv?.joined(separator: " "),
                                                 project: req.cwd, secrets: [name], alwaysAsk: true,
                                                 note: "The file will hold the real value. Delete it when you no longer need it.")
                if let why = approve(card, reason: "Write \(name) to a file", key: nil) {
                    audit([name], "denied: \(why)")
                    return .fail("not approved: \(why)")
                }
                let value = try KeychainStore.get(name)
                audit([name], "exported to a file")
                return BrokerResponse(ok: true, values: [name: value.base64EncodedString()])

            case .trust:
                guard let file = req.projectFile else { return .fail("projectFile required") }
                guard let data = FileManager.default.contents(atPath: file),
                      let policy = try? ProjectPolicy.parse(String(decoding: data, as: UTF8.self)) else {
                    return .fail("cannot read or parse \(file)")
                }
                let who = req.agent ?? "Terminal"
                let allow = policy.allow.isEmpty ? "nothing" : policy.allow.joined(separator: " · ")
                let card = ApprovalPanel.Request(title: "wants you to trust this project's agent rules", who: who, isAgent: req.agent != nil,
                                                 command: "agents may run: \(allow)\(policy.require ? " (and nothing else)" : "")",
                                                 project: file, secrets: [], alwaysAsk: true)
                if let why = approve(card, reason: "Trust \(file)", key: nil) {
                    audit([], "denied trust \(file): \(why)")
                    return .fail("not trusted: \(why)")
                }
                try ProjectTrust.trust(file, data: data)
                audit([], "trusted \(file)")
                return BrokerResponse(ok: true)

            case .pending:
                return BrokerResponse(ok: true, pending: PendingRegistry.shared.list())

            case .grants:
                return BrokerResponse(ok: true, grants: Approver.shared.grantInfos)

            case .revoke:
                // Taking power away needs no proof; anyone, agents included, may revoke.
                if req.name == "all" {
                    Approver.shared.revokeAll()
                    audit([], "revoked all approvals")
                    return BrokerResponse(ok: true, lines: ["✓ all remembered approvals revoked"])
                }
                var lines: [String] = []
                for g in req.grantIDs ?? [] {
                    let n = Approver.shared.revoke(g)
                    lines.append(n > 0 ? "✓ revoked \(g)" : "no approval \(g) (ids need at least 4 characters; see `sx grants`)")
                    audit([], n > 0 ? "revoked \(g)" : "revoke \(g): none")
                }
                return BrokerResponse(ok: true, lines: lines)

            case .approvals:
                return try approvals(req, peer: peer, approve: { approve($0, reason: $1, key: nil) }, audit: { audit([], $0) })

            case .approve:
                return approveFromTerminal(req, peer: peer, audit: { names, outcome, chain in
                    AuditLog.shared.record(.init(time: Date(), op: "approve", client: chain, command: req.ids.map { "sx approve \($0.map(String.init).joined(separator: " "))" },
                                                 names: names, outcome: outcome))
                })
            }
        } catch {
            audit(req.names ?? req.name.map { [$0] } ?? [], "error")
            return .fail("\(error)")
        }
    }

    /// `key == nil` means always prompt (no "remember" option). Returns nil when approved, otherwise why not.
    /// Every request is listed in `sx pending` while it waits; with `context.terminal` it can also be
    /// approved there (`sx approve`), which closes the card.
    func approve(_ card: ApprovalPanel.Request, reason: String, key: String?, clientFD: Int32? = nil,
                 context: ApprovalContext? = nil) -> String? {
        let ctx = context ?? ApprovalContext(kind: "other", what: reason)
        let prod = card.isProduction
        // Timed grants (card "Allow for N h", `sx approve --for`) never cover prod; the single retry a
        // human approved in a terminal does.
        func granted() -> Bool {
            if let key, Approver.shared.isApproved(key) { return true }
            if !prod, let c = ctx.classKey, c != key, Approver.shared.isApproved(c) { return true }
            if ctx.terminal, let c = ctx.classKey, Approver.shared.isApproved(GrantTable.onceKey(c)) { return true }
            return false
        }
        if granted() { return nil }

        guard let id = PendingRegistry.shared.add(
            PendingInfo(kind: ctx.kind, what: ctx.what, who: card.who, agent: card.isAgent ? card.who : nil, chain: ctx.chain,
                        command: card.command, argv: ctx.argv, cwd: card.project, names: card.secrets, host: ctx.host, hostKey: ctx.hostKey,
                        prod: prod, terminal: ctx.terminal, canGrant: ctx.canGrant && !prod, retryable: ctx.retryable),
            classKey: ctx.classKey ?? UUID().uuidString, wideKey: prod ? nil : ctx.wideKey) else {
            return "too many requests are waiting for approval; try again later"
        }
        var endState = PendingInfo.State.expired
        defer { PendingRegistry.shared.end(id, state: endState) }
        let cancelled = { clientFD.map(Broker.peerClosed) ?? false }
        let reasonText = reason.count > 180 ? String(reason.prefix(177)) + "…" : reason
        let started = Date()

        // One card at a time. Requests behind it wait here, listed as pending and approvable from a terminal.
        while true {
            if PendingRegistry.shared.approvedInTerminal(id) || granted() {
                endState = PendingInfo.State.approved
                return nil
            }
            if cancelled() { return "the requesting program exited" }
            if Date().timeIntervalSince(started) > Self.queueLimit { return "timed out waiting for approval" }
            if approvalGate.try() {
                defer { approvalGate.unlock() }
                if PendingRegistry.shared.approvedInTerminal(id) || granted() {
                    endState = PendingInfo.State.approved
                    return nil
                }
                PendingRegistry.shared.setDeadline(id, Date().addingTimeInterval(Approver.answerTimeout))
                let result = Approver.shared.authorize(card, reason: reasonText, offerRemember: key != nil, isCancelled: cancelled,
                                                       external: { PendingRegistry.shared.approvedInTerminal(id) ? .approved(remember: false) : nil })
                if let why = result.error {
                    if PendingRegistry.shared.approvedInTerminal(id), !cancelled() {
                        endState = PendingInfo.State.approved // approved in a terminal as the card timed out
                        return nil
                    }
                    if why == "denied by user" { endState = PendingInfo.State.denied }
                    return why
                }
                endState = PendingInfo.State.approved
                if let key, result.remember { Approver.shared.remember(key, card: card) }
                return nil
            }
            usleep(250_000)
        }
    }

    /// A request queued behind other cards gives up after this long.
    static let queueLimit: TimeInterval = 600

    /// Process chain of a peer for display: executable names, nearest first.
    static func chain(_ pid: pid_t) -> [String] {
        AgentDetect.ancestry(from: pid).prefix(6).map { ($0 as NSString).lastPathComponent }
    }

    /// Serializes limiter check, password check and limiter update, so parallel guesses cannot overrun the
    /// limit, and keeps `sx approvals off` from landing in the middle of an attempt.
    static let passwordLock = NSLock()

    /// `sx approve`: the account password, typed at a real terminal. Whoever started the command, only the
    /// password (which the owner alone knows) approves; it is checked here, never by the CLI.
    private func approveFromTerminal(_ req: BrokerRequest, peer: PeerIdentity,
                                     audit: (_ names: [String], _ outcome: String, _ chain: String) -> Void) -> BrokerResponse {
        let ancestry = AgentDetect.ancestry(from: peer.pid)
        let chainText = ancestry.prefix(6).map { ($0 as NSString).lastPathComponent }.joined(separator: " ← ")
        if let why = TerminalApproval.refusal(controllingTTY: AgentDetect.controllingTTY(of: peer.pid),
                                              stdinPath: AgentDetect.descriptorPath(of: peer.pid, fd: 0)) {
            audit([], "refused: \(why)", chainText)
            return .fail("refused: \(why)")
        }
        let ids = req.ids ?? []
        guard !ids.isEmpty, ids.count <= 64 else { return .fail("which requests? see `sx pending`") }
        if let s = req.seconds, s < 60 || TimeInterval(s) > TerminalApproval.maxGrant {
            return .fail("--for must be between 1 minute and \(Int(TerminalApproval.maxGrant / 3600)) hours")
        }
        let anyHost = req.anyHost ?? false
        let entries: [PendingTable.Entry]
        switch PendingRegistry.shared.check(ids, tokens: req.tokens ?? [], seconds: req.seconds, anyHost: anyHost) {
        case let .failure(e): return .fail(e.description)
        case let .success(list): entries = list
        }

        Self.passwordLock.lock()
        let state = TerminalApprovalStore.load()
        if let why = state.refusal() {
            Self.passwordLock.unlock()
            audit([], "refused: \(why)", chainText)
            return .fail(why)
        }
        // The attempt counts as failed until it succeeds (begun before the check), so an attempt that
        // cannot be recorded is not made (fail closed) and a crash mid-check still counts.
        do {
            try TerminalApprovalStore.update { $0.beginAttempt() }
        } catch {
            Self.passwordLock.unlock()
            audit([], "refused: cannot record the attempt: \(error)", chainText)
            return .fail("cannot record the attempt in the keychain (\(error)); not checking the password")
        }
        let ok = AccountPassword.verify(req.password ?? "")
        var since = 0
        let after = try? TerminalApprovalStore.update { since = $0.finishAttempt(ok: ok) }
        Self.passwordLock.unlock()
        guard ok else {
            audit(entries.flatMap(\.info.names), "wrong password", chainText)
            if let after, !after.enabled { return .fail("wrong password; terminal approvals are now off (\(after.disabledReason ?? "")). Turn them on at the Mac: `sx approvals on`") }
            return .fail("wrong password (\(after?.attemptsLeft() ?? 0) more tries before a lock)")
        }
        let lines = PendingRegistry.shared.apply(entries, seconds: req.seconds, anyHost: anyHost)
        for (e, line) in zip(entries, lines) {
            let how = req.seconds.map { "for \($0 / 60) min, \(PendingRegistry.scope(e.info, anyHost: anyHost))" } ?? "once"
            audit(e.info.names, "approved #\(e.info.id) in terminal (\(how)) for \(e.info.who): \(line)", chainText)
        }
        var out = lines
        if since > 0 {
            out.append("⚠ \(since) wrong password\(since == 1 ? "" : "s") since your last approval (not yours? something is guessing: `sx approvals off`)")
            audit([], "\(since) wrong passwords since the previous approval", chainText)
        }
        return BrokerResponse(ok: true, lines: out)
    }

    /// `sx approvals on|off|status`.
    private func approvals(_ req: BrokerRequest, peer: PeerIdentity, approve: (ApprovalPanel.Request, String) -> String?,
                           audit: (String) -> Void) throws -> BrokerResponse {
        switch req.name {
        case "on":
            let card = ApprovalPanel.Request(title: "wants to allow approvals from a terminal", who: req.agent ?? "Terminal",
                                             isAgent: req.agent != nil, command: "sx approvals on", project: nil, secrets: [], alwaysAsk: true,
                                             note: "Then `sx approve` in a terminal accepts your login password instead of Touch ID.")
            if let why = approve(card, "Allow approving sx requests from a terminal with your login password") {
                audit("denied terminal approvals on: \(why)")
                return .fail("not turned on: \(why)")
            }
            try TerminalApprovalStore.update { $0.turnOn() }
            audit("terminal approvals on")
            return BrokerResponse(ok: true, lines: ["✓ terminal approvals on: `sx approve ID` takes your login password"])
        case "off":
            // Like revoke: taking power away needs no proof.
            Self.passwordLock.lock()
            defer { Self.passwordLock.unlock() }
            try TerminalApprovalStore.update { $0.turnOff() }
            audit("terminal approvals off")
            return BrokerResponse(ok: true, lines: ["✓ terminal approvals off (turning them on again needs Touch ID)"])
        default:
            let s = TerminalApprovalStore.load()
            var lines = [s.enabled ? "terminal approvals: on" : "terminal approvals: off\(s.disabledReason.map { " (\($0))" } ?? "")"]
            if s.enabled { lines.append("wrong passwords in 24 h: \(s.failures.count) (\(s.failuresSinceSuccess()) since the last approval); tries left now: \(s.attemptsLeft())") }
            if let why = s.refusal(), s.enabled { lines.append(why) }
            return BrokerResponse(ok: true, lines: lines)
        }
    }
}

/// What `sx pending` shows about a request and what approving it covers.
struct ApprovalContext {
    var kind: String
    var what: String
    /// Can be approved with `sx approve` (SSH signatures, `sx run` secrets). Deletes, exports, trust: Touch ID only.
    var terminal = false
    /// The request class a single approval (retry) or `--for` covers.
    var classKey: String?
    /// SSH only: the key for any server (`--for … --any-host`), the same class the card's "Allow for N h" remembers.
    var wideKey: String?
    var chain: [String] = []
    /// `sx run`: the command as separate arguments, shown shell-quoted.
    var argv: [String]?
    var host: String?
    var hostKey: String?
    var canGrant = false
    /// False when the class is unique to this request (approving it after it gave up would match nothing).
    var retryable = true
}

extension Broker {
    /// True once the other end of a waiting client socket has closed (e.g. the command was interrupted).
    static func peerClosed(_ fd: Int32) -> Bool {
        var byte: UInt8 = 0
        let n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        return n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
    }
}

/// Code-signature check of the connected process via its audit token.
struct PeerIdentity {
    let pid: pid_t
    let label: String
    let problem: String?

    init(fd: Int32) {
        var pid: pid_t = 0
        var pidLen = socklen_t(MemoryLayout<pid_t>.size)
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLen)
        self.pid = pid

        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) == 0 else {
            label = "pid \(pid)"
            problem = "no peer token"
            return
        }
        let tokenData = Data(bytes: &token, count: Int(len))
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        let guestStatus = SecCodeCopyGuestWithAttributes(nil, attrs, [], &code)
        guard guestStatus == errSecSuccess, let code else {
            label = "pid \(pid)"
            problem = "cannot resolve code (OSStatus \(guestStatus), token \(len) bytes)"
            return
        }
        var staticCode: SecStaticCode?
        var path = "pid \(pid)"
        if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode {
            var url: CFURL?
            if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url { path = (url as URL).path }
        }
        label = path
        var requirement: SecRequirement?
        SecRequirementCreateWithString(SX.clientRequirement as CFString, [], &requirement)
        let status = SecCodeCheckValidity(code, [], requirement)
        problem = status == errSecSuccess ? nil : "signature does not match \(SX.cliIdentifier) by team \(SX.teamID)"
    }
}
