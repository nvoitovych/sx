import Foundation
import SxCore

/// `sx pending`, `sx approve`, `sx grants`, `sx revoke`, `sx approvals`: answering approval requests
/// from a terminal when Touch ID is out of reach (e.g. working on this Mac from a phone).
enum ApprovalCommands {
    static func pending(_ args: [String]) throws -> Int32 {
        let f = try Flags(args)
        let list = try Client.call(BrokerRequest(op: .pending)).pending ?? []
        if f.switches.contains("--json") {
            print(try json(list))
            return 0
        }
        if list.isEmpty {
            print("nothing is waiting for approval")
            return 0
        }
        for p in list { print(describe(p)) }
        let open = list.filter { $0.terminal && ($0.state == PendingInfo.State.waiting || ($0.state == PendingInfo.State.expired && $0.retryable)) }
        if let first = open.first {
            print("")
            print("approve:  sx approve \(open.map { String($0.id) }.joined(separator: " "))\(open.count > 1 ? "   (or one: sx approve \(first.id))" : "")")
            if first.canGrant { print("for 8 h:  sx approve \(first.id) --for 8h") }
        }
        return 0
    }

    static func approve(_ args: [String]) throws -> Int32 {
        let f = try Flags(args)
        // Early, clear refusal; the broker checks the terminal again on the real process and verifies the password.
        guard isatty(STDIN_FILENO) != 0 else {
            throw CLIError("\(TerminalApproval.noTerminal):\n  sx approve \(args.joined(separator: " "))", code: 126)
        }

        var seconds: Int?
        if let text = f.one("--for") {
            guard let s = TerminalApproval.duration(text) else {
                throw CLIError("--for \(text): use e.g. 30m, 8h or 1h30m (at most \(Int(TerminalApproval.maxGrant / 3600))h)")
            }
            seconds = Int(s)
        }
        let anyHost = f.switches.contains("--any-host")
        if anyHost, seconds == nil { throw CLIError("--any-host only goes with --for") }

        let list = try Client.call(BrokerRequest(op: .pending)).pending ?? []
        let approvable = list.filter { $0.terminal && ($0.state == PendingInfo.State.waiting || ($0.state == PendingInfo.State.expired && $0.retryable)) }
        var chosen: [PendingInfo]
        if f.switches.contains("--all") {
            guard f.positional.isEmpty else { throw CLIError("give ids or --all, not both") }
            chosen = approvable
        } else {
            guard !f.positional.isEmpty else { throw CLIError("usage: sx approve ID… | --all [--for 8h [--any-host]]   (ids: sx pending)") }
            chosen = []
            for raw in f.positional {
                guard let id = Int(raw.trimmingCharacters(in: CharacterSet(charactersIn: "#"))) else { throw CLIError("not a request id: \(raw)") }
                guard let p = list.first(where: { $0.id == id }) else { throw CLIError("#\(id): no such request (see `sx pending`)") }
                if !chosen.contains(where: { $0.id == id }) { chosen.append(p) }
            }
        }
        guard !chosen.isEmpty else {
            print("nothing to approve")
            return 0
        }
        for p in chosen {
            if !p.terminal { throw CLIError("#\(p.id): \(p.what) needs Touch ID at the Mac") }
            guard p.state == PendingInfo.State.waiting || p.state == PendingInfo.State.expired else { throw CLIError("#\(p.id): already \(DisplayText.safe(p.state))") }
            if p.state == PendingInfo.State.expired, !p.retryable {
                throw CLIError("#\(p.id) gave up already and cannot be approved after the fact (server not verified, or unknown data): let it ask again and approve it while it waits")
            }
            if seconds != nil, p.prod { throw CLIError("#\(p.id) uses a prod key: approve it once, without --for") }
            if seconds != nil, !anyHost, !p.canGrant {
                throw CLIError("#\(p.id): nothing to remember it by (server not verified, or not a login / signed-data request); approve it once, or add --any-host to allow this key for everything")
            }
            if anyHost, p.kind != "ssh-sign" { throw CLIError("#\(p.id): --any-host is only for SSH keys") }
        }

        // Show exactly what is approved; only these ids go to the broker, so a request that appears
        // while the password is typed is not included.
        print("You are approving \(chosen.count == 1 ? "this request" : "these \(chosen.count) requests"):")
        for p in chosen { print(describe(p)) }
        print("")
        if let seconds {
            let until = Date().addingTimeInterval(TimeInterval(seconds))
            print("and remembering, for \(format(TimeInterval(seconds))) (until about \(clock(until))), every request of the same kind:")
            for p in chosen { print("  #\(p.id) → \(p.who): \(scope(p, anyHost: anyHost))") }
        } else {
            print("once each (a request that timed out passes on its next try, within \(format(TerminalApproval.onceWindow))); nothing is remembered.")
        }
        print("")
        let password = try readPassword("macOS login password for \(NSUserName()): ")
        var req = BrokerRequest(op: .approve)
        req.ids = chosen.map(\.id)
        req.tokens = chosen.map(\.token)
        req.password = password
        req.seconds = seconds
        req.anyHost = anyHost ? true : nil
        // The password goes only to the real Sx.app (code signature checked on the socket's other end).
        let resp = try Client.call(req, verifyBroker: true)
        for line in resp.lines ?? [] { print(DisplayText.safe(line)) }
        return 0
    }

    static func grants(_ args: [String]) throws -> Int32 {
        let f = try Flags(args)
        let list = try Client.call(BrokerRequest(op: .grants)).grants ?? []
        if f.switches.contains("--json") {
            print(try json(list))
            return 0
        }
        if list.isEmpty { print("no remembered approvals") }
        for g in list {
            let uses = g.usesLeft.map { ", \($0) use\($0 == 1 ? "" : "s") left" } ?? ""
            print("\(DisplayText.safe(g.id))  \(DisplayText.safe(g.who))  \(DisplayText.safe(g.scope))  until \(clock(g.until))\(uses)  [\(DisplayText.safe(g.via))]")
        }
        if !list.isEmpty { print("\nrevoke:  sx revoke ID   or   sx revoke --all") }
        return 0
    }

    static func revoke(_ args: [String]) throws -> Int32 {
        let f = try Flags(args)
        let req: BrokerRequest
        if f.switches.contains("--all") {
            req = BrokerRequest(op: .revoke, name: "all")
        } else {
            guard !f.positional.isEmpty else { throw CLIError("usage: sx revoke ID… | --all   (ids: sx grants)") }
            var r = BrokerRequest(op: .revoke)
            r.grantIDs = f.positional
            req = r
        }
        for line in try Client.call(req).lines ?? [] { print(DisplayText.safe(line)) }
        return 0
    }

    static func approvals(_ args: [String]) throws -> Int32 {
        let sub = args.first
        guard sub == nil || sub == "on" || sub == "off" || sub == "status" else { throw CLIError("usage: sx approvals [on|off|status]") }
        let name = sub == "status" ? nil : sub
        let resp = try Client.call(BrokerRequest(op: .approvals, name: name, agent: AgentDetect.detect()))
        for line in resp.lines ?? [] { print(DisplayText.safe(line)) }
        return 0
    }

    // MARK: - Output

    static func describe(_ p: PendingInfo) -> String {
        let safe = DisplayText.safe
        var state: String
        switch p.state {
        case PendingInfo.State.waiting:
            state = p.deadline.map { "waiting, \(max(0, Int($0.timeIntervalSinceNow)))s left" } ?? "queued"
        case PendingInfo.State.expired:
            state = p.retryable ? "timed out — approve and the next try passes" : "timed out — cannot be approved now; approve it while it waits"
        default:
            state = safe(p.state)
        }
        if !p.terminal { state += "; Touch ID only" }
        if p.prod { state += "; PROD: once only" }
        var lines = ["#\(p.id)  \(safe(p.what))  [\(state)]"]
        lines.append("     who:   \(safe(p.who))\(p.agent != nil ? " (AI agent)" : "")  ·  asked \(clock(p.created))")
        if !p.chain.isEmpty { lines.append("     chain: \(p.chain.map(safe).joined(separator: " ← "))") }
        if p.kind == "ssh-sign" {
            if let hk = p.hostKey {
                lines.append("     host:  host key \(hk)  (the caller calls it \(safe(p.host ?? "?")))")
            } else if let host = p.host {
                lines.append("     host:  \(safe(host))  (as typed by the caller; server NOT verified)")
            }
        } else if let argv = p.argv {
            lines.append("     runs:  \(DisplayText.shellQuoted(argv))")
        } else if let command = p.command {
            lines.append("     runs:  \(safe(command))")
        }
        if let cwd = p.cwd, p.kind != "ssh-sign" { lines.append("     in:    \(safe((cwd as NSString).abbreviatingWithTildeInPath))") }
        if !p.names.isEmpty { lines.append("     keys:  \(p.names.map(safe).joined(separator: ", "))") }
        return lines.joined(separator: "\n")
    }

    /// What `--for` covers for one request (mirrors the broker's grant classes). Requester text is escaped.
    static func scope(_ p: PendingInfo, anyHost: Bool) -> String {
        if p.kind == "ssh-sign" {
            let key = p.names.first ?? "?"
            if anyHost { return "every signature with \(key): ANY server, any data" }
            if let hk = p.hostKey { return "logins with \(key) to the server with host key \(hk) only (the caller calls it \(DisplayText.safe(p.host ?? "?")))" }
            return "signatures with \(key) of the same kind: \(DisplayText.safe(p.what))"
        }
        let command = p.argv.map(DisplayText.shellQuoted) ?? DisplayText.safe(p.command ?? "?")
        let cwd = DisplayText.safe(((p.cwd ?? "?") as NSString).abbreviatingWithTildeInPath)
        return "this command line, \(command), in \(cwd) with \(p.names.map(DisplayText.safe).joined(separator: ", ")) (what the command does can still change, e.g. package.json scripts)"
    }

    static func clock(_ d: Date) -> String { d.formatted(date: .omitted, time: .standard) }

    static func format(_ t: TimeInterval) -> String {
        let m = Int(t / 60)
        return m % 60 == 0 ? "\(m / 60) h" : m >= 60 ? "\(m / 60) h \(m % 60) min" : "\(m) min"
    }

    static func json<T: Encodable>(_ value: T) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return String(data: try enc.encode(value), encoding: .utf8)!
    }

    /// Reads from /dev/tty with echo off and refuses without a terminal (RPP_REQUIRE_TTY).
    static func readPassword(_ prompt: String) throws -> String {
        var buf = [CChar](repeating: 0, count: 4096)
        defer { buf.withUnsafeMutableBufferPointer { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard let p = readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) else { throw CLIError("no terminal to read the password from", code: 126) }
        let s = String(cString: p)
        guard !s.isEmpty else { throw CLIError("cancelled (empty password)") }
        guard s.utf8.count < buf.count - 1 else { throw CLIError("password too long") }
        return s
    }
}
