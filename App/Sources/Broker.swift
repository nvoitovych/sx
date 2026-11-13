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
            response = handle(req, peer: peer)
        } else {
            response = .fail("malformed request")
        }
        if let data = try? Wire.encode(response) { try? UnixSocket.writeAll(fd, data) }
    }

    private func handle(_ req: BrokerRequest, peer: PeerIdentity) -> BrokerResponse {
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
                    let who = req.agent.map { "\($0) (agent)" } ?? "Terminal"
                    let card = ApprovalPanel.Request(title: "Overwrite a secret?", who: who, command: nil,
                                                     project: req.cwd, secrets: [name], alwaysAsk: true)
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
                let who = req.agent.map { "\($0) (agent)" } ?? "Terminal"
                let card = ApprovalPanel.Request(title: "Delete a secret?", who: who, command: nil,
                                                 project: req.cwd, secrets: [name], alwaysAsk: true)
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
                let who = req.agent.map { "\($0) (agent)" } ?? "Terminal"

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
                    let key = prod ? nil : Approver.shared.key(cwd: req.cwd ?? "", argv: argv, names: names + external)
                    let card = ApprovalPanel.Request(title: "Use secrets?", who: who, command: argv.joined(separator: " "),
                                                     project: req.cwd, secrets: shown, alwaysAsk: prod)
                    if let why = approve(card, reason: reason, key: key) {
                        audit(shown, "denied: \(why)")
                        return .fail("not approved: \(why)")
                    }
                }
                var values: [String: String] = [:]
                for n in names { values[n] = try KeychainStore.get(n).base64EncodedString() }
                audit(shown, preApproved && !prod ? "released (allowed by .sx.toml)" : "released")
                return BrokerResponse(ok: true, values: values)

            case .trust:
                guard let file = req.projectFile else { return .fail("projectFile required") }
                guard let data = FileManager.default.contents(atPath: file),
                      let policy = try? ProjectPolicy.parse(String(decoding: data, as: UTF8.self)) else {
                    return .fail("cannot read or parse \(file)")
                }
                let who = req.agent.map { "\($0) (agent)" } ?? "Terminal"
                let allow = policy.allow.isEmpty ? "nothing" : policy.allow.joined(separator: " · ")
                let card = ApprovalPanel.Request(title: "Trust this project's agent allowlist?", who: who,
                                                 command: "agents may run: \(allow)\(policy.require ? " (and nothing else)" : "")",
                                                 project: file, secrets: [], alwaysAsk: true)
                if let why = approve(card, reason: "Trust \(file)", key: nil) {
                    audit([], "denied trust \(file): \(why)")
                    return .fail("not trusted: \(why)")
                }
                try ProjectTrust.trust(file, data: data)
                audit([], "trusted \(file)")
                return BrokerResponse(ok: true)
            }
        } catch {
            audit(req.names ?? req.name.map { [$0] } ?? [], "error")
            return .fail("\(error)")
        }
    }

    /// `key == nil` means always prompt. Returns nil when approved, otherwise why not.
    func approve(_ card: ApprovalPanel.Request, reason: String, key: String?) -> String? {
        if let key, Approver.shared.isApproved(key) { return nil }
        approvalGate.lock()
        defer { approvalGate.unlock() }
        if let key, Approver.shared.isApproved(key) { return nil }
        let reasonText = reason.count > 180 ? String(reason.prefix(177)) + "…" : reason
        if let why = Approver.shared.authenticate(card, reason: reasonText) { return why }
        if let key { Approver.shared.remember(key) }
        return nil
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
