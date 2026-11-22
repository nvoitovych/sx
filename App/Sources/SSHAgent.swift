import Foundation
import SxCore

/// ssh-agent protocol on a socket in the app group container. Private keys stay in the keychain
/// and in this process; clients only get public keys and signatures. Each new (key, caller) asks first.
final class SSHAgent {
    static let shared = SSHAgent()

    private var listenFD: Int32 = -1
    private let workers = DispatchQueue(label: "dev.nvlab.sx.ssh-agent", attributes: .concurrent)
    private(set) var startError: String?

    func start() {
        do {
            listenFD = try UnixSocket.listen(SX.sshAgentSocketPath)
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

    private struct LoadedKey {
        let name: String
        let key: SSHPrivateKey
    }

    private func keys() -> [LoadedKey] {
        let items = (try? KeychainStore.list()) ?? []
        return items.filter { $0.tags.contains(SX.sshTag) }.compactMap { info in
            guard let data = try? KeychainStore.get(info.name), let key = try? SSHPrivateKey(openSSH: data) else { return nil }
            return LoadedKey(name: info.name, key: key)
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
        var bindings: [SSHHostBinding] = []
        while let message = readMessage(fd) {
            let reply = handle(message, peer: pid, fd: fd, bindings: &bindings)
            var w = SSHWriter()
            w.uint32(UInt32(reply.count))
            guard (try? UnixSocket.writeAll(fd, w.data + reply)) != nil else { return }
        }
    }

    private func readMessage(_ fd: Int32) -> Data? {
        guard let header = readExactly(fd, 4) else { return nil }
        let n = header.reduce(0) { $0 << 8 | Int($1) }
        guard n > 0, n < 256 * 1024 else { return nil }
        return readExactly(fd, n)
    }

    private func readExactly(_ fd: Int32, _ n: Int) -> Data? {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: min(n, 65536))
        while out.count < n {
            let r = read(fd, &buf, min(buf.count, n - out.count))
            if r < 0 && errno == EINTR { continue }
            if r <= 0 { return nil }
            out.append(buf, count: r)
        }
        return out
    }

    private func handle(_ message: Data, peer: pid_t, fd: Int32, bindings: inout [SSHHostBinding]) -> Data {
        let failure = Data([SSHAgentMessage.failure])
        var r = SSHReader(message)
        guard let type = try? r.byte() else { return failure }
        switch type {
        case SSHAgentMessage.requestIdentities:
            let loaded = keys()
            var w = SSHWriter()
            w.byte(SSHAgentMessage.identitiesAnswer)
            w.uint32(UInt32(loaded.count))
            for k in loaded {
                w.string(Array(k.key.publicBlob))
                w.string(k.name)
            }
            return w.data

        case SSHAgentMessage.signRequest:
            guard let blob = try? r.string(), let payload = try? r.string() else { return failure }
            let flags = (try? r.uint32()) ?? 0
            guard let k = keys().first(where: { Array($0.key.publicBlob) == blob }) else { return failure }

            let ancestry = AgentDetect.ancestry(from: peer).prefix(5).map { ($0 as NSString).lastPathComponent }
            let agent = AgentDetect.detect(pid: peer)
            let who = agent ?? "Terminal"
            let prod = KeychainStore.tags(k.name).contains("prod")

            // What is signed, and for which server. A login bound (session-bind) to a server's host key is
            // tied to that key; the alias on the ssh command line is only what the caller says (shown, never
            // trusted). `ssh-keygen -Y sign` data is tied to its namespace (e.g. "git"). Anything else —
            // a login without a verified server, a forwarded agent, unknown data — can only be approved once,
            // live: its class is unique, so no grant or retry can match another request.
            let data = Data(payload)
            let label = SSHDestination.host(argv: AgentDetect.arguments(of: peer) ?? []) // escaped where shown
            let bound = SSHUserAuthRequest.boundHost(payload: data, bindings: bindings, key: blob)
            let hostKey = bound?.hostKeyFingerprint
            let isLogin = SSHUserAuthRequest(payload: data) != nil
            let namespace = isLogin ? nil : SSHSignedData.namespace(data)
            let forwarded = bindings.contains(where: \.isForwarding)
            let what: String
            let scope: String
            if let hostKey {
                what = "sign in with \(k.name) to the server with host key \(hostKey) (caller calls it \(label ?? "?"))"
                scope = "login:hk:" + hostKey
            } else if let namespace {
                what = "sign data in namespace \"\(namespace)\" with \(k.name) (\(ancestry.first ?? "?"))"
                scope = "data:ns:" + namespace
            } else if isLogin {
                what = "sign in with \(k.name) to \(label ?? "a server") — server NOT verified\(forwarded ? " (forwarded agent)" : "")"
                scope = "once:" + UUID().uuidString
            } else {
                what = "sign unknown data with \(k.name) (\(ancestry.first ?? "?"))"
                scope = "once:" + UUID().uuidString
            }
            let target = hostKey.map { " → host key \($0) (\(label ?? "?"))" } ?? namespace.map { " → data \"\($0)\"" } ?? (isLogin ? " → \(label ?? "?") (not verified)" : "")
            let chainText = ancestry.joined(separator: " ← ") + target

            let card = ApprovalPanel.Request(title: "wants to sign in with an SSH key", who: who, isAgent: agent != nil,
                                             command: ancestry.joined(separator: " ← "),
                                             project: nil, secrets: [k.name], alwaysAsk: prod, isProduction: prod,
                                             note: what)
            let actor = agent ?? "human"
            let wideKey = Approver.shared.key(cwd: "ssh", argv: [actor], names: [k.name])
            let classKey = Approver.shared.key(cwd: "ssh", argv: [actor, "class=" + scope], names: [k.name])
            let context = ApprovalContext(kind: "ssh-sign", what: what, terminal: true, classKey: classKey, wideKey: wideKey,
                                          chain: Array(ancestry), host: label, hostKey: hostKey,
                                          canGrant: hostKey != nil || namespace != nil, retryable: hostKey != nil || namespace != nil)
            if let why = Broker.shared.approve(card, reason: "\(who) wants to sign with \(k.name)\(target)", key: prod ? nil : wideKey,
                                               clientFD: fd, context: context) {
                AuditLog.shared.record(.init(time: Date(), op: "ssh-sign", client: ancestry.first ?? "?", agent: agent,
                                             command: chainText, names: [k.name], outcome: "denied: \(why)"))
                return failure
            }
            guard let sig = try? k.key.sign(Data(payload), flags: flags) else { return failure }
            AuditLog.shared.record(.init(time: Date(), op: "ssh-sign", client: ancestry.first ?? "?", agent: agent,
                                         command: chainText, names: [k.name], outcome: "signed"))
            var w = SSHWriter()
            w.byte(SSHAgentMessage.signResponse)
            w.string(Array(sig))
            return w.data

        case SSHAgentMessage.extension:
            // Only session-bind, and only with a valid host signature. As in OpenSSH's agent: forwarding hops
            // first, then at most one binding for authentication; nothing after it. With any forwarding hop,
            // sign requests get no server-limited approval (see `boundHost`).
            guard let b = SSHHostBinding(extensionBody: Data(message.dropFirst())), b.isValid else { return failure }
            if let last = bindings.last, !last.isForwarding { return failure }
            guard bindings.count < 16 else { return failure }
            bindings.append(b)
            return Data([SSHAgentMessage.success])

        default:
            return failure
        }
    }
}
