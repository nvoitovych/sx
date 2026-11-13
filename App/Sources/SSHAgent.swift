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
        while let message = readMessage(fd) {
            let reply = handle(message, peer: pid, fd: fd)
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

    private func handle(_ message: Data, peer: pid_t, fd: Int32) -> Data {
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
            let card = ApprovalPanel.Request(title: "wants to sign in with an SSH key", who: who, isAgent: agent != nil,
                                             command: ancestry.joined(separator: " ← "),
                                             project: nil, secrets: [k.name], alwaysAsk: prod)
            let key = prod ? nil : Approver.shared.key(cwd: "ssh", argv: [agent ?? "human"], names: [k.name])
            if let why = Broker.shared.approve(card, reason: "\(who) wants to sign with \(k.name)", key: key, clientFD: fd) {
                AuditLog.shared.record(.init(time: Date(), op: "ssh-sign", client: ancestry.first ?? "?", agent: agent,
                                             command: ancestry.joined(separator: " ← "), names: [k.name], outcome: "denied: \(why)"))
                return failure
            }
            guard let sig = try? k.key.sign(Data(payload), flags: flags) else { return failure }
            AuditLog.shared.record(.init(time: Date(), op: "ssh-sign", client: ancestry.first ?? "?", agent: agent,
                                         command: ancestry.joined(separator: " ← "), names: [k.name], outcome: "signed"))
            var w = SSHWriter()
            w.byte(SSHAgentMessage.signResponse)
            w.string(Array(sig))
            return w.data

        default:
            return failure
        }
    }
}
