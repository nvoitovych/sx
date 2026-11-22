import Foundation
import Security
import SxCore

enum Client {
    /// `verifyBroker`: before sending, check that the other end of the socket is Sx.app signed by our
    /// team (a process that took over the socket path must not get what we send, e.g. a password).
    static func send(_ request: BrokerRequest, verifyBroker: Bool = false) throws -> BrokerResponse {
        let fd = try connectLaunchingApp()
        defer { close(fd) }
        if verifyBroker, let problem = brokerProblem(fd) {
            throw CLIError("refused: the process behind the sx socket is not Sx.app (\(problem)); nothing was sent", code: 126)
        }
        try UnixSocket.writeAll(fd, Wire.encode(request))
        let line = try UnixSocket.readLine(fd)
        guard !line.isEmpty else { throw CLIError("broker closed the connection (is this sx binary signed by team \(SX.teamID)?)") }
        return try Wire.decode(BrokerResponse.self, from: line)
    }

    static func call(_ request: BrokerRequest, verifyBroker: Bool = false) throws -> BrokerResponse {
        let resp = try send(request, verifyBroker: verifyBroker)
        guard resp.ok else { throw CLIError(resp.error ?? "broker error") }
        return resp
    }

    /// Nil when the listening process satisfies `SX.appRequirement`, otherwise why not.
    static func brokerProblem(_ fd: Int32) -> String? {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) == 0 else { return "no peer token" }
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: Data(bytes: &token, count: Int(len))] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return "cannot identify it" }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(SX.appRequirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return "bad requirement" }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess ? nil : "signature is not \(SX.appBundleID) by team \(SX.teamID)"
    }

    /// Connects to Sx.app's socket, starting the app in the background if it is not running.
    static func connectLaunchingApp() throws -> Int32 {
        if let fd = try? UnixSocket.connect(SX.socketPath) { return fd }
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-g", "-b", SX.appBundleID, "--args", "--background"]
        open.standardOutput = FileHandle.nullDevice
        open.standardError = FileHandle.nullDevice
        try? open.run()
        open.waitUntilExit()
        let deadline = Date().addingTimeInterval(10)
        var lastError: Error = CLIError("Sx.app is not running")
        while Date() < deadline {
            do { return try UnixSocket.connect(SX.socketPath) } catch { lastError = error }
            usleep(150_000)
        }
        throw CLIError("cannot reach Sx.app (\(lastError)); install it to /Applications and open it once")
    }
}

struct CLIError: Error, CustomStringConvertible {
    let description: String
    let code: Int32

    init(_ description: String, code: Int32 = 1) {
        self.description = description
        self.code = code
    }
}
