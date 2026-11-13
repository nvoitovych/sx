import Foundation
import SxCore

enum Client {
    static func send(_ request: BrokerRequest) throws -> BrokerResponse {
        let fd = try connectLaunchingApp()
        defer { close(fd) }
        try UnixSocket.writeAll(fd, Wire.encode(request))
        let line = try UnixSocket.readLine(fd)
        guard !line.isEmpty else { throw CLIError("broker closed the connection (is this sx binary signed by team \(SX.teamID)?)") }
        return try Wire.decode(BrokerResponse.self, from: line)
    }

    static func call(_ request: BrokerRequest) throws -> BrokerResponse {
        let resp = try send(request)
        guard resp.ok else { throw CLIError(resp.error ?? "broker error") }
        return resp
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
