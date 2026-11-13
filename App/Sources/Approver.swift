import CryptoKit
import Foundation
import AppKit
import LocalAuthentication

/// Human-in-the-loop gate. The first use of a (project, command, secret set) asks for Touch ID
/// (or the login password); the approval is remembered for `ttl`. `prod` secrets ask every time.
final class Approver {
    static let shared = Approver()

    var ttl: TimeInterval = TimeInterval(UserDefaults.standard.object(forKey: "approvalHours") as? Int ?? 8) * 3600
    private var approvals: [String: Date] = [:]
    private let lock = NSLock()

    func key(cwd: String, argv: [String], names: [String]) -> String {
        let raw = ([cwd] + argv + ["|"] + names.sorted()).joined(separator: "\u{0}")
        return SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    func isApproved(_ key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let until = approvals[key] else { return false }
        if until > Date() { return true }
        approvals[key] = nil
        return false
    }

    func remember(_ key: String) {
        guard ttl > 0 else { return }
        lock.lock()
        approvals[key] = Date().addingTimeInterval(ttl)
        lock.unlock()
    }

    func revokeAll() {
        lock.lock()
        approvals.removeAll()
        lock.unlock()
    }

    var activeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return approvals.values.filter { $0 > Date() }.count
    }

    static let answerTimeout: TimeInterval = 120

    /// Blocks the calling (socket) thread: shows the request card, then Touch ID / password.
    /// Returns nil when granted, otherwise why not.
    func authenticate(_ request: ApprovalPanel.Request, reason: String) -> String? {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Deny"
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return "authentication unavailable: \(error?.localizedDescription ?? "unknown")"
        }
        let done = DispatchSemaphore(value: 0)
        var failure: String? = "timed out waiting for approval"
        DispatchQueue.main.async {
            ApprovalPanel.show(request) { approved in
                guard approved else {
                    failure = "denied by user"
                    done.signal()
                    return
                }
                // The click made the app active, so the system prompt is not cancelled.
                NSApp.activate()
                ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
                    failure = ok ? nil : (err as NSError?).map { "\($0.localizedDescription) (\($0.code))" } ?? "denied"
                    done.signal()
                }
            }
        }
        if done.wait(timeout: .now() + Self.answerTimeout) == .timedOut {
            ctx.invalidate()
            DispatchQueue.main.async { ApprovalPanel.dismiss() }
            return "timed out waiting for approval"
        }
        return failure
    }
}
