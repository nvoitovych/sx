import CryptoKit
import Foundation
import AppKit
import LocalAuthentication

/// Human-in-the-loop gate. The first use of a (project, command, secret set) asks for Touch ID
/// (or the login password); the approval is remembered for `ttl`. `prod` secrets ask every time.
final class Approver {
    static let shared = Approver()

    var ttl: TimeInterval = TimeInterval(UserDefaults.standard.object(forKey: "approvalHours") as? Int ?? 8) * 3600
    var rememberHours: Int { Int(ttl / 3600) }

    /// What a remembered approval covers, for the UI.
    struct Grant: Identifiable {
        let id: String
        let who: String
        let command: String
        let names: [String]
        let until: Date
    }

    private var grants: [String: Grant] = [:]
    private let lock = NSLock()

    func key(cwd: String, argv: [String], names: [String]) -> String {
        let raw = ([cwd] + argv + ["|"] + names.sorted()).joined(separator: "\u{0}")
        return SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    func isApproved(_ key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let g = grants[key] else { return false }
        if g.until > Date() { return true }
        grants[key] = nil
        return false
    }

    func remember(_ key: String, card: ApprovalPanel.Request) {
        guard ttl > 0 else { return }
        lock.lock()
        grants[key] = Grant(id: key, who: card.who, command: card.command ?? "", names: card.secrets,
                            until: Date().addingTimeInterval(ttl))
        lock.unlock()
        notify()
    }

    func revoke(_ key: String) {
        lock.lock()
        grants[key] = nil
        lock.unlock()
        notify()
    }

    func revokeAll() {
        lock.lock()
        grants.removeAll()
        lock.unlock()
        notify()
    }

    var active: [Grant] {
        lock.lock()
        defer { lock.unlock() }
        return grants.values.filter { $0.until > Date() }.sorted { $0.until > $1.until }
    }

    var activeCount: Int { active.count }

    static let changed = Notification.Name("sx.approvals.changed")

    private func notify() {
        DispatchQueue.main.async { NotificationCenter.default.post(name: Self.changed, object: nil) }
    }

    static let answerTimeout: TimeInterval = 120

    /// Blocks the calling (socket) thread: shows the request card, then Touch ID / password.
    /// Returns nil when granted, otherwise why not.
    func authenticate(_ request: ApprovalPanel.Request, reason: String) -> String? {
        authorize(request, reason: reason, offerRemember: false).error
    }

    /// Like `authenticate`, and reports whether the user chose a timed ("remember") approval.
    func authorize(_ request: ApprovalPanel.Request, reason: String, offerRemember: Bool,
                   isCancelled: @escaping () -> Bool = { false }) -> (error: String?, remember: Bool) {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Deny"
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return ("authentication unavailable: \(error?.localizedDescription ?? "unknown")", false)
        }
        /// Written on the main thread, read after the semaphore; a class so late answers never touch freed memory.
        final class Outcome { var failure: String? = "timed out waiting for approval"; var remember = false }
        let outcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            var card = request
            card.expires = Date().addingTimeInterval(Self.answerTimeout)
            card.rememberHours = offerRemember ? self.rememberHours : 0
            ApprovalPanel.show(card) { decision in
                outcome.remember = decision == .remember
                guard decision != .deny else {
                    outcome.failure = "denied by user"
                    done.signal()
                    return
                }
                // The click made the app active, so the system prompt is not cancelled.
                NSApp.activate()
                ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
                    outcome.failure = ok ? nil : (err as NSError?).map { "\($0.localizedDescription) (\($0.code))" } ?? "denied"
                    done.signal()
                }
            }
        }
        // Wait in short slices so a request whose client has gone away does not hold the card (and the queue).
        let deadline = Date().addingTimeInterval(Self.answerTimeout)
        while done.wait(timeout: .now() + 0.5) == .timedOut {
            let cancelled = isCancelled()
            if cancelled || Date() >= deadline {
                ctx.invalidate()
                DispatchQueue.main.async { ApprovalPanel.dismiss() }
                return (cancelled ? "the requesting program exited" : "timed out waiting for approval", false)
            }
        }
        return (outcome.failure, outcome.remember)
    }
}
