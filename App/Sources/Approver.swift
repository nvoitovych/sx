import CryptoKit
import Foundation
import AppKit
import LocalAuthentication
import SxCore

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

    private var table = GrantTable()
    private let lock = NSLock()

    func key(cwd: String, argv: [String], names: [String]) -> String {
        let raw = ([cwd] + argv + ["|"] + names.sorted()).joined(separator: "\u{0}")
        return SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// True when a remembered approval covers `key`. A single-use approval is used up.
    func isApproved(_ key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return table.take(key)
    }

    /// "Allow for N h" on the card (Touch ID).
    func remember(_ key: String, card: ApprovalPanel.Request) {
        guard ttl > 0 else { return }
        remember(key, info: GrantInfo(who: card.who, scope: card.command ?? "", names: card.secrets,
                                      until: Date().addingTimeInterval(ttl), via: "card"))
    }

    /// Approvals from `sx approve`: timed (`uses == nil`) or single-use.
    func remember(_ key: String, info: GrantInfo, uses: Int? = nil) {
        lock.lock()
        table.add(key: key, info: info, uses: uses)
        lock.unlock()
        notify()
    }

    /// `id` is the full key (UI) or a short id / prefix of at least 4 characters (`sx revoke`).
    @discardableResult
    func revoke(_ id: String) -> Int {
        lock.lock()
        let n = table.revoke(prefix: id)
        lock.unlock()
        notify()
        return n
    }

    func revokeAll() {
        lock.lock()
        table.removeAll()
        lock.unlock()
        notify()
    }

    var grantInfos: [GrantInfo] {
        lock.lock()
        defer { lock.unlock() }
        return table.active()
    }

    var active: [Grant] {
        grantInfos.map { Grant(id: $0.id, who: $0.who, command: $0.scope, names: $0.names, until: $0.until) }
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
    /// `external` reports an answer given elsewhere (`sx approve` in a terminal); the card then closes.
    func authorize(_ request: ApprovalPanel.Request, reason: String, offerRemember: Bool,
                   isCancelled: @escaping () -> Bool = { false },
                   external: @escaping () -> ApprovalPanel.Outcome? = { nil }) -> (error: String?, remember: Bool) {
        /// Written on the main thread, read after the semaphore; a class so late answers never touch freed memory.
        final class Box { var outcome: ApprovalPanel.Outcome? }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        let cardID = UUID()
        DispatchQueue.main.async {
            var card = request
            card.expires = Date().addingTimeInterval(Self.answerTimeout)
            card.rememberHours = offerRemember ? self.rememberHours : 0
            ApprovalPanel.show(card, reason: reason, id: cardID) { outcome in
                box.outcome = outcome
                done.signal()
            }
        }
        // Wait in short slices so a request whose client has gone away does not hold the card (and the queue).
        let deadline = Date().addingTimeInterval(Self.answerTimeout)
        while done.wait(timeout: .now() + 0.5) == .timedOut {
            if let answer = external() {
                DispatchQueue.main.async { ApprovalPanel.dismiss(id: cardID) }
                return Self.result(answer)
            }
            let cancelled = isCancelled()
            if cancelled || Date() >= deadline {
                DispatchQueue.main.async { ApprovalPanel.dismiss(id: cardID) }
                return (cancelled ? "the requesting program exited" : "timed out waiting for approval", false)
            }
        }
        return Self.result(box.outcome)
    }

    private static func result(_ outcome: ApprovalPanel.Outcome?) -> (error: String?, remember: Bool) {
        switch outcome {
        case let .approved(remember)?: return (nil, remember)
        case .denied?: return ("denied by user", false)
        case let .failed(why)?: return (why, false)
        case nil: return ("no answer", false)
        }
    }
}
