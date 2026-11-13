import Foundation

/// Append-only access log: who, what command, which secret NAMES, outcome. Never values.
final class AuditLog: ObservableObject {
    static let shared = AuditLog()

    struct Entry: Identifiable, Codable {
        var id = UUID()
        var time: Date
        var op: String
        var client: String
        var agent: String?
        var command: String?
        var cwd: String?
        var names: [String]
        var outcome: String
    }

    @Published private(set) var recent: [Entry] = []
    /// Full log for the Activity view, newest first (last 1000 entries).
    @Published private(set) var history: [Entry] = []
    private let queue = DispatchQueue(label: "dev.nvlab.sx.audit")
    private let url: URL

    private init() {
        let logs = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0].appendingPathComponent("Logs")
        try? FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        url = logs.appendingPathComponent("sx-audit.jsonl")
    }

    var path: String { url.path }

    /// Last successful use per secret name, from the loaded history.
    var lastUsed: [String: Date] {
        var out: [String: Date] = [:]
        for e in history where e.outcome.hasPrefix("released") || e.outcome == "signed" || e.outcome.hasPrefix("copied") {
            for n in e.names where (out[n] ?? .distantPast) < e.time { out[n] = e.time }
        }
        return out
    }

    func setDemo(_ entries: [Entry]) {
        recent = entries
        history = entries
    }

    func loadHistory() {
        if Snapshot.isActive { return }
        queue.async {
            let dec = JSONDecoder()
            dec.dateDecodingStrategy = .iso8601
            let lines = ((try? String(contentsOf: self.url, encoding: .utf8)) ?? "").split(separator: "\n").suffix(1000)
            let entries = lines.compactMap { try? dec.decode(Entry.self, from: Data($0.utf8)) }.reversed()
            DispatchQueue.main.async { self.history = Array(entries) }
        }
    }

    func record(_ entry: Entry) {
        queue.async {
            let enc = JSONEncoder()
            enc.dateEncodingStrategy = .iso8601
            if var line = try? enc.encode(entry) {
                line.append(0x0A)
                if let h = try? FileHandle(forWritingTo: self.url) {
                    h.seekToEndOfFile()
                    h.write(line)
                    try? h.close()
                } else {
                    try? line.write(to: self.url)
                }
            }
            DispatchQueue.main.async {
                self.recent.insert(entry, at: 0)
                self.history.insert(entry, at: 0)
                if self.recent.count > 50 { self.recent.removeLast(self.recent.count - 50) }
            }
        }
    }
}
