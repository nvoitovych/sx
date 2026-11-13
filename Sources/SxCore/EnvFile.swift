import Foundation

/// Minimal dotenv reader/writer. `.env.sx` files hold only `sx://` references and are safe to commit.
public enum EnvFile {
    public struct Entry: Equatable {
        public var key: String
        public var value: String

        public init(key: String, value: String) {
            self.key = key
            self.value = value
        }

        public var reference: String? {
            value.hasPrefix(SX.refScheme) ? String(value.dropFirst(SX.refScheme.count)) : nil
        }
    }

    public static func parse(_ text: String) -> [Entry] {
        var out: [Entry] = []
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            guard isValidKey(key) else { continue }
            var value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, let first = value.first, first == "\"" || first == "'", value.last == first {
                value = String(value.dropFirst().dropLast())
                if first == "\"" {
                    value = unescape(value)
                }
            } else if let hash = value.range(of: " #") {
                value = value[..<hash.lowerBound].trimmingCharacters(in: .whitespaces)
            }
            out.append(Entry(key: key, value: value))
        }
        return out
    }

    public static func render(_ entries: [Entry], header: String? = nil) -> String {
        var lines: [String] = []
        if let header { lines.append("# \(header)") }
        for e in entries { lines.append("\(e.key)=\(e.value)") }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Double-quoted dotenv escapes: \\n, \\", \\\\ (anything else is kept as written).
    static func unescape(_ s: String) -> String {
        var out = ""
        var it = s.makeIterator()
        while let c = it.next() {
            guard c == "\\", let n = it.next() else {
                out.append(c)
                continue
            }
            switch n {
            case "n": out.append("\n")
            case "\"": out.append("\"")
            case "\\": out.append("\\")
            default: out.append(c); out.append(n)
            }
        }
        return out
    }

    /// Dotenv with every value double-quoted and escaped, so newlines and quotes survive a round trip.
    public static func renderQuoted(_ pairs: [(String, String)]) -> String {
        pairs.map { key, value in
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
            return "\(key)=\"\(escaped)\""
        }.joined(separator: "\n") + "\n"
    }

    public static func isValidKey(_ key: String) -> Bool {
        guard let first = key.unicodeScalars.first, first == "_" || CharacterSet.letters.contains(first) else { return false }
        return key.unicodeScalars.allSatisfy { $0 == "_" || CharacterSet.alphanumerics.contains($0) } && key.allSatisfy(\.isASCII)
    }
}

public enum SecretName {
    /// Names look like `project/KEY` or `ssh/id_ed25519`: ASCII letters, digits, `._-/`.
    public static func isValid(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 200, !name.hasPrefix("/"), !name.hasSuffix("/"), !name.contains("//") else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")
        return name.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}
