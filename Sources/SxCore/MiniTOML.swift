import Foundation

/// The TOML subset sx config files use: `[section.sub]`, bare or quoted keys,
/// strings, booleans, integers and single-line string arrays. No dependencies on purpose.
public enum TOMLValue: Equatable {
    case string(String)
    case bool(Bool)
    case int(Int)
    case array([String])

    public var string: String? { if case let .string(s) = self { return s } else { return nil } }
    public var bool: Bool? { if case let .bool(b) = self { return b } else { return nil } }
    public var array: [String]? { if case let .array(a) = self { return a } else { return nil } }
}

public enum MiniTOML {
    public struct ParseError: Error, CustomStringConvertible {
        public let line: Int
        public let message: String
        public var description: String { "line \(line): \(message)" }
    }

    /// Section name ("" for top level) → key → value, in file order of sections.
    public static func parse(_ text: String) throws -> [(section: String, values: [String: TOMLValue])] {
        var out: [(section: String, values: [String: TOMLValue])] = [("", [:])]
        for (i, raw) in text.components(separatedBy: .newlines).enumerated() {
            let line = stripComment(raw).trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                guard line.hasSuffix("]"), !line.hasPrefix("[[") else { throw ParseError(line: i + 1, message: "bad section header") }
                let name = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                out.append((name, [:]))
                continue
            }
            guard let eq = indexOfEquals(line) else { throw ParseError(line: i + 1, message: "expected key = value") }
            let key = unquote(line[..<eq].trimmingCharacters(in: .whitespaces))
            let rawValue = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            guard let value = parseValue(rawValue) else { throw ParseError(line: i + 1, message: "unsupported value for \(key)") }
            out[out.count - 1].values[key] = value
        }
        return out
    }

    static func parseValue(_ s: String) -> TOMLValue? {
        if s == "true" { return .bool(true) }
        if s == "false" { return .bool(false) }
        if let n = Int(s) { return .int(n) }
        if let str = quoted(s) { return .string(str) }
        if s.hasPrefix("["), s.hasSuffix("]") {
            let inner = s.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
            if inner.isEmpty { return .array([]) }
            var items: [String] = []
            for part in splitTopLevel(String(inner)) {
                let p = part.trimmingCharacters(in: .whitespaces)
                if p.isEmpty { continue }
                guard let str = quoted(p) else { return nil }
                items.append(str)
            }
            return .array(items)
        }
        return nil
    }

    static func quoted(_ s: String) -> String? {
        guard s.count >= 2, let q = s.first, q == "\"" || q == "'", s.last == q else { return nil }
        let body = String(s.dropFirst().dropLast())
        return q == "\"" ? body.replacingOccurrences(of: "\\\"", with: "\"").replacingOccurrences(of: "\\\\", with: "\\") : body
    }

    static func unquote(_ s: String) -> String { quoted(s) ?? s }

    /// Splits on commas that are outside quotes.
    static func splitTopLevel(_ s: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var quote: Character?
        for c in s {
            if let q = quote {
                if c == q { quote = nil }
                current.append(c)
            } else if c == "\"" || c == "'" {
                quote = c
                current.append(c)
            } else if c == "," {
                parts.append(current)
                current = ""
            } else {
                current.append(c)
            }
        }
        parts.append(current)
        return parts
    }

    static func stripComment(_ s: String) -> String {
        var quote: Character?
        for (i, c) in s.enumerated() {
            if let q = quote {
                if c == q { quote = nil }
            } else if c == "\"" || c == "'" {
                quote = c
            } else if c == "#" {
                return String(s.prefix(i))
            }
        }
        return s
    }

    static func indexOfEquals(_ s: String) -> String.Index? {
        var quote: Character?
        for i in s.indices {
            let c = s[i]
            if let q = quote {
                if c == q { quote = nil }
            } else if c == "\"" || c == "'" {
                quote = c
            } else if c == "=" {
                return i
            }
        }
        return nil
    }
}
