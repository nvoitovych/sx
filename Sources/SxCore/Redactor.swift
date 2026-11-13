import Foundation

/// Streaming redaction of secret values (raw, base64, hex) in child process output.
/// Holds back a tail of `maxPattern - 1` bytes so a secret split across reads is still caught.
public final class Redactor {
    private struct Pattern {
        let bytes: [UInt8]
        let replacement: [UInt8]
    }

    private let patterns: [Pattern]
    private let holdback: Int
    private var pending: [UInt8] = []

    /// Values shorter than this are not redacted: they would mangle ordinary output.
    public static let minLength = 4

    public init(secrets: [String: Data]) {
        var pats: [Pattern] = []
        for (name, value) in secrets where value.count >= Self.minLength {
            let tag = Array("<sx:\(name)>".utf8)
            var variants: [[UInt8]] = [Array(value)]
            let trimmed = Self.trimTrailingNewlines(value)
            if trimmed.count >= Self.minLength, trimmed.count != value.count { variants.append(Array(trimmed)) }
            variants.append(Array(trimmed.base64EncodedString().utf8))
            variants.append(Array(trimmed.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "=")).utf8))
            variants.append(Array(trimmed.map { String(format: "%02x", $0) }.joined().utf8))
            for v in Set(variants) where v.count >= Self.minLength {
                pats.append(Pattern(bytes: v, replacement: tag))
            }
        }
        patterns = pats.sorted { $0.bytes.count > $1.bytes.count }
        holdback = max(0, (patterns.first?.bytes.count ?? 1) - 1)
    }

    public var isEmpty: Bool { patterns.isEmpty }

    public func feed(_ chunk: Data) -> Data {
        pending.append(contentsOf: chunk)
        let replaced = redact(pending)
        guard replaced.count > holdback else {
            pending = replaced
            return Data()
        }
        let cut = replaced.count - holdback
        pending = Array(replaced[cut...])
        return Data(replaced[..<cut])
    }

    public func finish() -> Data {
        let out = redact(pending)
        pending = []
        return Data(out)
    }

    public func redact(_ data: Data) -> Data { Data(redact(Array(data))) }

    private func redact(_ input: [UInt8]) -> [UInt8] {
        guard !patterns.isEmpty, !input.isEmpty else { return input }
        var out: [UInt8] = []
        out.reserveCapacity(input.count)
        var i = 0
        outer: while i < input.count {
            for p in patterns where p.bytes[0] == input[i] && i + p.bytes.count <= input.count {
                if input[i..<(i + p.bytes.count)].elementsEqual(p.bytes) {
                    out.append(contentsOf: p.replacement)
                    i += p.bytes.count
                    continue outer
                }
            }
            out.append(input[i])
            i += 1
        }
        return out
    }

    private static func trimTrailingNewlines(_ d: Data) -> Data {
        var d = d
        while let last = d.last, last == 0x0A || last == 0x0D { d.removeLast() }
        return d
    }
}
