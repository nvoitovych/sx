import CryptoKit
import Foundation
import Security

/// SSH wire encoding (RFC 4251): uint32, string, mpint.
public struct SSHReader {
    private let data: [UInt8]
    private(set) var offset = 0

    public init(_ data: Data) { self.data = Array(data) }

    public var remaining: Int { data.count - offset }

    public mutating func byte() throws -> UInt8 {
        guard offset < data.count else { throw SSHError.truncated }
        defer { offset += 1 }
        return data[offset]
    }

    public mutating func uint32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHError.truncated }
        defer { offset += 4 }
        return data[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }

    public mutating func bytes(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw SSHError.truncated }
        defer { offset += n }
        return Array(data[offset..<offset + n])
    }

    public mutating func string() throws -> [UInt8] { try bytes(Int(uint32())) }

    public mutating func text() throws -> String { String(decoding: try string(), as: UTF8.self) }
}

public struct SSHWriter {
    public private(set) var data = Data()

    public init() {}

    public mutating func byte(_ b: UInt8) { data.append(b) }

    public mutating func uint32(_ v: UInt32) {
        data.append(contentsOf: [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)])
    }

    public mutating func string(_ b: [UInt8]) {
        uint32(UInt32(b.count))
        data.append(contentsOf: b)
    }

    public mutating func string(_ s: String) { string(Array(s.utf8)) }
}

public enum SSHError: Error, CustomStringConvertible {
    case truncated, notOpenSSH, encrypted, unsupported(String), checkMismatch, signingFailed(String)

    public var description: String {
        switch self {
        case .truncated: return "malformed SSH data"
        case .notOpenSSH: return "not an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----)"
        case .encrypted: return "key is passphrase-protected; store an unencrypted copy (`ssh-keygen -p -N '' -f COPY`) — sx keeps it in the keychain behind Touch ID"
        case let .unsupported(t): return "unsupported key type \(t) (ed25519 and rsa are supported)"
        case .checkMismatch: return "corrupt private key (check bytes differ)"
        case let .signingFailed(m): return "signing failed: \(m)"
        }
    }
}

/// An unencrypted OpenSSH private key that can sign agent requests.
public struct SSHPrivateKey {
    public enum Kind {
        case ed25519(seed: [UInt8])
        case rsa(SecKey)
    }

    public let type: String
    public let publicBlob: Data
    public let comment: String
    let kind: Kind

    public static let agentRSASHA256: UInt32 = 2
    public static let agentRSASHA512: UInt32 = 4

    /// `SHA256:…` like `ssh-keygen -l`.
    public var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: publicBlob)).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    public var authorizedKey: String { "\(type) \(publicBlob.base64EncodedString())\(comment.isEmpty ? "" : " \(comment)")" }

    public init(openSSH pem: Data) throws {
        guard let text = String(data: pem, encoding: .utf8), text.contains("BEGIN OPENSSH PRIVATE KEY") else { throw SSHError.notOpenSSH }
        let body = text.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let raw = Data(base64Encoded: body) else { throw SSHError.notOpenSSH }
        let magic = Array("openssh-key-v1\0".utf8)
        guard raw.count > magic.count, Array(raw.prefix(magic.count)) == magic else { throw SSHError.notOpenSSH }
        var r = SSHReader(raw.dropFirst(magic.count))
        let cipher = try r.text()
        _ = try r.text() // kdf name
        _ = try r.string() // kdf options
        guard cipher == "none" else { throw SSHError.encrypted }
        guard try r.uint32() == 1 else { throw SSHError.unsupported("multi-key file") }
        publicBlob = Data(try r.string())
        var p = SSHReader(Data(try r.string()))
        guard try p.uint32() == p.uint32() else { throw SSHError.checkMismatch }
        type = try p.text()
        switch type {
        case "ssh-ed25519":
            _ = try p.string() // public
            let priv = try p.string()
            guard priv.count == 64 else { throw SSHError.truncated }
            kind = .ed25519(seed: Array(priv.prefix(32)))
        case "ssh-rsa":
            let n = try p.string(), e = try p.string(), d = try p.string()
            let iqmp = try p.string(), pp = try p.string(), q = try p.string()
            kind = .rsa(try Self.rsaKey(n: n, e: e, d: d, p: pp, q: q, iqmp: iqmp))
        default:
            throw SSHError.unsupported(type)
        }
        comment = try p.text()
    }

    /// Returns the SSH signature blob (`string algorithm, string signature`).
    public func sign(_ message: Data, flags: UInt32 = 0) throws -> Data {
        var w = SSHWriter()
        switch kind {
        case let .ed25519(seed):
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            w.string("ssh-ed25519")
            w.string(Array(try key.signature(for: message)))
        case let .rsa(key):
            let (name, alg): (String, SecKeyAlgorithm) =
                flags & Self.agentRSASHA512 != 0 ? ("rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512)
                : flags & Self.agentRSASHA256 != 0 ? ("rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256)
                : ("ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1)
            var error: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(key, alg, message as CFData, &error) as Data? else {
                throw SSHError.signingFailed(error.map { "\($0.takeRetainedValue())" } ?? "unknown")
            }
            w.string(name)
            w.string(Array(sig))
        }
        return w.data
    }

    /// Security.framework wants PKCS#1 DER, which also needs d mod (p-1) and d mod (q-1).
    static func rsaKey(n: [UInt8], e: [UInt8], d: [UInt8], p: [UInt8], q: [UInt8], iqmp: [UInt8]) throws -> SecKey {
        let dp = BigUInt.mod(d, BigUInt.minusOne(p))
        let dq = BigUInt.mod(d, BigUInt.minusOne(q))
        let der = DER.sequence([DER.integer([0]), DER.integer(n), DER.integer(e), DER.integer(d),
                                DER.integer(p), DER.integer(q), DER.integer(dp), DER.integer(dq), DER.integer(iqmp)])
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, &error) else {
            throw SSHError.signingFailed(error.map { "\($0.takeRetainedValue())" } ?? "bad RSA key")
        }
        return key
    }
}

/// SSH agent protocol message numbers (draft-miller-ssh-agent).
public enum SSHAgentMessage {
    public static let failure: UInt8 = 5
    public static let requestIdentities: UInt8 = 11
    public static let identitiesAnswer: UInt8 = 12
    public static let signRequest: UInt8 = 13
    public static let signResponse: UInt8 = 14
}

enum DER {
    static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.insert(UInt8(v & 0xff), at: 0)
            v >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var m = Array(magnitude.drop { $0 == 0 })
        if m.isEmpty { m = [0] }
        if m[0] & 0x80 != 0 { m.insert(0, at: 0) }
        return [0x02] + length(m.count) + m
    }

    static func sequence(_ items: [[UInt8]]) -> [UInt8] {
        let body = items.flatMap { $0 }
        return [0x30] + length(body.count) + body
    }
}

/// Just enough unsigned big-integer arithmetic for RSA CRT parameters. Big-endian byte arrays.
enum BigUInt {
    static func minusOne(_ a: [UInt8]) -> [UInt8] {
        var r = a
        var i = r.count - 1
        while i >= 0 {
            if r[i] > 0 {
                r[i] -= 1
                break
            }
            r[i] = 0xff
            i -= 1
        }
        return r
    }

    /// a mod m by binary long division.
    static func mod(_ a: [UInt8], _ m: [UInt8]) -> [UInt8] {
        let mod = limbs(m)
        var rem = [UInt32](repeating: 0, count: mod.count + 1)
        for byte in a {
            for bit in stride(from: 7, through: 0, by: -1) {
                shiftLeftOne(&rem, carryIn: UInt32(byte >> UInt8(bit) & 1))
                if compare(rem, mod) >= 0 { subtract(&rem, mod) }
            }
        }
        return bytes(rem)
    }

    /// Little-endian 32-bit limbs.
    static func limbs(_ b: [UInt8]) -> [UInt32] {
        var out: [UInt32] = []
        var i = b.count
        while i > 0 {
            let lo = max(0, i - 4)
            out.append(b[lo..<i].reduce(0) { $0 << 8 | UInt32($1) })
            i = lo
        }
        return out.isEmpty ? [0] : out
    }

    static func bytes(_ l: [UInt32]) -> [UInt8] {
        var out: [UInt8] = []
        for limb in l.reversed() {
            out += [UInt8(limb >> 24 & 0xff), UInt8(limb >> 16 & 0xff), UInt8(limb >> 8 & 0xff), UInt8(limb & 0xff)]
        }
        let trimmed = Array(out.drop { $0 == 0 })
        return trimmed.isEmpty ? [0] : trimmed
    }

    static func shiftLeftOne(_ a: inout [UInt32], carryIn: UInt32) {
        var carry = carryIn
        for i in a.indices {
            let next = a[i] >> 31
            a[i] = a[i] << 1 | carry
            carry = next
        }
    }

    static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let n = max(a.count, b.count)
        for i in stride(from: n - 1, through: 0, by: -1) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x > y ? 1 : -1 }
        }
        return 0
    }

    static func subtract(_ a: inout [UInt32], _ b: [UInt32]) {
        var borrow: Int64 = 0
        for i in a.indices {
            var v = Int64(a[i]) - (i < b.count ? Int64(b[i]) : 0) - borrow
            borrow = v < 0 ? 1 : 0
            if v < 0 { v += 1 << 32 }
            a[i] = UInt32(v)
        }
    }
}
