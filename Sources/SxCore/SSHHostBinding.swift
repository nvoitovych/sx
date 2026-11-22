import CryptoKit
import Foundation
import Security

/// `session-bind@openssh.com` (OpenSSH 8.9+): before using agent keys, `ssh` tells the agent which
/// server it is talking to — the server's host key, the session identifier, and the server's signature
/// over that identifier. A verified binding names the real server, unlike the host alias in `argv`
/// or `~/.ssh/config`, which any process running as the user can edit.
public struct SSHHostBinding: Equatable {
    public static let extensionName = "session-bind@openssh.com"

    public let hostKey: [UInt8]
    public let sessionID: [UInt8]
    public let signature: [UInt8]
    public let isForwarding: Bool

    public init(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8], isForwarding: Bool) {
        self.hostKey = hostKey
        self.sessionID = sessionID
        self.signature = signature
        self.isForwarding = isForwarding
    }

    /// Parses the body of an SSH_AGENTC_EXTENSION message (after the type byte).
    /// Returns nil for any other extension or malformed data.
    public init?(extensionBody: Data) {
        var r = SSHReader(extensionBody)
        guard let name = try? r.text(), name == Self.extensionName,
              let hostKey = try? r.string(), let sessionID = try? r.string(),
              let signature = try? r.string(), let forwarding = try? r.byte(), r.remaining == 0,
              !sessionID.isEmpty, sessionID.count <= 128 else { return nil }
        self.init(hostKey: hostKey, sessionID: sessionID, signature: signature, isForwarding: forwarding != 0)
    }

    /// The host key really signed this session identifier.
    public var isValid: Bool {
        SSHSignatureVerifier.verify(publicKeyBlob: hostKey, signatureBlob: signature, data: Data(sessionID))
    }

    public var hostKeyFingerprint: String { SSHFingerprint.sha256(hostKey) }
}

public enum SSHFingerprint {
    /// `SHA256:…` like `ssh-keygen -l`.
    public static func sha256(_ blob: [UInt8]) -> String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}

/// Verifies SSH signature blobs (`string algorithm, string signature`) against public key blobs.
/// Host keys: ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa (rsa-sha2-256/512 only).
public enum SSHSignatureVerifier {
    public static func verify(publicKeyBlob: [UInt8], signatureBlob: [UInt8], data: Data) -> Bool {
        var k = SSHReader(Data(publicKeyBlob))
        var s = SSHReader(Data(signatureBlob))
        guard let keyType = try? k.text(), let sigType = try? s.text(), let sig = try? s.string(), s.remaining == 0 else { return false }
        switch keyType {
        case "ssh-ed25519":
            guard sigType == "ssh-ed25519", let raw = try? k.string(), k.remaining == 0,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { return false }
            return key.isValidSignature(sig, for: data)

        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            guard sigType == keyType, let curve = try? k.text(), "ecdsa-sha2-" + curve == keyType,
                  let point = try? k.string(), k.remaining == 0 else { return false }
            var rs = SSHReader(Data(sig))
            guard let r = try? rs.string(), let sv = try? rs.string(), rs.remaining == 0 else { return false }
            switch curve {
            case "nistp256":
                guard let key = try? P256.Signing.PublicKey(x963Representation: point),
                      let raw = fixed(r, 32).flatMap({ a in fixed(sv, 32).map { a + $0 } }),
                      let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
                return key.isValidSignature(signature, for: data)
            case "nistp384":
                guard let key = try? P384.Signing.PublicKey(x963Representation: point),
                      let raw = fixed(r, 48).flatMap({ a in fixed(sv, 48).map { a + $0 } }),
                      let signature = try? P384.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
                return key.isValidSignature(signature, for: data)
            default:
                guard let key = try? P521.Signing.PublicKey(x963Representation: point),
                      let raw = fixed(r, 66).flatMap({ a in fixed(sv, 66).map { a + $0 } }),
                      let signature = try? P521.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
                return key.isValidSignature(signature, for: data)
            }

        case "ssh-rsa":
            let alg: SecKeyAlgorithm
            switch sigType {
            case "rsa-sha2-256": alg = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512": alg = .rsaSignatureMessagePKCS1v15SHA512
            default: return false // no SHA-1 ("ssh-rsa") signatures: OpenSSH has not sent them for session-bind
            }
            guard let e = try? k.string(), let n = try? k.string(), k.remaining == 0 else { return false }
            let der = DER.sequence([DER.integer(n), DER.integer(e)])
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
            guard let key = SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, nil) else { return false }
            return SecKeyVerifySignature(key, alg, data as CFData, Data(sig) as CFData, nil)

        default:
            return false
        }
    }

    /// SSH mpint → fixed-width big-endian magnitude (drops the sign byte, left-pads).
    static func fixed(_ mpint: [UInt8], _ width: Int) -> [UInt8]? {
        let m = Array(mpint.drop { $0 == 0 })
        guard m.count <= width else { return nil }
        return [UInt8](repeating: 0, count: width - m.count) + m
    }
}

/// The data a client asks the agent to sign for public-key user authentication (RFC 4252 §7).
public struct SSHUserAuthRequest: Equatable {
    public let sessionID: [UInt8]
    public let user: String
    public let method: String
    /// The user key the request authenticates with (must be the key asked to sign).
    public let publicKey: [UInt8]
    /// Server host key, present for `publickey-hostbound-v00@openssh.com`.
    public let hostKey: [UInt8]?

    public init?(payload: Data) {
        var r = SSHReader(payload)
        guard let sid = try? r.string(), !sid.isEmpty, let type = try? r.byte(), type == 50,
              let user = try? r.text(), let service = try? r.text(), service == "ssh-connection",
              let method = try? r.text() else { return nil }
        guard method == "publickey" || method == "publickey-hostbound-v00@openssh.com",
              let hasSig = try? r.byte(), hasSig != 0, (try? r.text()) != nil, let key = try? r.string() else { return nil }
        var hostKey: [UInt8]?
        if method == "publickey-hostbound-v00@openssh.com" {
            guard let hk = try? r.string() else { return nil }
            hostKey = hk
        }
        guard r.remaining == 0 else { return nil }
        sessionID = sid
        self.user = user
        self.method = method
        publicKey = key
        self.hostKey = hostKey
    }

    /// Which server a sign request is for, given the (verified) bindings `ssh` sent on this agent
    /// connection. Nil unless nothing was forwarded, the payload is a login for the bound session with
    /// the key being asked to sign, and (host-bound auth) names the bound host key — as OpenSSH's agent checks.
    public static func boundHost(payload: Data, bindings: [SSHHostBinding], key: [UInt8]) -> SSHHostBinding? {
        guard let last = bindings.last, !bindings.contains(where: \.isForwarding),
              let auth = SSHUserAuthRequest(payload: payload), auth.sessionID == last.sessionID,
              auth.publicKey == key else { return nil }
        if let hk = auth.hostKey, hk != last.hostKey { return nil }
        return last
    }
}

/// `ssh-keygen -Y sign` data (PROTOCOL.sshsig): what is signed is tied to a namespace, e.g. "git".
public enum SSHSignedData {
    public static func namespace(_ payload: Data) -> String? {
        let magic = Array("SSHSIG".utf8)
        guard payload.count > magic.count, Array(payload.prefix(magic.count)) == magic else { return nil }
        var r = SSHReader(payload.dropFirst(magic.count))
        guard let ns = try? r.text(), !ns.isEmpty, (try? r.string()) != nil, (try? r.text()) != nil,
              (try? r.string()) != nil, r.remaining == 0 else { return nil }
        return ns
    }
}

/// Destination host as typed on the `ssh` command line (an alias; shown to people, never trusted alone).
public enum SSHDestination {
    /// ssh(1) options that take an argument.
    static let valued = Set("BbcDEeFIiJLlmOoPpQRSWw")

    public static func host(argv: [String]) -> String? {
        guard let first = argv.first, (first as NSString).lastPathComponent == "ssh" else { return nil }
        var i = 1
        while i < argv.count {
            let a = argv[i]
            if a == "--" { i += 1; break }
            if a.hasPrefix("-"), a.count > 1 {
                // Option cluster like -4Cv or -p22: a valued letter consumes the rest or the next arg.
                let letters = Array(a.dropFirst())
                for (j, c) in letters.enumerated() where valued.contains(c) {
                    if j == letters.count - 1 { i += 1 }
                    break
                }
                i += 1
                continue
            }
            break
        }
        guard i < argv.count else { return nil }
        var dest = argv[i]
        if dest.hasPrefix("ssh://") {
            dest = String(dest.dropFirst(6))
            if let slash = dest.firstIndex(of: "/") { dest = String(dest[..<slash]) }
            if let at = dest.lastIndex(of: "@") { dest = String(dest[dest.index(after: at)...]) }
            if dest.hasPrefix("["), let end = dest.firstIndex(of: "]") { return String(dest[dest.index(after: dest.startIndex)..<end]) }
            if let colon = dest.lastIndex(of: ":") { dest = String(dest[..<colon]) }
            return dest.isEmpty ? nil : dest
        }
        if let at = dest.lastIndex(of: "@") { dest = String(dest[dest.index(after: at)...]) }
        return dest.isEmpty ? nil : dest
    }
}
