import CryptoKit
import Foundation
import Security
import XCTest
@testable import SxCore

final class MiniTOMLTests: XCTestCase {
    func testSectionsValuesAndComments() throws {
        let t = try MiniTOML.parse("""
        default = "personal"  # top level
        [vault.team]
        backend = "bitwarden"
        server = 'https://vault.example.com'
        [agents]
        allow = ["npm run dev", "go test ./...", 'a, b']
        require = true
        n = 3
        "quoted key" = "x # not a comment"
        """)
        XCTAssertEqual(t[0].values["default"], .string("personal"))
        XCTAssertEqual(t[1].section, "vault.team")
        XCTAssertEqual(t[1].values["server"], .string("https://vault.example.com"))
        XCTAssertEqual(t[2].values["allow"], .array(["npm run dev", "go test ./...", "a, b"]))
        XCTAssertEqual(t[2].values["require"], .bool(true))
        XCTAssertEqual(t[2].values["n"], .int(3))
        XCTAssertEqual(t[2].values["quoted key"], .string("x # not a comment"))
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try MiniTOML.parse("key value"))
        XCTAssertThrowsError(try MiniTOML.parse("k = {inline = 1}"))
    }
}

final class VaultConfigTests: XCTestCase {
    let text = """
    [vault.team]
    backend = "bitwarden"
    server = "https://vault.example.com"
    [vault.work]
    backend = "1password"
    account = "acme"
    [vault.hc]
    backend = "plugin"
    type = "hashicorp"
    [route]
    "/Users/x/work/team/**" = "team"
    "/Users/x/work/**" = "work"
    """

    func testBackendsAndRouting() throws {
        let c = try SxConfig.parse(text)
        XCTAssertEqual(c.vaults["team"]?.backend, .bitwarden(server: "https://vault.example.com"))
        XCTAssertEqual(c.vaults["work"]?.backend, .onePassword(account: "acme"))
        XCTAssertEqual(c.vaults["hc"]?.backend, .plugin(command: "sx-backend-hashicorp"))
        XCTAssertEqual(c.vault(forPath: "/Users/x/work/team/app").name, "team")
        XCTAssertEqual(c.vault(forPath: "/Users/x/work/other").name, "work")
        XCTAssertEqual(c.vault(forPath: "/Users/x/work").name, "work")
        XCTAssertEqual(c.vault(forPath: "/Users/x/personal").name, "personal")
    }

    func testBitwardenCLIIsBwUnlessTheVaultPinsOne() throws {
        let c = try SxConfig.parse("""
        [vault.team]
        backend = "bitwarden"
        [vault.selfhosted]
        backend = "bitwarden"
        server = "https://vault.example.com"
        cli = "npx -y  @bitwarden/cli@2025.12.1"
        """)
        XCTAssertEqual(c.vaults["team"]?.bitwardenCLI, ["bw"])
        XCTAssertEqual(c.vaults["team"]?.kind, "bitwarden")
        XCTAssertEqual(c.vaults["selfhosted"]?.bitwardenCLI, ["npx", "-y", "@bitwarden/cli@2025.12.1"])
        XCTAssertEqual(c.vaults["selfhosted"]?.kind, "bitwarden (npx -y @bitwarden/cli@2025.12.1)")
        XCTAssertEqual(c.vaults["selfhosted"]?.backend, .bitwarden(server: "https://vault.example.com"))
    }

    func testAnEmptyBitwardenCLIIsRefused() {
        XCTAssertThrowsError(try SxConfig.parse("[vault.team]\nbackend = \"bitwarden\"\ncli = \"  \""))
    }

    func testUnknownRouteTargetFails() {
        XCTAssertThrowsError(try SxConfig.parse("[route]\n\"/a/**\" = \"nope\""))
    }

    func testReferences() {
        XCTAssertEqual(SecretRef(reference: "app/KEY"), SecretRef(vault: nil, name: "app/KEY"))
        XCTAssertEqual(SecretRef(reference: "@team/ci/TOKEN"), SecretRef(vault: "team", name: "ci/TOKEN"))
        XCTAssertNil(SecretRef(reference: "@team"))
        XCTAssertNil(SecretRef(reference: ""))
    }
}

final class ProjectPolicyTests: XCTestCase {
    func testAllowlistMatchesWordPrefixes() throws {
        let p = try ProjectPolicy.parse("""
        [agents]
        allow = ["npm run dev", "npm test", "wrangler deploy", "make"]
        require = true
        [vault]
        default = "team"
        """)
        XCTAssertTrue(p.require)
        XCTAssertEqual(p.defaultVault, "team")
        XCTAssertTrue(p.allows(["npm", "run", "dev"]))
        XCTAssertTrue(p.allows(["/opt/homebrew/bin/npm", "test", "--", "-u"]))
        XCTAssertTrue(p.allows(["make", "deploy"]))
        XCTAssertFalse(p.allows(["npm", "run", "build"]))
        XCTAssertFalse(p.allows(["npm"]))
        XCTAssertFalse(p.allows(["wrangler", "secret", "list"]))
    }

    func testFindWalksUp() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("sx-policy-\(UUID().uuidString)")
        let deep = root.appendingPathComponent("a/b")
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        try "[agents]\n".write(to: root.appendingPathComponent(".sx.toml"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectPolicy.find(from: deep.path).map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path },
                       root.appendingPathComponent(".sx.toml").resolvingSymlinksInPath().path)
    }
}

final class SSHKeyTests: XCTestCase {
    private func keygen(_ type: String, bits: Int? = nil, passphrase: String = "") throws -> Data {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sx-ssh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("key").path
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-q", "-t", type, "-N", passphrase, "-C", "test@sx", "-f", path] + (bits.map { ["-b", "\($0)"] } ?? [])
        try p.run()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0)
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }

    func testEd25519SignatureVerifies() throws {
        let key = try SSHPrivateKey(openSSH: keygen("ed25519"))
        XCTAssertEqual(key.type, "ssh-ed25519")
        XCTAssertEqual(key.comment, "test@sx")
        XCTAssertTrue(key.fingerprint.hasPrefix("SHA256:"))
        let msg = Data("session data".utf8)
        var sig = SSHReader(try key.sign(msg))
        XCTAssertEqual(try sig.text(), "ssh-ed25519")
        let raw = try sig.string()
        var pub = SSHReader(key.publicBlob)
        _ = try pub.text()
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: try pub.string())
        XCTAssertTrue(pk.isValidSignature(raw, for: msg))
    }

    func testRSASignaturesVerifyForAllAlgorithms() throws {
        let key = try SSHPrivateKey(openSSH: keygen("rsa", bits: 2048))
        XCTAssertEqual(key.type, "ssh-rsa")
        var pub = SSHReader(key.publicBlob)
        _ = try pub.text()
        let e = try pub.string(), n = try pub.string()
        let der = DER.sequence([DER.integer(n), DER.integer(e)])
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        let pk = try XCTUnwrap(SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, nil))
        let msg = Data("session data".utf8)
        for (flags, name, alg) in [(SSHPrivateKey.agentRSASHA256, "rsa-sha2-256", SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256),
                                   (SSHPrivateKey.agentRSASHA512, "rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512),
                                   (0, "ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1)] {
            var sig = SSHReader(try key.sign(msg, flags: flags))
            XCTAssertEqual(try sig.text(), name)
            XCTAssertTrue(SecKeyVerifySignature(pk, alg, msg as CFData, Data(try sig.string()) as CFData, nil), name)
        }
    }

    func testEncryptedKeyIsRejectedWithGuidance() throws {
        XCTAssertThrowsError(try SSHPrivateKey(openSSH: keygen("ed25519", passphrase: "pw"))) { error in
            XCTAssertTrue("\(error)".contains("passphrase"))
        }
    }

    func testBigUIntMod() {
        // 1_000_003 mod 997 = 1_000_003 - 997*1003 = 12
        XCTAssertEqual(BigUInt.mod([0x0F, 0x42, 0x43], [0x03, 0xE5]), [12])
        XCTAssertEqual(BigUInt.minusOne([0x01, 0x00]), [0x00, 0xFF])
        XCTAssertEqual(BigUInt.mod([0x05], [0x07]), [5])
    }
}
