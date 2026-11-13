import Foundation
import XCTest
@testable import SxCore

final class EnvFileTests: XCTestCase {
    func testParsesReferencesLiteralsQuotesAndComments() {
        let text = """
        # comment
        export A=sx://proj/A
        B="quoted value"
        C='single'
        D=plain # trailing comment
        bad-key=1
        EMPTY=
        """
        let e = EnvFile.parse(text)
        XCTAssertEqual(e.map(\.key), ["A", "B", "C", "D", "EMPTY"])
        XCTAssertEqual(e[0].reference, "proj/A")
        XCTAssertEqual(e[1].value, "quoted value")
        XCTAssertEqual(e[2].value, "single")
        XCTAssertEqual(e[3].value, "plain")
        XCTAssertNil(e[3].reference)
    }

    func testQuotedRenderRoundTrips() {
        let pairs = [("A", "plain"), ("B", "multi\nline \"quoted\" back\\slash"), ("C", "")]
        let back = EnvFile.parse(EnvFile.renderQuoted(pairs))
        XCTAssertEqual(back.map(\.key), ["A", "B", "C"])
        XCTAssertEqual(back.map(\.value), pairs.map(\.1))
    }

    func testSecretNames() {
        XCTAssertTrue(SecretName.isValid("reelifyads/OPENAI_KEY"))
        XCTAssertTrue(SecretName.isValid("ssh/id_ed25519.pub"))
        XCTAssertFalse(SecretName.isValid("/abs"))
        XCTAssertFalse(SecretName.isValid("a//b"))
        XCTAssertFalse(SecretName.isValid("space name"))
        XCTAssertFalse(SecretName.isValid(""))
    }
}

final class RedactorTests: XCTestCase {
    let secret = Data("s3cr3t-token-value".utf8)

    func testRawBase64AndHexAreMasked() {
        let r = Redactor(secrets: ["TOKEN": secret])
        let b64 = secret.base64EncodedString()
        let hex = secret.map { String(format: "%02x", $0) }.joined()
        let out = String(data: r.redact(Data("a s3cr3t-token-value b \(b64) c \(hex)".utf8)), encoding: .utf8)!
        XCTAssertEqual(out, "a <sx:TOKEN> b <sx:TOKEN> c <sx:TOKEN>")
    }

    func testSecretSplitAcrossChunks() {
        let r = Redactor(secrets: ["TOKEN": secret])
        var out = Data()
        let input = Array("prefix s3cr3t-token-value suffix".utf8)
        for byte in input { out += r.feed(Data([byte])) }
        out += r.finish()
        XCTAssertEqual(String(data: out, encoding: .utf8), "prefix <sx:TOKEN> suffix")
    }

    func testShortValuesAreNotMasked() {
        let r = Redactor(secrets: ["X": Data("ab".utf8)])
        XCTAssertTrue(r.isEmpty)
        XCTAssertEqual(r.redact(Data("ab".utf8)), Data("ab".utf8))
    }

    func testTrailingNewlineVariant() {
        let r = Redactor(secrets: ["K": Data("abcdef\n".utf8)])
        XCTAssertEqual(String(data: r.redact(Data("x abcdef y".utf8)), encoding: .utf8), "x <sx:K> y")
    }
}

final class PolicyTests: XCTestCase {
    func testAgentDenials() {
        XCTAssertNotNil(Policy.agentDenial(argv: ["env"]))
        XCTAssertNotNil(Policy.agentDenial(argv: ["/usr/bin/printenv", "KEY"]))
        XCTAssertNotNil(Policy.agentDenial(argv: ["bash", "-c", "echo $KEY"]))
        XCTAssertNotNil(Policy.agentDenial(argv: ["python3.12", "-c", "print(1)"]))
        XCTAssertNotNil(Policy.agentDenial(argv: ["node", "-e", "1"]))
        XCTAssertNotNil(Policy.agentDenial(argv: ["sx", "run", "--", "x"]))
        XCTAssertNil(Policy.agentDenial(argv: ["npm", "run", "dev"]))
        XCTAssertNil(Policy.agentDenial(argv: ["bash", "scripts/deploy.sh"]))
        XCTAssertNil(Policy.agentDenial(argv: ["wrangler", "deploy"]))
    }
}

final class AgentDetectTests: XCTestCase {
    func testEnvMarker() {
        XCTAssertEqual(AgentDetect.detect(env: ["CLAUDECODE": "1"]), "Claude Code")
    }

    func testAncestryIsReadable() {
        XCTAssertFalse(AgentDetect.ancestry().isEmpty)
    }
}

final class WireTests: XCTestCase {
    func testRoundTrip() throws {
        let req = BrokerRequest(op: .resolve, names: ["a/B"], argv: ["npm", "run"], cwd: "/x", agent: "Claude Code")
        XCTAssertEqual(try Wire.decode(BrokerRequest.self, from: Wire.encode(req)), req)
    }
}
