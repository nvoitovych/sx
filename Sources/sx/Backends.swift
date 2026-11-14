import Foundation
import SxCore

/// Non-keychain vaults run inside the CLI process; the broker only approves the request.
protocol ExternalBackend {
    func get(_ name: String, session: String?) throws -> Data
    func list(session: String?) throws -> [String]
    /// Stores a new secret; refuses to replace one that exists.
    func put(_ name: String, value: Data, about: String?, collection: String?, session: String?) throws
    /// Where `put` can file a secret (Bitwarden: the organization's collections).
    func collections(session: String?) throws -> [String]
}

extension ExternalBackend {
    func put(_ name: String, value: Data, about: String?, collection: String?, session: String?) throws {
        throw CLIError("this vault is read-only for sx; store \(name) with its own tool")
    }

    func collections(session: String?) throws -> [String] { [] }
}

enum Backends {
    static func make(_ vault: VaultConfig) throws -> ExternalBackend {
        switch vault.backend {
        case .keychain: throw CLIError("keychain vaults go through Sx.app")
        case let .bitwarden(server):
            return Bitwarden(vault: vault.name, server: server, cli: vault.bitwardenCLI,
                             organization: vault.settings["organization"], collection: vault.settings["collection"])
        case let .onePassword(account): return OnePassword(account: account)
        case let .plugin(command): return Plugin(command: command, vault: vault)
        }
    }

    /// Keychain name under which `sx login` keeps a Bitwarden session for this vault.
    static func sessionName(_ vault: String) -> String { "\(SX.internalPrefix)bitwarden-session/\(vault)" }
}

/// Runs a helper; stdout is captured (never printed), stderr is summarized on failure.
/// No helper gets the terminal: a child process does not own it, so prompts belong to sx.
func runTool(_ path: String, _ args: [String], env extra: [String: String] = [:], stdin: Data? = nil) throws -> Data {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = [path] + args
    var env = ProcessInfo.processInfo.environment
    for (k, v) in extra { env[k] = v }
    p.environment = env
    let out = Pipe()
    let err = Pipe()
    p.standardOutput = out
    p.standardError = err
    if let stdin {
        let inPipe = Pipe()
        p.standardInput = inPipe
        try p.run()
        inPipe.fileHandleForWriting.write(stdin)
        try inPipe.fileHandleForWriting.close()
    } else {
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { throw CLIError("\(path) not found — install it first") }
    }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0 else {
        let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: .newlines).last ?? ""
        throw CLIError("\(path) failed\(msg.isEmpty ? "" : ": \(msg)")")
    }
    return data
}

struct Bitwarden: ExternalBackend {
    let vault: String
    let server: String?
    /// argv of the Bitwarden CLI (`VaultConfig.bitwardenCLI`): `bw`, or a pinned one such as
    /// `npx -y @bitwarden/cli@<version>`.
    let cli: [String]
    /// Organization (name or id) that `put` files items in, and its default collection.
    var organization: String? = nil
    var collection: String? = nil

    /// Runs the vault's CLI. A CLI newer than a self-hosted server can fail to read the server's
    /// key-derivation answer; that failure names the fix instead of only the CLI's own words.
    private func bw(_ args: [String], env: [String: String], stdin: Data? = nil) throws -> Data {
        do {
            return try runTool(cli[0], Array(cli.dropFirst()) + args, env: env, stdin: stdin)
        } catch let error as CLIError where error.description.contains("KDF") {
            throw CLIError("\(error.description)\n  the Bitwarden CLI does not understand this server's login settings; "
                + "pin a CLI that matches the server in [vault.\(vault)]: cli = \"npx -y @bitwarden/cli@<version>\"")
        }
    }

    /// A separate bw data dir per vault lets several Bitwarden servers coexist.
    var env: [String: String] {
        guard server != nil else { return [:] }
        return ["BITWARDENCLI_APPDATA_DIR": "\(SX.realHome)/.config/sx/bitwarden/\(vault)"]
    }

    func env(session: String?) -> [String: String] {
        var e = env
        if let session { e["BW_SESSION"] = session }
        return e
    }

    /// `name` or `name#field`: password, then notes, unless a custom field is named.
    func get(_ name: String, session: String?) throws -> Data {
        let (item, field) = split(name)
        let json = try bw(["get", "item", item, "--nointeraction"], env: env(session: session))
        guard let obj = try JSONSerialization.jsonObject(with: json) as? [String: Any] else { throw CLIError("bw: unexpected output for \(item)") }
        if let field {
            let fields = obj["fields"] as? [[String: Any]] ?? []
            guard let v = fields.first(where: { $0["name"] as? String == field })?["value"] as? String else {
                throw CLIError("bw: \(item) has no field \(field)")
            }
            return Data(v.utf8)
        }
        if let login = obj["login"] as? [String: Any], let pw = login["password"] as? String, !pw.isEmpty { return Data(pw.utf8) }
        if let notes = obj["notes"] as? String, !notes.isEmpty { return Data(notes.utf8) }
        throw CLIError("bw: \(item) has no password or notes; use \(item)#FIELD")
    }

    func list(session: String?) throws -> [String] {
        let json = try bw(["list", "items", "--nointeraction"], env: env(session: session))
        let items = try JSONSerialization.jsonObject(with: json) as? [[String: Any]] ?? []
        return items.compactMap { $0["name"] as? String }.sorted()
    }

    /// The item travels to `bw create` on stdin, never in argv (argv is visible to every process).
    /// An existing item of that name is refused; the stored value is read back and compared by hash.
    func put(_ name: String, value: Data, about: String?, collection wanted: String?, session: String?) throws {
        guard !name.isEmpty, !name.contains("\n") else { throw CLIError("invalid name \(name)") }
        guard let text = String(data: value, encoding: .utf8), !text.isEmpty else {
            throw CLIError("\(name): Bitwarden stores text; the value is empty or not UTF-8")
        }
        let e = env(session: session)
        // The CLI answers from its local copy; a fresh one sees items, organizations and memberships added since login.
        _ = try bw(["sync", "--nointeraction"], env: e)
        let found = try JSONSerialization.jsonObject(with: bw(["list", "items", "--search", name, "--nointeraction"], env: e))
        if (found as? [[String: Any]] ?? []).contains(where: { $0["name"] as? String == name }) {
            throw CLIError("\(name) already exists in \(vault); sx does not overwrite — rename or remove it in Bitwarden first")
        }
        var orgId: String?
        var collId: String?
        if let organization {
            let orgs = try JSONSerialization.jsonObject(with: bw(["list", "organizations", "--nointeraction"], env: e))
            orgId = try BitwardenItem.pick(organization, from: orgs as? [[String: Any]] ?? [], kind: "organization")
            guard let c = wanted ?? collection else {
                throw CLIError("\(vault) files secrets in organization \(organization); name a collection "
                    + "(--collection, or collection = \"…\" in [vault.\(vault)]); see sx ls --vault \(vault) --collections")
            }
            let colls = try JSONSerialization.jsonObject(with: bw(["list", "org-collections", "--organizationid", orgId!, "--nointeraction"], env: e))
            collId = try BitwardenItem.pick(c, from: colls as? [[String: Any]] ?? [], kind: "collection")
        }
        let item = BitwardenItem.make(name: name, value: text, about: about, organizationId: orgId, collectionId: collId)
        let encoded = try JSONSerialization.data(withJSONObject: item).base64EncodedData()
        _ = try bw(["create", "item", "--nointeraction"], env: e, stdin: encoded)
        guard shortHash(try get(name, session: session)) == shortHash(value) else {
            throw CLIError("\(name) was created but reads back different; check it in Bitwarden")
        }
    }

    func collections(session: String?) throws -> [String] {
        guard let organization else { return [] }
        let e = env(session: session)
        _ = try bw(["sync", "--nointeraction"], env: e)
        let orgs = try JSONSerialization.jsonObject(with: bw(["list", "organizations", "--nointeraction"], env: e))
        let orgId = try BitwardenItem.pick(organization, from: orgs as? [[String: Any]] ?? [], kind: "organization")
        let colls = try JSONSerialization.jsonObject(with: bw(["list", "org-collections", "--organizationid", orgId, "--nointeraction"], env: e))
        return (colls as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }.sorted()
    }

    /// Interactive: configure server, log in if needed, unlock; returns the session key.
    /// sx asks for everything itself and runs `bw` without a terminal: a child process does not own
    /// the terminal, so the CLI's own prompts (raw mode) cannot read it.
    func login() throws -> String {
        if let server {
            try FileManager.default.createDirectory(atPath: env["BITWARDENCLI_APPDATA_DIR"]!, withIntermediateDirectories: true)
            _ = try? bw(["config", "server", server], env: env)
        }
        let status = (try? bw(["status"], env: env)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        if status?["status"] as? String == "unauthenticated" {
            stderrPrint("Logging in to Bitwarden\(server.map { " (\($0))" } ?? "")…")
            let email = try prompt("Email: ", echo: true)
            var e = env
            e["SX_BW_PASSWORD"] = try prompt("Master password: ", echo: false)
            let login = ["login", email, "--passwordenv", "SX_BW_PASSWORD", "--raw", "--nointeraction"]
            let out: Data
            do {
                out = try bw(login, env: e)
            } catch let error as CLIError where VaultConfig.bitwardenNeedsSecondFactor(error.description) {
                let method = try prompt("Two-step method (0 authenticator, 1 e-mail, 3 YubiKey) [0]: ", echo: true)
                let code = try prompt("Two-step code: ", echo: true)
                out = try bw(login + ["--method", method.isEmpty ? "0" : method, "--code", code], env: e)
            }
            let session = String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !session.isEmpty else { throw CLIError("bw login returned no session") }
            return session
        }
        var e = env
        e["SX_BW_PASSWORD"] = try prompt("Bitwarden master password for \(vault): ", echo: false)
        let session = String(decoding: try bw(["unlock", "--passwordenv", "SX_BW_PASSWORD", "--raw"], env: e), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !session.isEmpty else { throw CLIError("bw unlock returned no session") }
        return session
    }

    /// Reads one line from the terminal (not stdin); the buffer is wiped after use.
    private func prompt(_ text: String, echo: Bool) throws -> String {
        var buf = [CChar](repeating: 0, count: 1024)
        defer { buf.withUnsafeMutableBufferPointer { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard let p = readpassphrase(text, &buf, buf.count, echo ? RPP_ECHO_ON : 0) else { throw CLIError("no input") }
        return String(cString: p).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func split(_ name: String) -> (String, String?) {
        guard let hash = name.lastIndex(of: "#") else { return (name, nil) }
        return (String(name[..<hash]), String(name[name.index(after: hash)...]))
    }
}

/// 1Password via `op read op://Vault/Item[/field]`; `op` handles its own unlock (app integration / Touch ID).
struct OnePassword: ExternalBackend {
    let account: String?

    private var accountArgs: [String] { account.map { ["--account", $0] } ?? [] }

    func get(_ name: String, session: String?) throws -> Data {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 || parts.count == 3, !parts.contains(where: \.isEmpty) else {
            throw CLIError("1Password names are Vault/Item or Vault/Item/field (got \(name))")
        }
        let ref = "op://" + (parts.count == 2 ? "\(name)/password" : name)
        return try runTool("op", ["read", "--no-newline"] + accountArgs + [ref])
    }

    func list(session: String?) throws -> [String] {
        let json = try runTool("op", ["item", "list", "--format", "json"] + accountArgs)
        let items = try JSONSerialization.jsonObject(with: json) as? [[String: Any]] ?? []
        return items.compactMap { item in
            guard let title = item["title"] as? String else { return nil }
            let vault = (item["vault"] as? [String: Any])?["name"] as? String ?? "?"
            return "\(vault)/\(title)"
        }.sorted()
    }
}

/// Any executable `sx-backend-<type>` (or `command = …`). Protocol, one JSON object each way:
///   stdin:  {"op":"get","name":"…","vault":"…","settings":{…}}   (op: get | list)
///   stdout: {"ok":true,"value":"<base64>"} | {"ok":true,"names":[…]} | {"ok":false,"error":"…"}
struct Plugin: ExternalBackend {
    let command: String
    let vault: VaultConfig

    private func call(_ op: String, name: String? = nil) throws -> [String: Any] {
        var req: [String: Any] = ["op": op, "vault": vault.name, "settings": vault.settings]
        if let name { req["name"] = name }
        let out = try runTool(command, [], stdin: try JSONSerialization.data(withJSONObject: req))
        guard let resp = try JSONSerialization.jsonObject(with: out) as? [String: Any] else { throw CLIError("\(command): invalid response") }
        guard resp["ok"] as? Bool == true else { throw CLIError("\(command): \(resp["error"] as? String ?? "failed")") }
        return resp
    }

    func get(_ name: String, session: String?) throws -> Data {
        guard let b64 = try call("get", name: name)["value"] as? String, let d = Data(base64Encoded: b64) else {
            throw CLIError("\(command): no value for \(name)")
        }
        return d
    }

    func list(session: String?) throws -> [String] {
        (try call("list")["names"] as? [String] ?? []).sorted()
    }
}
