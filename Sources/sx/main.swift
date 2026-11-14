import CryptoKit
import Foundation
import SxCore

let usage = """
sx \(SX.version) — secrets exec. Agents can use secrets; nobody sees them in files or output.

Run
  sx run [--env-file F] [--env K=sx://name] [--file PATH] [--no-mask] -- cmd [args]
                                    run cmd with secrets from .env.sx (default) in its env;
                                    secret values are masked in its output. --file also writes them
                                    as dotenv to PATH (mode 600) for the run only, e.g. wrangler's .dev.vars
Keychain secrets
  sx put NAME [--tag T] [--file P]  store a secret (value from --file, stdin, or hidden prompt)
  sx put NAME --vault V [--file P] [--about TEXT] [--collection C]
                                    store in a Bitwarden vault (organization from the vault's config); never overwrites
  sx import-env FILE --prefix P [--out F] [--tag T] [--literal K1,K2] [--dedupe-with P2] [--remove-original]
                                    move a dotenv file into sx; writes .env.sx with references
  sx import-file PATH --name NAME [--tag T] [--remove-original]
  sx verify NAME (--file P | stdin) compare by hash, never by value
  sx export NAME --out PATH         write a key file back to disk (human-only, Touch ID)
  sx ls [--vault V] [--json] [--collections]
                                    list secret names (Bitwarden: --collections lists where put can file)
  sx rm NAME                        delete a secret (Touch ID)
Vaults (~/.config/sx/config.toml)
  sx vaults                         configured vaults and the one this directory routes to
  sx login VAULT                    unlock a Bitwarden vault; the session is kept in the keychain
Projects
  sx trust [PATH]                   approve this project's .sx.toml agent allowlist (Touch ID)
SSH
  sx ssh import PATH [--name N]     store an OpenSSH private key (ed25519/rsa) for the sx SSH agent
  sx ssh list                       keys the agent offers, with fingerprints
  sx ssh setup [--write]            point ssh at the sx agent (prints, or appends to ~/.ssh/config)
Other
  sx status                         broker, agent detection, vault routing

References: sx://name (vault by route) or sx://@vault/name. Tag `prod` = Touch ID on every use.
"""

func shortHash(_ d: Data) -> String {
    SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined().prefix(16).description
}

func stderrPrint(_ s: String) {
    FileHandle.standardError.write((s + "\n").data(using: .utf8)!)
}

struct Flags {
    var positional: [String] = []
    var values: [String: [String]] = [:]
    var switches: Set<String> = []

    static let valued: Set<String> = ["--tag", "--file", "--prefix", "--out", "--name", "--literal", "--dedupe-with", "--vault",
                                      "--about", "--collection"]

    init(_ args: [String]) throws {
        var i = 0
        while i < args.count {
            let a = args[i]
            if Self.valued.contains(a) {
                guard i + 1 < args.count else { throw CLIError("\(a) needs a value") }
                values[a, default: []].append(args[i + 1])
                i += 2
            } else if a.hasPrefix("--") {
                switches.insert(a)
                i += 1
            } else {
                positional.append(a)
                i += 1
            }
        }
    }

    func one(_ key: String) -> String? { values[key]?.last }
    func all(_ key: String) -> [String] { values[key] ?? [] }
}

func readSecretValue(file: String?) throws -> Data {
    if let file {
        guard let d = FileManager.default.contents(atPath: (file as NSString).expandingTildeInPath) else { throw CLIError("cannot read \(file)") }
        return d
    }
    if isatty(STDIN_FILENO) != 0 {
        var buf = [CChar](repeating: 0, count: 8192)
        guard let p = readpassphrase("value (hidden): ", &buf, buf.count, 0) else { throw CLIError("no input") }
        let s = String(cString: p)
        buf.withUnsafeMutableBufferPointer { memset_s($0.baseAddress, $0.count, 0, $0.count) }
        return Data(s.utf8)
    }
    return FileHandle.standardInput.readDataToEndOfFile()
}

func storedSession(_ vault: VaultConfig) throws -> String? {
    guard case .bitwarden = vault.backend else { return nil }
    let name = Backends.sessionName(vault.name)
    let stored = (try Client.call(BrokerRequest(op: .list)).secrets ?? []).contains { $0.name == name }
    guard stored else { return nil }
    let resp = try Client.call(BrokerRequest(op: .resolve, names: [name], argv: ["bw", "list", "items"],
                                             cwd: FileManager.default.currentDirectoryPath, agent: AgentDetect.detect()))
    return resp.values?[name].flatMap { Data(base64Encoded: $0) }.map { String(decoding: $0, as: UTF8.self) }
}

func put(_ name: String, _ value: Data, tags: [String], allowInternal: Bool = false) throws {
    guard SecretName.isValid(name) else { throw CLIError("invalid name \(name)") }
    guard allowInternal || !name.hasPrefix(SX.internalPrefix) else { throw CLIError("names starting with \(SX.internalPrefix) are reserved") }
    guard !value.isEmpty else { throw CLIError("empty value for \(name)") }
    _ = try Client.call(BrokerRequest(op: .put, name: name, value: value.base64EncodedString(), tags: tags,
                                      cwd: FileManager.default.currentDirectoryPath, agent: AgentDetect.detect()))
    // Read-back check by hash: proves the stored bytes match without returning them.
    let stored = try Client.call(BrokerRequest(op: .hash, name: name)).hash
    guard stored == shortHash(value) else { throw CLIError("verification failed for \(name)") }
}

func secureRemove(_ path: String) throws {
    try FileManager.default.removeItem(atPath: path)
}

func main() throws -> Int32 {
    var args = Array(CommandLine.arguments.dropFirst())
    guard let cmd = args.first else {
        print(usage)
        return 0
    }
    args.removeFirst()

    switch cmd {
    case "run":
        return try Run.execute(args)

    case "put":
        let f = try Flags(args)
        guard let name = f.positional.first else { throw CLIError("usage: sx put NAME") }
        if let vaultName = f.one("--vault") {
            guard let vault = try SxConfig.load().vaults[vaultName] else { throw CLIError("unknown vault \(vaultName)") }
            if vault.backend != .keychain {
                let value = try readSecretValue(file: f.one("--file"))
                try Backends.make(vault).put(name, value: value, about: f.one("--about"), collection: f.one("--collection"),
                                             session: try storedSession(vault))
                print("✓ \(name) → \(vault.name)  sha:\(shortHash(value))")
                return 0
            }
        }
        try put(name, readSecretValue(file: f.one("--file")), tags: f.all("--tag"))
        print("✓ \(name)")

    case "import-file":
        let f = try Flags(args)
        guard let path = f.positional.first, let name = f.one("--name") else { throw CLIError("usage: sx import-file PATH --name NAME") }
        let data = try readSecretValue(file: path)
        try put(name, data, tags: f.all("--tag"))
        if f.switches.contains("--remove-original") { try secureRemove(path) }
        print("✓ \(name)  sha:\(shortHash(data))\(f.switches.contains("--remove-original") ? "  (original removed)" : "")")

    case "import-env":
        let f = try Flags(args)
        guard let path = f.positional.first, let prefix = f.one("--prefix") else { throw CLIError("usage: sx import-env FILE --prefix P") }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw CLIError("cannot read \(path)") }
        let out = f.one("--out") ?? ((path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(SX.defaultEnvFile)
        var existing = (try? String(contentsOfFile: out, encoding: .utf8)).map(EnvFile.parse) ?? []
        var imported = 0
        // Non-secret settings stay plain text in .env.sx.
        let literal = Set(f.all("--literal").flatMap { $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } })
        // Same KEY with the same value already stored under another prefix → reference it instead of a copy.
        let dedupePrefixes = f.all("--dedupe-with")
        let existingNames = dedupePrefixes.isEmpty ? [] : Set((try Client.call(BrokerRequest(op: .list)).secrets ?? []).map(\.name))
        for e in EnvFile.parse(text) {
            let entry: EnvFile.Entry
            if e.reference != nil || e.value.isEmpty || literal.contains(e.key) {
                entry = e
                if literal.contains(e.key) { print("· \(e.key) kept as plain text") }
            } else if let twin = try dedupePrefixes.map({ "\($0)/\(e.key)" }).first(where: { name in
                guard existingNames.contains(name) else { return false }
                return try Client.call(BrokerRequest(op: .hash, name: name)).hash == shortHash(Data(e.value.utf8))
            }) {
                entry = EnvFile.Entry(key: e.key, value: SX.refScheme + twin)
                print("= \(e.key) → \(SX.refScheme)\(twin) (same value, reused)")
            } else {
                let name = "\(prefix)/\(e.key)"
                try put(name, Data(e.value.utf8), tags: f.all("--tag"))
                entry = EnvFile.Entry(key: e.key, value: SX.refScheme + name)
                imported += 1
                print("✓ \(e.key) → \(SX.refScheme)\(name)")
            }
            if let idx = existing.firstIndex(where: { $0.key == entry.key }) { existing[idx] = entry } else { existing.append(entry) }
        }
        try EnvFile.render(existing, header: "sx references only — safe to commit. Run: sx run -- <cmd>")
            .write(toFile: out, atomically: true, encoding: .utf8)
        if f.switches.contains("--remove-original") { try secureRemove(path) }
        print("\(imported) secrets imported; wrote \(out)\(f.switches.contains("--remove-original") ? "; removed \(path)" : "")")

    case "export":
        // Restores a key file (signing key, .p12, .netrc …). Human-only, Touch ID every time.
        let f = try Flags(args)
        guard let name = f.positional.first, let out = f.one("--out") else { throw CLIError("usage: sx export NAME --out PATH [--force]") }
        if let agent = AgentDetect.detect() { throw CLIError("refused for \(agent): export is human-only", code: 126) }
        let path = (out as NSString).expandingTildeInPath
        if FileManager.default.fileExists(atPath: path), !f.switches.contains("--force") { throw CLIError("\(out) exists (use --force)") }
        let resp = try Client.call(BrokerRequest(op: .reveal, name: name, argv: ["sx", "export", name, "--out", out],
                                                 cwd: FileManager.default.currentDirectoryPath, agent: nil))
        guard let data = resp.values?[name].flatMap({ Data(base64Encoded: $0) }) else { throw CLIError("no value returned") }
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        guard FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CLIError("cannot write \(out)")
        }
        print("✓ \(name) → \(out) (mode 600)")

    case "verify":
        let f = try Flags(args)
        guard let name = f.positional.first else { throw CLIError("usage: sx verify NAME --file P") }
        let local = try readSecretValue(file: f.one("--file"))
        let stored = try Client.call(BrokerRequest(op: .hash, name: name)).hash
        if stored == shortHash(local) {
            print("✓ \(name) matches")
        } else {
            print("✗ \(name) differs")
            return 1
        }

    case "ls", "list":
        let f = try Flags(args)
        if let name = f.one("--vault") {
            let config = try SxConfig.load()
            guard let vault = config.vaults[name] else { throw CLIError("unknown vault \(name)") }
            if vault.backend != .keychain {
                let session = try storedSession(vault)
                let backend = try Backends.make(vault)
                for n in try f.switches.contains("--collections") ? backend.collections(session: session) : backend.list(session: session) {
                    print(n)
                }
                return 0
            }
        }
        let secrets = (try Client.call(BrokerRequest(op: .list)).secrets ?? []).filter { !$0.name.hasPrefix(SX.internalPrefix) }
        if f.switches.contains("--json") {
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            enc.dateEncodingStrategy = .iso8601
            print(String(data: try enc.encode(secrets), encoding: .utf8)!)
        } else {
            for s in secrets { print(s.tags.isEmpty ? s.name : "\(s.name)  [\(s.tags.joined(separator: ","))]") }
        }

    case "rm", "remove":
        guard let name = args.first else { throw CLIError("usage: sx rm NAME") }
        _ = try Client.call(BrokerRequest(op: .remove, name: name, cwd: FileManager.default.currentDirectoryPath, agent: AgentDetect.detect()))
        print("✓ removed \(name)")

    case "status":
        let agent = AgentDetect.detect()
        let cwd = FileManager.default.currentDirectoryPath
        print("agent:   \(agent ?? "none (human)")")
        print("vault:   \(try SxConfig.load().vault(forPath: cwd).name) (for this directory)")
        print("project: \(ProjectPolicy.find(from: cwd) ?? "no .sx.toml")")
        print("socket:  \(SX.socketPath)")
        let resp = try Client.call(BrokerRequest(op: .ping))
        print("broker:  ok (Sx.app \(resp.version ?? "?"))")

    case "vaults":
        let config = try SxConfig.load()
        let here = config.vault(forPath: FileManager.default.currentDirectoryPath).name
        for v in config.vaults.values.sorted(by: { $0.name < $1.name }) {
            print("\(v.name == here ? "→" : " ") \(v.name)  \(v.kind)\(v.name == config.defaultVault ? "  (default)" : "")")
        }
        for r in config.routes { print("  route \(r.pattern) → \(r.vault)") }
        if !FileManager.default.fileExists(atPath: SxConfig.path) { print("  (no \(SxConfig.path); only the keychain vault)") }

    case "login":
        guard let name = args.first else { throw CLIError("usage: sx login VAULT") }
        guard let vault = try SxConfig.load().vaults[name] else { throw CLIError("unknown vault \(name)") }
        guard case let .bitwarden(server) = vault.backend else {
            throw CLIError("\(name) is \(vault.kind); only Bitwarden vaults need `sx login` (1Password uses its own app unlock)")
        }
        let session = try Bitwarden(vault: name, server: server, cli: vault.bitwardenCLI).login()
        try put(Backends.sessionName(name), Data(session.utf8), tags: ["internal"], allowInternal: true)
        print("✓ \(name) unlocked; session stored in the keychain (sx run asks before using it)")

    case "trust":
        let start = args.first ?? FileManager.default.currentDirectoryPath
        let file = start.hasSuffix(ProjectPolicy.fileName) ? start : ProjectPolicy.find(from: start)
        guard let file, FileManager.default.fileExists(atPath: file) else { throw CLIError("no \(ProjectPolicy.fileName) here or above") }
        let path = URL(fileURLWithPath: file).resolvingSymlinksInPath().path
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw CLIError("cannot read \(path)") }
        let policy = try ProjectPolicy.parse(text)
        _ = try Client.call(BrokerRequest(op: .trust, cwd: FileManager.default.currentDirectoryPath,
                                          agent: AgentDetect.detect(), projectFile: path))
        print("✓ trusted \(path)")
        for a in policy.allow { print("  agents may run: \(a)") }
        if policy.require { print("  agents may run nothing else with secrets") }

    case "ssh":
        return try SSHCommands.run(args)

    case "version", "--version", "-v":
        print("sx \(SX.version)")

    case "help", "--help", "-h":
        print(usage)

    default:
        throw CLIError("unknown command \(cmd)\n\n\(usage)")
    }
    return 0
}

do {
    exit(try main())
} catch let e as CLIError {
    stderrPrint("sx: \(e.description)")
    exit(e.code)
} catch {
    stderrPrint("sx: \(error)")
    exit(1)
}
