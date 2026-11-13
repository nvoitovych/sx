import Foundation
import SxCore

enum SSHCommands {
    static func run(_ args: [String]) throws -> Int32 {
        guard let sub = args.first else { throw CLIError("usage: sx ssh import|list|setup") }
        let f = try Flags(Array(args.dropFirst()))
        switch sub {
        case "import":
            guard let path = f.positional.first else { throw CLIError("usage: sx ssh import PATH [--name ssh/NAME]") }
            let data = try readSecretValue(file: path)
            let key = try SSHPrivateKey(openSSH: data) // validates before storing
            let name = f.one("--name") ?? "ssh/" + (path as NSString).lastPathComponent
            try put(name, data, tags: [SX.sshTag] + f.all("--tag"))
            if f.switches.contains("--remove-original") { try FileManager.default.removeItem(atPath: (path as NSString).expandingTildeInPath) }
            print("✓ \(name)  \(key.type)  \(key.fingerprint)")
            print("  public key: \(key.authorizedKey)")

        case "list":
            let keys = (try Client.call(BrokerRequest(op: .list)).secrets ?? []).filter { $0.tags.contains(SX.sshTag) }
            if keys.isEmpty { print("no SSH keys; add one with `sx ssh import ~/.ssh/id_ed25519`") }
            for k in keys { print(k.name) }
            print("agent socket: \(SX.sshAgentSocketPath)")
            print("fingerprints: SSH_AUTH_SOCK=\"\(SX.sshAgentSocketPath)\" ssh-add -l")

        case "setup":
            let line = "  IdentityAgent \"\(SX.sshAgentSocketPath)\""
            let block = "\n# sx SSH agent: keys stay in the keychain; each new use asks for approval\nHost *\n\(line)\n"
            if f.switches.contains("--write") {
                let config = SX.realHome + "/.ssh/config"
                let existing = (try? String(contentsOfFile: config, encoding: .utf8)) ?? ""
                if existing.contains(SX.sshAgentSocketPath) {
                    print("~/.ssh/config already uses the sx agent")
                } else {
                    if !existing.isEmpty { try existing.write(toFile: config + ".sx-backup", atomically: true, encoding: .utf8) }
                    try FileManager.default.createDirectory(atPath: SX.realHome + "/.ssh", withIntermediateDirectories: true,
                                                            attributes: [.posixPermissions: 0o700])
                    // Prepend: the first IdentityAgent that matches wins in ssh_config.
                    try (block.trimmingCharacters(in: .newlines) + "\n\n" + existing).write(toFile: config, atomically: true, encoding: .utf8)
                    chmod(config, 0o600)
                    print("✓ ~/.ssh/config now uses the sx agent\(existing.isEmpty ? "" : " (backup: ~/.ssh/config.sx-backup)")")
                }
            } else {
                print("Add to the top of ~/.ssh/config (or run `sx ssh setup --write`):\(block)")
                print("Or per shell: export SSH_AUTH_SOCK=\"\(SX.sshAgentSocketPath)\"")
            }

        default:
            throw CLIError("usage: sx ssh import|list|setup")
        }
        return 0
    }
}
