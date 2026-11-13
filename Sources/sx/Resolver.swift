import Foundation
import SxCore

/// Turns `.env.sx` entries into values: keychain secrets come from Sx.app,
/// other vaults are fetched here after Sx.app has approved the whole request.
enum Resolver {
    static func resolve(entries: [EnvFile.Entry], argv: [String], cwd: String, agent: String?) throws -> [String: Data] {
        let refs = entries.compactMap { e in e.reference.flatMap(SecretRef.init(reference:)).map { (e.key, $0) } }
        if let bad = entries.first(where: { $0.reference != nil && SecretRef(reference: $0.reference!) == nil }) {
            throw CLIError("bad reference for \(bad.key): \(bad.value)")
        }
        guard !refs.isEmpty else { return [:] }

        let config = try SxConfig.load()
        let projectFile = ProjectPolicy.find(from: cwd)
        let projectDefault = projectFile.flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }
            .flatMap { try? ProjectPolicy.parse($0) }?.defaultVault
        func vault(of ref: SecretRef) throws -> VaultConfig {
            if let name = ref.vault ?? projectDefault {
                guard let v = config.vaults[name] else { throw CLIError("unknown vault @\(name) (see \(SxConfig.path))") }
                return v
            }
            return config.vault(forPath: cwd)
        }

        var keychainNames: Set<String> = []
        var external: [(key: String, ref: SecretRef, vault: VaultConfig)] = []
        for (key, ref) in refs {
            let v = try vault(of: ref)
            if v.backend == .keychain {
                keychainNames.insert(ref.name)
            } else {
                external.append((key, SecretRef(vault: v.name, name: ref.name), v))
                if case .bitwarden = v.backend { keychainNames.insert(Backends.sessionName(v.name)) }
            }
        }

        // Stored Bitwarden sessions are optional: without one, `bw` uses BW_SESSION from the environment.
        var names = keychainNames
        if !names.isEmpty {
            let stored = Set((try Client.call(BrokerRequest(op: .list)).secrets ?? []).map(\.name))
            names = names.filter { !$0.hasPrefix(SX.internalPrefix) || stored.contains($0) }
        }

        let resp = try Client.call(BrokerRequest(op: .resolve, names: names.sorted(), argv: argv, cwd: cwd, agent: agent,
                                                 external: external.map { $0.ref.display }.sorted(), projectFile: projectFile))
        var values: [String: Data] = [:]
        for (name, b64) in resp.values ?? [:] {
            guard let d = Data(base64Encoded: b64) else { throw CLIError("broker returned malformed \(name)") }
            values[name] = d
        }

        var out: [String: Data] = [:]
        for (key, ref) in refs where (try? vault(of: ref))?.backend == .keychain {
            guard let d = values[ref.name] else { throw CLIError("no secret \(ref.name) in the keychain (sx ls)") }
            out[key] = d
        }
        for item in external {
            let session = values[Backends.sessionName(item.vault.name)].map { String(decoding: $0, as: UTF8.self) }
            out[item.key] = try Backends.make(item.vault).get(item.ref.name, session: session)
        }
        return out
    }
}
