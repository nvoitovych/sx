import CryptoKit
import Foundation

/// `.sx.toml` in a project: which commands agents may run with secrets.
///
///     [agents]
///     allow = ["npm run dev", "npm test", "wrangler deploy"]
///     require = true      # agents may run only allowlisted commands
///
/// The file has effect only after a human runs `sx trust` (Touch ID); any edit un-trusts it.
public struct ProjectPolicy: Equatable {
    public static let fileName = ".sx.toml"

    public var allow: [String]
    public var require: Bool
    public var defaultVault: String?

    public init(allow: [String] = [], require: Bool = false, defaultVault: String? = nil) {
        self.allow = allow
        self.require = require
        self.defaultVault = defaultVault
    }

    public static func parse(_ text: String) throws -> ProjectPolicy {
        var p = ProjectPolicy()
        for (section, values) in try MiniTOML.parse(text) {
            switch section {
            case "agents":
                p.allow = values["allow"]?.array ?? []
                p.require = values["require"]?.bool ?? false
            case "vault":
                p.defaultVault = values["default"]?.string
            default:
                continue
            }
        }
        return p
    }

    /// Nearest `.sx.toml` from `dir` upward, stopping at the home directory.
    public static func find(from dir: String) -> String? {
        var current = (dir as NSString).standardizingPath
        let home = SX.realHome
        while true {
            let candidate = (current as NSString).appendingPathComponent(fileName)
            // Real path, so `sx trust` and `sx run` agree even through symlinks (/tmp → /private/tmp).
            if FileManager.default.fileExists(atPath: candidate) { return URL(fileURLWithPath: candidate).resolvingSymlinksInPath().path }
            if current == "/" || current == home { return nil }
            current = (current as NSString).deletingLastPathComponent
        }
    }

    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// An entry allows argv when its words are a prefix of argv (first word compared by basename).
    public func allows(_ argv: [String]) -> Bool {
        guard !argv.isEmpty else { return false }
        let cmd = [(argv[0] as NSString).lastPathComponent] + argv.dropFirst()
        return allow.contains { entry in
            let words = entry.split(whereSeparator: \.isWhitespace).map(String.init)
            guard !words.isEmpty, words.count <= cmd.count else { return false }
            return zip(words, cmd).allSatisfy { $0 == $1 }
        }
    }
}
