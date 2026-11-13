import Foundation

public enum Policy {
    /// Commands that exist only to print the environment.
    static let envDumpers: Set<String> = ["env", "printenv", "export", "set", "declare"]

    /// Interpreters and the flags that make them evaluate inline code.
    static let inlineEval: [String: Set<String>] = [
        "sh": ["-c"], "bash": ["-c"], "zsh": ["-c"], "dash": ["-c"], "ksh": ["-c"], "fish": ["-c", "--command"],
        "python": ["-c"], "python3": ["-c"], "node": ["-e", "-p", "--eval", "--print"], "bun": ["-e", "--eval", "-p", "--print"],
        "deno": ["eval"], "ruby": ["-e"], "perl": ["-e", "-E"], "php": ["-r"], "osascript": ["-e"], "lua": ["-e"],
    ]

    /// Why an agent may not run `argv` under `sx run`, or nil when allowed.
    /// Humans are not restricted; output masking applies to everyone.
    public static func agentDenial(argv: [String]) -> String? {
        guard let first = argv.first else { return "empty command" }
        let base = (first as NSString).lastPathComponent
        let tool = base.hasPrefix("python3.") ? "python3" : base
        if envDumpers.contains(tool) { return "`\(tool)` only prints the environment" }
        if tool == "sx" { return "nested `sx` is not allowed" }
        if let flags = inlineEval[tool], argv.dropFirst().contains(where: { flags.contains($0) }) {
            return "inline code (`\(tool) \(argv.dropFirst().first(where: { flags.contains($0) }) ?? "")`) is not allowed"
        }
        return nil
    }
}
