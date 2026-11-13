import Foundation

/// Detects whether the current process runs under an AI coding agent.
/// Process ancestry is the primary signal: an agent can unset env vars but cannot rename its parents.
public enum AgentDetect {
    static let envMarkers: [(String, String)] = [
        ("CLAUDECODE", "Claude Code"), ("CLAUDE_CODE_ENTRYPOINT", "Claude Code"),
        ("CURSOR_AGENT", "Cursor"), ("CODEX_SANDBOX", "Codex"), ("CODEX_MANAGED_BY_NPM", "Codex"),
        ("GEMINI_CLI", "Gemini CLI"), ("AIDER_MODEL", "Aider"),
    ]

    static let processMarkers: [(String, String)] = [
        ("claude", "Claude Code"), ("codex", "Codex"), ("cursor-agent", "Cursor"),
        ("gemini", "Gemini CLI"), ("aider", "Aider"), ("opencode", "OpenCode"), ("amp", "Amp"),
    ]

    public static func detect(env: [String: String] = ProcessInfo.processInfo.environment) -> String? {
        for (key, name) in envMarkers where env[key] != nil { return name }
        return detect(ancestors: ancestry())
    }

    /// Agent driving another process (e.g. the `ssh` client talking to the sx SSH agent).
    public static func detect(pid: pid_t) -> String? {
        detect(ancestors: ancestry(from: pid))
    }

    static func detect(ancestors: [String]) -> String? {
        for ancestor in ancestors {
            let lower = ancestor.lowercased()
            let base = (lower as NSString).lastPathComponent
            for (marker, name) in processMarkers where base == marker || base.hasPrefix(marker + "-") || lower.contains("/\(marker)/") {
                return name
            }
        }
        return nil
    }

    /// Executable paths (or names) of all ancestors, nearest first.
    public static func ancestry(from pid: pid_t = getppid()) -> [String] {
        var out: [String] = []
        var current = pid
        var seen = Set<pid_t>()
        while current > 1, !seen.contains(current), out.count < 64 {
            seen.insert(current)
            out.append(executable(of: current) ?? "?")
            guard let parent = parentPID(of: current) else { break }
            current = parent
        }
        return out
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return info.kp_eproc.e_ppid
    }

    static func executable(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        if n > 0 { return String(cString: buf) }
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
        return withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
    }
}
