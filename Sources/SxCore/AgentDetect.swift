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
        // Orca runs every agent session under this helper (Orca → orca-provider-exec → claude/codex/…).
        ("orca-provider-exec", "Orca agent"),
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

    /// Name of the process's controlling terminal (e.g. `ttys004`), or nil when it has none.
    public static func controllingTTY(of pid: pid_t) -> String? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        let dev = info.kp_eproc.e_tdev
        guard dev != -1, let name = devname(dev, S_IFCHR) else { return nil }
        let s = String(cString: name)
        return s.isEmpty || s == "??" ? nil : s
    }

    /// Path of the file behind a process's descriptor (e.g. `/dev/ttys004` for a terminal), or nil
    /// for pipes, sockets and closed descriptors.
    public static func descriptorPath(of pid: pid_t, fd: Int32) -> String? {
        var info = vnode_fdinfowithpath()
        let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &info, size) == size else { return nil }
        let path = withUnsafeBytes(of: info.pvip.vip_path) { raw in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
        return path.isEmpty ? nil : path
    }

    /// Command-line arguments of another process run by the same user (KERN_PROCARGS2).
    public static func arguments(of pid: pid_t) -> [String]? {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0, argmax > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: Int(argmax))
        size = buf.count
        mib = [CTL_KERN, KERN_PROCARGS2, pid]
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        return parseProcArgs(Array(buf.prefix(size)))
    }

    /// Layout: int32 argc, executable path, NUL padding, then argc NUL-terminated strings.
    static func parseProcArgs(_ buf: [UInt8]) -> [String]? {
        guard buf.count >= 4 else { return nil }
        let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
        guard argc > 0, argc < 4096 else { return nil }
        var i = 4
        while i < buf.count, buf[i] != 0 { i += 1 } // executable path
        while i < buf.count, buf[i] == 0 { i += 1 } // padding
        var out: [String] = []
        while out.count < argc, i < buf.count {
            var j = i
            while j < buf.count, buf[j] != 0 { j += 1 }
            out.append(String(decoding: buf[i..<j], as: UTF8.self))
            i = j + 1
        }
        return out.count == argc ? out : nil
    }
}
