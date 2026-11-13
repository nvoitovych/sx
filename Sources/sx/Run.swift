import Foundation
import SxCore

/// `sx run`: resolve references, spawn the command with secrets in its environment,
/// and mask secret values in its output.
enum Run {
    struct Options {
        var envFiles: [String] = []
        var inline: [EnvFile.Entry] = []
        var mask = true
        var argv: [String] = []
    }

    static func parse(_ args: [String]) throws -> Options {
        var o = Options()
        var i = 0
        while i < args.count {
            let a = args[i]
            switch a {
            case "--":
                o.argv = Array(args[(i + 1)...])
                i = args.count
                continue
            case "--env-file", "-f":
                guard i + 1 < args.count else { throw CLIError("\(a) needs a path") }
                o.envFiles.append(args[i + 1])
                i += 1
            case "--env", "-e":
                guard i + 1 < args.count, let entry = EnvFile.parse(args[i + 1]).first else { throw CLIError("\(a) needs KEY=sx://name") }
                guard entry.reference != nil else { throw CLIError("--env accepts only references (KEY=sx://name), never values") }
                o.inline.append(entry)
                i += 1
            case "--no-mask":
                o.mask = false
            default:
                if a.hasPrefix("-") { throw CLIError("unknown option \(a)") }
                o.argv = Array(args[i...])
                i = args.count
                continue
            }
            i += 1
        }
        guard !o.argv.isEmpty else { throw CLIError("usage: sx run [--env-file F] [--env K=sx://name] -- command [args]") }
        if o.envFiles.isEmpty, FileManager.default.fileExists(atPath: SX.defaultEnvFile) {
            o.envFiles = [SX.defaultEnvFile]
        }
        return o
    }

    static func execute(_ args: [String]) throws -> Int32 {
        let o = try parse(args)
        let agent = AgentDetect.detect()
        if let agent {
            if let why = Policy.agentDenial(argv: o.argv) { throw CLIError("refused for \(agent): \(why)", code: 126) }
            if !o.mask { throw CLIError("refused for \(agent): --no-mask is human-only", code: 126) }
        }

        var entries: [EnvFile.Entry] = []
        for path in o.envFiles {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { throw CLIError("cannot read \(path)") }
            entries += EnvFile.parse(text)
        }
        entries += o.inline

        let cwd = FileManager.default.currentDirectoryPath
        let resolved = try Resolver.resolve(entries: entries, argv: o.argv, cwd: cwd, agent: agent)
        var env = ProcessInfo.processInfo.environment
        for e in entries where e.reference == nil { env[e.key] = e.value }
        var secrets: [String: Data] = [:]
        for (key, data) in resolved {
            guard let str = String(data: data, encoding: .utf8) else { throw CLIError("\(key) is binary; it cannot go into an environment variable") }
            env[key] = str
            secrets[key] = data
        }
        return try spawn(o.argv, env: env, redactor: o.mask ? secrets : nil)
    }

    static func spawn(_ argv: [String], env: [String: String], redactor secrets: [String: Data]?) throws -> Int32 {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }

        var outPipe: [Int32] = [-1, -1]
        var errPipe: [Int32] = [-1, -1]
        let masking = secrets.map { !$0.isEmpty } ?? false
        if masking {
            guard pipe(&outPipe) == 0, pipe(&errPipe) == 0 else { throw CLIError("pipe failed") }
            posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO)
            posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO)
            for fd in outPipe + errPipe { posix_spawn_file_actions_addclose(&actions, fd) }
        }

        let cArgs = argv.map { strdup($0) } + [nil]
        let cEnv = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            cArgs.forEach { free($0) }
            cEnv.forEach { free($0) }
        }

        var pid: pid_t = 0
        let rc = posix_spawnp(&pid, argv[0], &actions, nil, cArgs, cEnv)
        guard rc == 0 else { throw CLIError("\(argv[0]): \(String(cString: strerror(rc)))", code: 127) }

        for sig in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
            src.setEventHandler { kill(pid, sig) }
            src.resume()
            Forwarders.keep.append(src)
        }

        var pumps: [Thread] = []
        if masking, let secrets {
            close(outPipe[1])
            close(errPipe[1])
            pumps = [pump(from: outPipe[0], to: STDOUT_FILENO, secrets: secrets),
                     pump(from: errPipe[0], to: STDERR_FILENO, secrets: secrets)]
        }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        for t in pumps { while !t.isFinished { usleep(5_000) } }

        if status & 0x7f == 0 { return (status >> 8) & 0xff }
        return 128 + (status & 0x7f)
    }

    private static func pump(from src: Int32, to dst: Int32, secrets: [String: Data]) -> Thread {
        let t = Thread {
            let redactor = Redactor(secrets: secrets)
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = read(src, &buf, buf.count)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                try? UnixSocket.writeAll(dst, redactor.feed(Data(buf[0..<n])))
            }
            try? UnixSocket.writeAll(dst, redactor.finish())
            close(src)
        }
        t.start()
        return t
    }
}

enum Forwarders {
    static var keep: [DispatchSourceSignal] = []
}
