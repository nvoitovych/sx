import Foundation

public enum SocketError: Error, CustomStringConvertible {
    case system(String, Int32)
    case pathTooLong(String)

    public var description: String {
        switch self {
        case let .system(call, err): return "\(call): \(String(cString: strerror(err)))"
        case let .pathTooLong(path): return "socket path too long: \(path)"
        }
    }
}

public enum UnixSocket {
    static func address(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { throw SocketError.pathTooLong(path) }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            bytes.withUnsafeBytes { buf.copyMemory(from: $0) }
        }
        return addr
    }

    public static func connect(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket", errno) }
        var addr = try address(path)
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) }
        }
        guard rc == 0 else {
            let err = errno
            close(fd)
            throw SocketError.system("connect", err)
        }
        return fd
    }

    public static func listen(_ path: String) throws -> Int32 {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket", errno) }
        var addr = try address(path)
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard rc == 0 else {
            let err = errno
            close(fd)
            throw SocketError.system("bind", err)
        }
        chmod(path, 0o600)
        guard Darwin.listen(fd, 16) == 0 else { throw SocketError.system("listen", errno) }
        return fd
    }

    public static func writeAll(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { raw in
            while offset < data.count {
                let n = write(fd, raw.baseAddress! + offset, data.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw SocketError.system("write", errno)
                }
                offset += n
            }
        }
    }

    /// Reads until a newline or EOF; requests and responses are single JSON lines.
    public static func readLine(_ fd: Int32, limit: Int = 16 << 20) throws -> Data {
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 16384)
        while data.count < limit {
            let n = read(fd, &buf, buf.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw SocketError.system("read", errno)
            }
            if n == 0 { break }
            data.append(buf, count: n)
            if buf[n - 1] == 0x0A { break }
        }
        return data
    }
}
