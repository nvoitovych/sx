import Foundation
import SxCore

/// The `sx` command ships inside the app (Contents/Helpers/sx); installing it means linking it into PATH.
enum CLIInstaller {
    static let linkPath = "/usr/local/bin/sx"

    static var bundled: String { Bundle.main.bundlePath + "/Contents/Helpers/sx" }

    enum Status: CustomStringConvertible {
        case installed(String), other(String), missing, notBundled

        var isInstalled: Bool { if case .installed = self { return true } else { return false } }

        /// One plain line for the UI; paths shown with ~.
        var detail: String {
            switch self {
            case let .installed(p): return "Linked at \(CLIInstaller.tilde(p)). Updates come with the app."
            case let .other(p): return "Another sx is at \(CLIInstaller.tilde(p)). Install links /usr/local/bin/sx to this app."
            case .missing: return "Links /usr/local/bin/sx to the copy inside the app. Asks for your password once."
            case .notBundled: return "This build has no bundled command."
            }
        }

        var description: String {
            switch self {
            case let .installed(p): return "Installed at \(p)"
            case let .other(p): return "A different sx is at \(p)"
            case .missing: return "Not installed"
            case .notBundled: return "This build has no bundled CLI"
            }
        }
    }

    static func tilde(_ path: String) -> String {
        path.hasPrefix(SX.realHome) ? "~" + path.dropFirst(SX.realHome.count) : path
    }

    static func status() -> Status {
        if Snapshot.isActive { return .installed(SX.realHome + "/.local/bin/sx") }
        guard FileManager.default.isExecutableFile(atPath: bundled) else { return .notBundled }
        for path in [linkPath, SX.realHome + "/.local/bin/sx", "/opt/homebrew/bin/sx"] {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let resolved = (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) ?? path
            // A link into any Sx.app counts: it follows that app's updates.
            return resolved == bundled || resolved.hasSuffix("/Sx.app/Contents/Helpers/sx") ? .installed(path) : .other(path)
        }
        return .missing
    }

    /// Creates /usr/local/bin/sx → bundled helper, asking for an administrator password.
    static func install() -> String {
        guard FileManager.default.isExecutableFile(atPath: bundled) else { return "No bundled CLI in this build." }
        let cmd = "mkdir -p /usr/local/bin && ln -sf '\(bundled)' '\(linkPath)'"
        let script = "do shell script \"\(cmd)\" with administrator privileges with prompt \"sx wants to install the sx command in /usr/local/bin.\""
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        if let error { return "Not installed: \(error[NSAppleScript.errorMessage] ?? "cancelled")" }
        return "Installed. Open a new terminal and run `sx status`."
    }
}
