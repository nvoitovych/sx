import Foundation

public enum SX {
    public static let version = "0.2.1"
    public static let teamID = "37A7P47GPA"
    public static let appBundleID = "dev.nvlab.sx"
    public static let cliIdentifier = "dev.nvlab.sx.cli"
    public static let appGroup = "\(teamID).dev.nvlab.sx"
    public static let keychainAccessGroup = "\(teamID).dev.nvlab.sx"
    public static let keychainService = "dev.nvlab.sx"
    public static let refScheme = "sx://"
    public static let defaultEnvFile = ".env.sx"

    /// Code requirement the broker enforces on every client connection.
    public static let clientRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(cliIdentifier)\""

    /// Real home directory, even inside the app sandbox.
    public static var realHome: String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return String(cString: dir)
        }
        return NSHomeDirectory()
    }

    public static var groupContainer: String {
        "\(realHome)/Library/Group Containers/\(appGroup)"
    }

    public static var socketPath: String { "\(groupContainer)/broker.sock" }
    public static var sshAgentSocketPath: String { "\(groupContainer)/ssh-agent.sock" }
    public static let sshTag = "ssh"
    /// Names under this prefix are sx's own (e.g. stored Bitwarden sessions), never user secrets.
    public static let internalPrefix = "_sx/"
}
