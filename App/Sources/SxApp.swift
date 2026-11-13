import AppKit
import SwiftUI
import SxCore

@main
struct SxApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuContent()
        } label: {
            Image("MenuIcon")
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // A client that exits mid-request must not take the broker down with SIGPIPE.
        signal(SIGPIPE, SIG_IGN)
        if Snapshot.isActive {
            Snapshot.run()
            return
        }
        Broker.shared.start()
        SSHAgent.shared.start()
        // `sx` starts the app with --background when it only needs the broker.
        if !CommandLine.arguments.contains("--background") {
            MainWindow.shared.show()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        MainWindow.shared.show()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

/// Compact menu bar popover: status, recent access, shortcuts into the main window.
struct MenuContent: View {
    @ObservedObject private var audit = AuditLog.shared
    @ObservedObject private var store = SecretsModel.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 22, height: 22)
                Text("sx").font(.headline)
                Spacer()
                Text("\(store.secrets.count) secrets").font(.caption).foregroundStyle(.secondary)
            }
            if let err = Broker.shared.startError {
                Text("Broker: \(err)").font(.caption).foregroundStyle(.red)
            }
            Divider()
            Text("Recent access").font(.caption).foregroundStyle(.secondary)
            if audit.recent.isEmpty {
                Text("Nothing since launch").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(audit.recent.prefix(5)) { e in ActivityRow(entry: e, compact: true) }
            Divider()
            HStack {
                Button("Open sx…") { MainWindow.shared.show() }
                Spacer()
                Button("Revoke approvals") { Approver.shared.revokeAll() }
                Button("Quit") { NSApp.terminate(nil) }
            }
        }
        .padding(12)
        .frame(width: 340)
        .onAppear { store.reload() }
    }
}
