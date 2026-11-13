import AppKit
import SwiftUI
import SxCore

/// `Sx --snapshot DIR`: renders marketing screenshots of the app's own windows with demo data.
/// No keychain access, no sockets, no screen-recording permission (an app may image its own views).
enum Snapshot {
    static var isActive: Bool { CommandLine.arguments.contains("--snapshot") }

    static var outputDir: String? {
        guard let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count else { return nil }
        return CommandLine.arguments[i + 1]
    }

    static let demoSecrets: [SecretInfo] = [
        SecretInfo(name: "myapp/OPENAI_KEY", tags: [], modified: Date().addingTimeInterval(-3600 * 26)),
        SecretInfo(name: "myapp/STRIPE_KEY", tags: ["prod"], modified: Date().addingTimeInterval(-3600 * 26)),
        SecretInfo(name: "myapp/DATABASE_URL", tags: [], modified: Date().addingTimeInterval(-3600 * 50)),
        SecretInfo(name: "cloudflare/API_TOKEN", tags: [], modified: Date().addingTimeInterval(-3600 * 120)),
        SecretInfo(name: "ssh/id_ed25519", tags: ["ssh"], modified: Date().addingTimeInterval(-3600 * 300)),
        SecretInfo(name: "github/RELEASE_TOKEN", tags: ["prod"], modified: Date().addingTimeInterval(-3600 * 400)),
    ]

    static var demoLastUsed: [String: Date] {
        ["myapp/OPENAI_KEY": Date().addingTimeInterval(-120), "myapp/DATABASE_URL": Date().addingTimeInterval(-120),
         "ssh/id_ed25519": Date().addingTimeInterval(-540), "cloudflare/API_TOKEN": Date().addingTimeInterval(-3600 * 26)]
    }

    static var demoGrants: [Approver.Grant] {
        [Approver.Grant(id: "1", who: "Claude Code", command: "npm run dev", names: ["myapp/OPENAI_KEY", "myapp/DATABASE_URL"],
                        until: Date().addingTimeInterval(3600 * 7.5))]
    }

    static var demoActivity: [AuditLog.Entry] {
        let now = Date()
        func e(_ mins: Double, _ op: String, _ agent: String?, _ cmd: String, _ names: [String], _ outcome: String) -> AuditLog.Entry {
            .init(time: now.addingTimeInterval(-mins * 60), op: op, client: "sx", agent: agent, command: cmd, cwd: "~/code/myapp", names: names, outcome: outcome)
        }
        return [
            e(2, "resolve", "Claude Code", "npm run dev", ["myapp/OPENAI_KEY", "myapp/DATABASE_URL"], "released (allowed by .sx.toml)"),
            e(3, "resolve", "Claude Code", "printenv OPENAI_KEY", ["myapp/OPENAI_KEY"], "refused: `printenv` only prints the environment"),
            e(9, "ssh-sign", "Claude Code", "ssh ← git ← claude", ["ssh/id_ed25519"], "signed"),
            e(15, "resolve", nil, "npm test", ["myapp/OPENAI_KEY"], "released"),
            e(42, "resolve", "Cursor", "wrangler deploy", ["cloudflare/API_TOKEN", "myapp/STRIPE_KEY"], "denied: denied by user"),
        ]
    }

    @MainActor static func run() {
        guard let dir = outputDir else { exit(2) }
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        SecretsModel.shared.secrets = demoSecrets
        AuditLog.shared.setDemo(demoActivity)

        for (appearance, suffix) in [(NSAppearance.Name.darkAqua, "dark"), (.aqua, "light")] {
            NSApp.appearance = NSAppearance(named: appearance)
            // Vibrant materials (sidebar, toolbar) do not image off-screen, so the window is recomposed
            // from the app's real views on solid backgrounds.
            render(Framed { ShotWindow(selected: .secrets) { ShotSecrets() } }, size: nil, titled: false, to: "\(dir)/secrets-\(suffix).png")
            render(Framed { ShotWindow(selected: .activity) { ShotActivity() } }, size: nil, titled: false, to: "\(dir)/activity-\(suffix).png")
            render(Framed { ShotWindow(selected: .cli) { CommandLineView() } }, size: nil, titled: false, to: "\(dir)/cli-\(suffix).png")
            render(Framed { ShotWindow(selected: .settings) { SettingsView() } }, size: nil, titled: false, to: "\(dir)/settings-\(suffix).png")
            render(Framed { TagEditorSheet(secret: demoSecrets[1], onDone: { _ in })
                .background(Color(nsColor: .windowBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 12)) },
                   size: nil, titled: false, to: "\(dir)/tags-\(suffix).png")
            let card = ApprovalPanel.Request(title: "wants to use 2 keys", who: "Claude Code", isAgent: true, command: "npm run deploy",
                                             project: "~/code/myapp", secrets: ["myapp/STRIPE_KEY", "cloudflare/API_TOKEN"], alwaysAsk: false,
                                             expires: Date().addingTimeInterval(118),
                                             note: "Keys go to this command only. Its output is masked.", rememberHours: 8)
            render(Framed { ApprovalPanel.preview(card).clipShape(RoundedRectangle(cornerRadius: 14)) }, size: nil, titled: false,
                   to: "\(dir)/approval-\(suffix).png")
        }
        exit(0)
    }

    /// Lays the view out in an off-screen window, lets SwiftUI settle, then images the window's content.
    @MainActor private static func render<V: View>(_ view: V, size: NSSize?, titled: Bool, to path: String) {
        let host = NSHostingView(rootView: view)
        let target = size ?? host.fittingSize
        let window = NSWindow(contentRect: NSRect(origin: NSPoint(x: -20000, y: -20000), size: target),
                              styleMask: titled ? [.titled, .fullSizeContentView] : [.borderless], backing: .buffered, defer: false)
        window.isOpaque = false
        window.backgroundColor = .clear
        window.titlebarAppearsTransparent = true
        window.contentView = host
        window.setContentSize(target)
        window.orderFrontRegardless()
        RunLoop.main.run(until: Date().addingTimeInterval(1.2))
        guard let frameView = window.contentView?.superview ?? window.contentView,
              let rep = frameView.bitmapImageRepForCachingDisplay(in: frameView.bounds) else { return }
        frameView.cacheDisplay(in: frameView.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        window.orderOut(nil)
    }
}

/// Transparent margin + soft shadow, like a window on a page.
private struct Framed<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .shadow(color: .black.opacity(0.35), radius: 22, y: 10)
            .padding(36)
    }
}

private struct ShotWindow<Content: View>: View {
    let selected: Pane
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                ForEach([Color.red, .yellow, .green], id: \.self) { Circle().fill($0.opacity(0.85)).frame(width: 12, height: 12) }
                Spacer()
            }
            .padding(.horizontal, 14).frame(height: 38)
            .background(Color(nsColor: .windowBackgroundColor))
            HStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Pane.allCases) { pane in
                        Label(pane.rawValue, systemImage: pane.symbol)
                            .padding(.horizontal, 10).padding(.vertical, 6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(pane == selected ? Color.accentColor.opacity(0.28) : .clear, in: RoundedRectangle(cornerRadius: 6))
                    }
                    Spacer()
                }
                .padding(10).frame(width: 190)
                .background(Color(nsColor: .windowBackgroundColor))
                Divider()
                content.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .clipped()
                    .background(Color(nsColor: .textBackgroundColor))
            }
        }
        .frame(width: 820, height: 470)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.12)))
    }
}

private struct ShotSecrets: View {
    @State private var selection: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ShotHeader(title: "Secrets") {
                Label("Import .env", systemImage: "square.and.arrow.down")
                Image(systemName: "plus")
            }
            SecretsTable(secrets: Snapshot.demoSecrets, lastUsed: Snapshot.demoLastUsed, selection: $selection)
        }
    }
}

private struct ShotActivity: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ShotHeader(title: "Activity") { Image(systemName: "doc.text.magnifyingglass") }
            VStack(alignment: .leading, spacing: 8) {
                Text("Remembered approvals").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(Snapshot.demoGrants) { GrantRow(grant: $0, onRevoke: {}) }
                Text("Today").font(.caption.weight(.semibold)).foregroundStyle(.secondary).padding(.top, 6)
                ForEach(Snapshot.demoActivity.prefix(3)) { ActivityRow(entry: $0) }
            }
            .padding(.horizontal, 16)
        }
    }
}

/// Title row with the toolbar items the real window shows (the real toolbar is a vibrant material).
private struct ShotHeader<Items: View>: View {
    let title: String
    @ViewBuilder var items: Items

    var body: some View {
        HStack(spacing: 14) {
            Text(title).font(.title2.weight(.semibold))
            Spacer()
            HStack(spacing: 14) { items }.foregroundStyle(.secondary)
            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass")
                Text("Search")
                Spacer()
            }
            .foregroundStyle(.tertiary).font(.callout)
            .padding(.horizontal, 8).frame(width: 150, height: 26)
            .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
        }
        .padding([.top, .horizontal], 16)
    }
}
