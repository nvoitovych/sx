import AppKit
import ServiceManagement
import SwiftUI
import SxCore
import UniformTypeIdentifiers

/// AppKit-owned window so it can be opened from the delegate, the menu bar, and reopen events.
/// The app shows in the Dock only while this window is open.
final class MainWindow: NSObject, NSWindowDelegate {
    static let shared = MainWindow()
    private var window: NSWindow?

    func show() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 860, height: 560),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                             backing: .buffered, defer: false)
            w.title = "sx"
            w.titlebarAppearsTransparent = true
            w.isReleasedWhenClosed = false
            w.contentViewController = NSHostingController(rootView: MainView())
            w.setContentSize(NSSize(width: 860, height: 560))
            w.minSize = NSSize(width: 720, height: 460)
            w.center()
            w.setFrameAutosaveName("sx.main")
            w.delegate = self
            window = w
        }
        NSApp.setActivationPolicy(.regular)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }

    func windowWillClose(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
    }
}

final class SecretsModel: ObservableObject {
    static let shared = SecretsModel()
    @Published var secrets: [SecretInfo] = []
    @Published var error: String?

    func reload() {
        do {
            secrets = try KeychainStore.list()
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }
}

enum Pane: String, CaseIterable, Identifiable {
    case secrets = "Secrets", activity = "Activity", cli = "Command line", settings = "Settings"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .secrets: return "key"
        case .activity: return "list.bullet.rectangle"
        case .cli: return "terminal"
        case .settings: return "gearshape"
        }
    }
}

struct MainView: View {
    @State private var section: Pane? = .secrets

    var body: some View {
        NavigationSplitView {
            List(Pane.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.symbol).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            switch section ?? .secrets {
            case .secrets: SecretsView()
            case .activity: ActivityView()
            case .cli: CommandLineView()
            case .settings: SettingsView()
            }
        }
    }
}

// MARK: - Secrets

struct SecretsView: View {
    @ObservedObject private var model = SecretsModel.shared
    @State private var query = ""
    @State private var selection: String?
    @State private var showAdd = false
    @State private var showImport = false
    @State private var notice: String?

    private var filtered: [SecretInfo] {
        query.isEmpty ? model.secrets : model.secrets.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if model.secrets.isEmpty {
                EmptySecrets(add: { showAdd = true }, importEnv: { showImport = true })
            } else {
                Table(filtered, selection: $selection) {
                    TableColumn("Name") { s in Text(s.name).font(.system(.body, design: .monospaced)) }
                    TableColumn("Tags") { s in Text(s.tags.joined(separator: ", ")).foregroundStyle(.secondary) }.width(90)
                    TableColumn("Modified") { s in Text(s.modified?.formatted(date: .abbreviated, time: .shortened) ?? "—").foregroundStyle(.secondary) }.width(160)
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let name = ids.first {
                        Button("Copy reference  sx://\(name)") { copy("sx://\(name)") }
                        Button("Copy value (Touch ID, clears in 30 s)") { copyValue(name) }
                        Divider()
                        Button("Delete…", role: .destructive) { delete(name) }
                    }
                }
            }
            if let notice {
                Text(notice).font(.caption).foregroundStyle(.secondary).padding(8)
            }
            if let err = model.error {
                Text(err).font(.caption).foregroundStyle(.red).padding(8)
            }
        }
        .navigationTitle("Secrets")
        .searchable(text: $query, placement: .toolbar)
        .toolbar {
            Button { showImport = true } label: { Label("Import .env", systemImage: "square.and.arrow.down") }
            Button { showAdd = true } label: { Label("Add", systemImage: "plus") }
        }
        .sheet(isPresented: $showAdd) { AddSecretSheet { model.reload() } }
        .sheet(isPresented: $showImport) { ImportEnvSheet { msg in notice = msg; model.reload() } }
        .onAppear { model.reload() }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        notice = "Copied \(s)"
    }

    private func copyValue(_ name: String) {
        let card = ApprovalPanel.Request(title: "Copy a secret value?", who: "You (sx window)", command: nil,
                                         project: nil, secrets: [name], alwaysAsk: true)
        DispatchQueue.global().async {
            if let why = Approver.shared.authenticate(card, reason: "Copy \(name) to the clipboard") {
                DispatchQueue.main.async { notice = "Not copied: \(why)" }
                return
            }
            guard let data = try? KeychainStore.get(name), let str = String(data: data, encoding: .utf8) else {
                DispatchQueue.main.async { notice = "\(name) is binary; use `sx import-file` / `sx run --file`" }
                return
            }
            DispatchQueue.main.async {
                let pb = NSPasteboard.general
                pb.clearContents()
                pb.setString(str, forType: .string)
                let change = pb.changeCount
                notice = "Copied \(name). Clipboard clears in 30 s."
                AuditLog.shared.record(.init(time: Date(), op: "copy", client: "sx window", names: [name], outcome: "copied to clipboard"))
                DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                    if pb.changeCount == change { pb.clearContents() }
                }
            }
        }
    }

    private func delete(_ name: String) {
        let card = ApprovalPanel.Request(title: "Delete a secret?", who: "You (sx window)", command: nil,
                                         project: nil, secrets: [name], alwaysAsk: true)
        DispatchQueue.global().async {
            if let why = Approver.shared.authenticate(card, reason: "Delete secret \(name)") {
                DispatchQueue.main.async { notice = "Not deleted: \(why)" }
                return
            }
            try? KeychainStore.remove(name)
            AuditLog.shared.record(.init(time: Date(), op: "remove", client: "sx window", names: [name], outcome: "deleted"))
            DispatchQueue.main.async {
                notice = "Deleted \(name)"
                model.reload()
            }
        }
    }
}

struct EmptySecrets: View {
    let add: () -> Void
    let importEnv: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 96, height: 96)
            Text("No secrets yet").font(.title2.weight(.semibold))
            Text("Secrets live in your iCloud Keychain and sync to your other Macs.\nApps and agents get them only through `sx run`, after you approve.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            HStack {
                Button("Import a .env file…", action: importEnv)
                Button("Add a secret", action: add).buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

struct AddSecretSheet: View {
    var onDone: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var value = ""
    @State private var prod = false
    @State private var error: String?

    var body: some View {
        Form {
            TextField("Name", text: $name, prompt: Text("project/API_KEY"))
                .font(.system(.body, design: .monospaced))
            SecureField("Value", text: $value)
            Toggle("Production (Touch ID on every use)", isOn: $prod)
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
            Text("Reference it from `.env.sx` as  KEY=sx://\(name.isEmpty ? "project/API_KEY" : name)")
                .font(.caption).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) { Button("Save", action: save).disabled(name.isEmpty || value.isEmpty) }
        }
    }

    private func save() {
        guard SecretName.isValid(name) else {
            error = "Use letters, digits and ._-/ (e.g. reelifyads/OPENAI_KEY)"
            return
        }
        if KeychainStore.exists(name) {
            error = "\(name) already exists. Delete it first, or overwrite via `sx put` (asks Touch ID)."
            return
        }
        do {
            try KeychainStore.put(name, value: Data(value.utf8), tags: prod ? ["prod"] : [])
            AuditLog.shared.record(.init(time: Date(), op: "put", client: "sx window", names: [name], outcome: "stored"))
            value = ""
            onDone()
            dismiss()
        } catch {
            self.error = "\(error)"
        }
    }
}

struct ImportEnvSheet: View {
    var onDone: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var file: URL?
    @State private var prefix = ""
    @State private var removeOriginal = false
    @State private var error: String?

    var body: some View {
        Form {
            LabeledContent("File") {
                HStack {
                    Text(file?.path ?? "none").lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                    Button("Choose…", action: choose)
                }
            }
            TextField("Prefix", text: $prefix, prompt: Text("project name"))
            Toggle("Delete the original file after import", isOn: $removeOriginal)
            Text("Each value goes to the keychain as prefix/KEY. A `.env.sx` with references only is written next to the file — safe to commit and for agents to read.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) { Button("Import", action: run).disabled(file == nil || prefix.isEmpty) }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.showsHiddenFiles = true
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            file = url
            if prefix.isEmpty { prefix = url.deletingLastPathComponent().lastPathComponent }
        }
    }

    private func run() {
        guard let file, let text = try? String(contentsOf: file, encoding: .utf8) else {
            error = "Cannot read the file"
            return
        }
        guard SecretName.isValid(prefix) else {
            error = "Prefix: letters, digits and ._-/"
            return
        }
        let out = file.deletingLastPathComponent().appendingPathComponent(SX.defaultEnvFile)
        var existing = (try? String(contentsOf: out, encoding: .utf8)).map(EnvFile.parse) ?? []
        var imported: [String] = []
        var skipped: [String] = []
        for e in EnvFile.parse(text) {
            var entry = e
            if e.reference == nil, !e.value.isEmpty {
                let name = "\(prefix)/\(e.key)"
                if KeychainStore.exists(name) {
                    skipped.append(e.key)
                } else {
                    do {
                        try KeychainStore.put(name, value: Data(e.value.utf8), tags: [])
                        imported.append(name)
                    } catch {
                        self.error = "\(e.key): \(error)"
                        return
                    }
                }
                entry = EnvFile.Entry(key: e.key, value: SX.refScheme + name)
            }
            if let i = existing.firstIndex(where: { $0.key == entry.key }) { existing[i] = entry } else { existing.append(entry) }
        }
        do {
            try EnvFile.render(existing, header: "sx references only — safe to commit. Run: sx run -- <cmd>")
                .write(to: out, atomically: true, encoding: .utf8)
            if removeOriginal, skipped.isEmpty { try FileManager.default.removeItem(at: file) }
        } catch {
            self.error = "\(error)"
            return
        }
        AuditLog.shared.record(.init(time: Date(), op: "import", client: "sx window", names: imported, outcome: "stored"))
        var msg = "Imported \(imported.count) from \(file.lastPathComponent); wrote \(out.path)."
        if !skipped.isEmpty { msg += " Skipped existing: \(skipped.joined(separator: ", "))." }
        onDone(msg)
        dismiss()
    }
}

// MARK: - Activity

struct ActivityRow: View {
    let entry: AuditLog.Entry
    var compact = false

    private var bad: Bool { entry.outcome.hasPrefix("denied") || entry.outcome.hasPrefix("refused") || entry.outcome.hasPrefix("rejected") }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack {
                Text(entry.time.formatted(date: compact ? .omitted : .abbreviated, time: .shortened)).foregroundStyle(.secondary)
                Text(entry.op).fontWeight(.medium)
                Text(entry.outcome).foregroundStyle(bad ? .red : .primary).lineLimit(1)
            }.font(.caption)
            Text([entry.agent.map { "agent: \($0)" }, entry.command, entry.names.isEmpty ? nil : entry.names.joined(separator: ", ")]
                .compactMap { $0 }.joined(separator: " · "))
                .font(.caption2).foregroundStyle(.secondary).lineLimit(compact ? 1 : 2)
        }
    }
}

struct ActivityView: View {
    @ObservedObject private var audit = AuditLog.shared

    var body: some View {
        List {
            if audit.history.isEmpty { Text("No activity yet.").foregroundStyle(.secondary) }
            ForEach(audit.history) { ActivityRow(entry: $0) }
        }
        .navigationTitle("Activity")
        .toolbar {
            Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: audit.path)]) } label: {
                Label("Show log file", systemImage: "doc.text.magnifyingglass")
            }
        }
        .onAppear { audit.loadHistory() }
    }
}

// MARK: - Command line

struct CommandLineView: View {
    @State private var status = CLIInstaller.status()
    @State private var message: String?

    var body: some View {
        Form {
            Section("The `sx` command") {
                LabeledContent("Status") {
                    Text(status.description).foregroundStyle(status.isInstalled ? Color.green : Color.orange)
                }
                HStack {
                    Button(status.isInstalled ? "Reinstall in /usr/local/bin" : "Install in /usr/local/bin") {
                        message = CLIInstaller.install()
                        status = CLIInstaller.status()
                    }
                    Text("Creates a link to the copy inside sx.app, so updates of the app update the command.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let message { Text(message).font(.caption) }
            }
            Section("Quick start") {
                Snippet("sx import-env .env --prefix myapp --remove-original", "Move a .env into the keychain; writes .env.sx with references")
                Snippet("sx run -- npm run dev", "Run with secrets from .env.sx; values are masked in output")
                Snippet("sx put myapp/STRIPE_KEY --tag prod", "Add one secret (hidden prompt or stdin)")
                Snippet("sx import-file ~/.ssh/id_ed25519 --name ssh/id_ed25519", "Store a key file")
                Snippet("sx ls", "List names — values are never printed")
                Snippet("sx ssh import ~/.ssh/id_ed25519 && sx ssh setup --write", "SSH keys from the keychain; ssh asks sx to sign")
                Snippet("sx trust", "Approve this project's .sx.toml agent allowlist")
                Snippet("sx vaults", "Keychain, Bitwarden, 1Password and plugin vaults (~/.config/sx/config.toml)")
            }
            Section("With AI agents") {
                Text("When `sx` runs under Claude Code, Codex, Cursor and similar agents, it refuses commands that only print the environment (`env`, `printenv`, `sh -c`, `python -c` …), never disables masking, and every new command needs your approval in a card with Touch ID — unless a `.sx.toml` you trusted allows it.")
                    .font(.callout)
                Text("Limit: a program that legitimately receives a secret can still send it somewhere. Give agents development keys with narrow scopes; tag production secrets `prod`.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Command line")
        .onAppear { status = CLIInstaller.status() }
    }
}

struct Snippet: View {
    let code: String
    let note: String

    init(_ code: String, _ note: String) {
        self.code = code
        self.note = note
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(code).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(code, forType: .string)
                } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
            }
            Text(note).font(.caption).foregroundStyle(.secondary)
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @AppStorage("approvalHours") private var approvalHours = 8
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section("Approvals") {
                Picker("Remember an approved command for", selection: $approvalHours) {
                    Text("Ask every time").tag(0)
                    Text("1 hour").tag(1)
                    Text("8 hours").tag(8)
                    Text("24 hours").tag(24)
                }
                .onChange(of: approvalHours) { _, h in Approver.shared.ttl = TimeInterval(h) * 3600 }
                Button("Revoke all approvals now") { Approver.shared.revokeAll() }
                Text("Secrets tagged `prod` ask every time regardless.").font(.caption).foregroundStyle(.secondary)
            }
            Section("General") {
                Toggle("Open at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, on in
                        do {
                            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                            loginError = nil
                        } catch {
                            loginError = "\(error.localizedDescription)"
                        }
                    }
                if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
                Text("Not required: `sx` starts the app in the background when needed.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Storage") {
                LabeledContent("Where", value: "iCloud Keychain (syncs to Macs signed in to the same Apple Account)")
                LabeledContent("Access group", value: SX.keychainAccessGroup)
                LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
    }
}
