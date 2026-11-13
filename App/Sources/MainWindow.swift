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
        if Snapshot.isActive { return }
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
    @State private var section: Pane?

    init(initial: Pane = .secrets) {
        _section = State(initialValue: initial)
    }

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
    @ObservedObject private var audit = AuditLog.shared
    @State private var query = ""
    @State private var selection: String?
    @State private var showAdd = false
    @State private var showImport = false
    @State private var editingTags: SecretInfo?
    @State private var notice: String?

    private var filtered: [SecretInfo] {
        query.isEmpty ? model.secrets : model.secrets.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if model.secrets.isEmpty {
                EmptySecrets(add: { showAdd = true }, importEnv: { showImport = true })
            } else {
                SecretsTable(secrets: filtered, lastUsed: audit.lastUsed, selection: $selection)
                .contextMenu(forSelectionType: String.self) { ids in
                    if let name = ids.first {
                        Button("Edit tags…") { editingTags = model.secrets.first { $0.name == name } }
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
        .sheet(item: $editingTags) { secret in
            TagEditorSheet(secret: secret) { msg in notice = msg; model.reload() }
        }
        .onAppear {
            model.reload()
            audit.loadHistory()
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        notice = "Copied \(s)"
    }

    private func copyValue(_ name: String) {
        let card = ApprovalPanel.Request(title: "Copy the value to the clipboard?", who: "You", command: nil,
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
        let card = ApprovalPanel.Request(title: "Delete this key?", who: "You", command: nil,
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

/// Name with a muted project prefix, tags as badges, and when an agent or command last used it.
struct SecretsTable: View {
    let secrets: [SecretInfo]
    let lastUsed: [String: Date]
    @Binding var selection: String?

    var body: some View {
        Table(secrets, selection: $selection) {
            TableColumn("Name") { s in SecretNameText(name: s.name) }
            TableColumn("Tags") { s in
                HStack(spacing: 4) { ForEach(s.tags, id: \.self) { TagBadge(tag: $0) } }
            }.width(90)
            TableColumn("Last used") { s in
                if let d = lastUsed[s.name] {
                    Text(d, format: .relative(presentation: .named)).foregroundStyle(.secondary)
                } else {
                    Text("never").foregroundStyle(.tertiary)
                }
            }.width(120)
        }
        .alternatingRowBackgrounds(.disabled)
    }
}

struct SecretNameText: View {
    let name: String

    var body: some View {
        let cut = name.lastIndex(of: "/").map { name.index(after: $0) } ?? name.startIndex
        (Text(name[..<cut]).foregroundStyle(.secondary) + Text(name[cut...]))
            .font(.system(.body, design: .monospaced))
    }
}

struct TagBadge: View {
    let tag: String

    var body: some View {
        let color: Color = tag == "prod" ? .orange : tag == "ssh" ? .blue : .gray
        Text(tag).font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.16), in: Capsule())
    }
}

/// Add or remove tags. Dropping `prod` weakens protection, so it needs Touch ID; everything else does not.
struct TagEditorSheet: View {
    let secret: SecretInfo
    var onDone: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var tags: [String] = []
    @State private var newTag = ""
    @State private var busy = false
    @State private var error: String?

    static let suggested = ["prod", "ssh", "legacy", "dev"]
    static let hints = ["prod": "Touch ID every time", "ssh": "offered by the SSH agent", "legacy": "old, kept just in case", "dev": "development key"]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Tags").font(.headline)
            SecretNameText(name: secret.name)

            VStack(alignment: .leading, spacing: 6) {
                ForEach(Self.suggested, id: \.self) { tag in
                    Toggle(isOn: Binding(get: { tags.contains(tag) }, set: { on in toggle(tag, on) })) {
                        HStack(spacing: 6) {
                            TagBadge(tag: tag)
                            Text(Self.hints[tag] ?? "").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }

            let custom = tags.filter { !Self.suggested.contains($0) }
            if !custom.isEmpty {
                HStack(spacing: 6) {
                    ForEach(custom, id: \.self) { tag in
                        Button { toggle(tag, false) } label: {
                            HStack(spacing: 3) { TagBadge(tag: tag); Image(systemName: "xmark").font(.caption2) }
                        }.buttonStyle(.plain)
                    }
                }
            }
            HStack {
                TextField("New tag", text: $newTag).onSubmit(addCustom).frame(maxWidth: 200)
                Button("Add", action: addCustom).disabled(!Self.isValid(newTag))
            }
            if let error { Text(error).font(.caption).foregroundStyle(.red) }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save", action: save).keyboardShortcut(.defaultAction).disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 380)
        .onAppear { tags = secret.tags }
    }

    static func isValid(_ t: String) -> Bool {
        let t = t.trimmingCharacters(in: .whitespaces).lowercased()
        return !t.isEmpty && t.count <= 24 && t.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    }

    private func toggle(_ tag: String, _ on: Bool) {
        if on { if !tags.contains(tag) { tags.append(tag) } } else { tags.removeAll { $0 == tag } }
    }

    private func addCustom() {
        let t = newTag.trimmingCharacters(in: .whitespaces).lowercased()
        guard Self.isValid(t) else { return }
        toggle(t, true)
        newTag = ""
    }

    private func save() {
        let final = tags
        let name = secret.name
        let downgrade = secret.tags.contains("prod") && !final.contains("prod")
        busy = true
        DispatchQueue.global().async {
            if downgrade {
                let card = ApprovalPanel.Request(title: "Remove the prod tag?", who: "You", command: nil, project: nil,
                                                 secrets: [name], alwaysAsk: true,
                                                 note: "Without it, an approved command can reuse this key for hours.")
                if let why = Approver.shared.authenticate(card, reason: "Remove prod from \(name)") {
                    DispatchQueue.main.async { error = "Not changed: \(why)"; busy = false }
                    return
                }
            }
            do {
                try KeychainStore.setTags(name, final)
                AuditLog.shared.record(.init(time: Date(), op: "tags", client: "sx window", names: [name],
                                             outcome: "tagged \(final.isEmpty ? "(none)" : final.joined(separator: ", "))"))
                DispatchQueue.main.async { onDone("Tags of \(name): \(final.isEmpty ? "none" : final.joined(separator: ", "))"); dismiss() }
            } catch {
                DispatchQueue.main.async { self.error = "\(error)"; busy = false }
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

/// Plain-language label, icon and color for an audit outcome.
struct OutcomeStyle {
    let label: String
    let detail: String?
    let symbol: String
    let color: Color

    init(_ outcome: String) {
        func after(_ prefix: String) -> String? {
            guard outcome.hasPrefix(prefix) else { return nil }
            let rest = outcome.dropFirst(prefix.count).trimmingCharacters(in: CharacterSet(charactersIn: ": "))
            return rest.isEmpty ? nil : rest.replacingOccurrences(of: "`", with: "")
        }
        switch true {
        case outcome.hasPrefix("released") && outcome.contains(".sx.toml"):
            (label, detail, symbol, color) = ("Allowed", "by project rules", "checkmark.circle.fill", .green)
        case outcome.hasPrefix("released"):
            (label, detail, symbol, color) = ("Allowed", nil, "checkmark.circle.fill", .green)
        case outcome == "signed":
            (label, detail, symbol, color) = ("Signed", nil, "checkmark.circle.fill", .green)
        case outcome.hasPrefix("refused"):
            (label, detail, symbol, color) = ("Blocked", after("refused"), "hand.raised.fill", .red)
        case outcome.contains("denied by user"):
            (label, detail, symbol, color) = ("Denied by you", nil, "xmark.circle.fill", .orange)
        case outcome.contains("timed out"):
            (label, detail, symbol, color) = ("Not answered", "auto-denied", "clock.badge.xmark", .orange)
        case outcome.hasPrefix("denied"):
            (label, detail, symbol, color) = ("Denied", after("denied"), "xmark.circle.fill", .orange)
        case outcome == "stored":
            (label, detail, symbol, color) = ("Saved", nil, "tray.and.arrow.down.fill", .blue)
        case outcome == "deleted":
            (label, detail, symbol, color) = ("Deleted", nil, "trash.fill", .secondary)
        case outcome.hasPrefix("trusted"):
            (label, detail, symbol, color) = ("Project rules trusted", after("trusted"), "checkmark.shield.fill", .green)
        case outcome.hasPrefix("rejected"):
            (label, detail, symbol, color) = ("Unknown program refused", after("rejected"), "exclamationmark.octagon.fill", .red)
        case outcome.hasPrefix("tagged"):
            (label, detail, symbol, color) = ("Tags changed", after("tagged"), "tag.fill", .blue)
        case outcome.hasPrefix("exported"):
            (label, detail, symbol, color) = ("Exported by you", "to a file", "square.and.arrow.up.fill", .blue)
        case outcome.hasPrefix("copied"):
            (label, detail, symbol, color) = ("Copied by you", nil, "doc.on.doc.fill", .blue)
        default:
            (label, detail, symbol, color) = (outcome.prefix(1).uppercased() + outcome.dropFirst(), nil, "circle", .secondary)
        }
    }
}

struct AgentBadge: View {
    let name: String

    var body: some View {
        Text(name).font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Color.purple.opacity(0.2), in: Capsule())
    }
}

struct ActivityRow: View {
    let entry: AuditLog.Entry
    var compact = false

    var body: some View {
        let style = OutcomeStyle(entry.outcome)
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: style.symbol).foregroundStyle(style.color).font(compact ? .caption : .body)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(style.label).fontWeight(.semibold)
                    if let d = style.detail { Text(d).foregroundStyle(.secondary).lineLimit(1) }
                    Spacer(minLength: 8)
                    Text(entry.time.formatted(date: .omitted, time: .shortened)).foregroundStyle(.secondary).monospacedDigit()
                }
                .font(compact ? .caption : .callout)
                HStack(spacing: 6) {
                    if let agent = entry.agent { AgentBadge(name: agent) }
                    if let cmd = entry.command { Text(cmd).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1) }
                }
                if !entry.names.isEmpty {
                    if compact {
                        Text(entry.names.joined(separator: ", ")).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                    } else {
                        FlowChips(items: entry.names)
                    }
                }
            }
        }
        .padding(.vertical, compact ? 0 : 4)
    }
}

struct GrantRow: View {
    let grant: Approver.Grant
    var onRevoke: (() -> Void)?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "clock.fill").foregroundStyle(.blue)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(grant.who).fontWeight(.semibold)
                    Text(grant.command).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
                FlowChips(items: grant.names)
            }
            Spacer()
            Text("until \(grant.until.formatted(date: .omitted, time: .shortened))").font(.caption).foregroundStyle(.secondary)
            if let onRevoke { Button("Revoke", action: onRevoke) }
        }
        .padding(.vertical, 4)
    }
}

enum DayGroups {
    static func group(_ entries: [AuditLog.Entry]) -> [(title: String, entries: [AuditLog.Entry])] {
        let cal = Calendar.current
        var out: [(String, [AuditLog.Entry])] = []
        for e in entries {
            let title = cal.isDateInToday(e.time) ? "Today" : cal.isDateInYesterday(e.time) ? "Yesterday"
                : e.time.formatted(date: .abbreviated, time: .omitted)
            if out.last?.0 == title { out[out.count - 1].1.append(e) } else { out.append((title, [e])) }
        }
        return out
    }
}

struct ActivityView: View {
    @ObservedObject private var audit = AuditLog.shared
    @State private var grants = Approver.shared.active

    var body: some View {
        List {
            if !grants.isEmpty {
                Section {
                    ForEach(grants) { g in
                        GrantRow(grant: g) { Approver.shared.revoke(g.id) }
                    }
                } header: {
                    HStack {
                        Text("Remembered approvals")
                        Spacer()
                        Button("Revoke all") { Approver.shared.revokeAll() }.buttonStyle(.link)
                    }
                }
            }
            if audit.history.isEmpty { Text("No activity yet.").foregroundStyle(.secondary) }
            ForEach(DayGroups.group(audit.history), id: \.title) { day in
                Section(day.title) {
                    ForEach(day.entries) { ActivityRow(entry: $0) }
                }
            }
        }
        .navigationTitle("Activity")
        .toolbar {
            Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: audit.path)]) } label: {
                Label("Show log file", systemImage: "doc.text.magnifyingglass")
            }
        }
        .onAppear {
            audit.loadHistory()
            grants = Approver.shared.active
        }
        .onReceive(NotificationCenter.default.publisher(for: Approver.changed)) { _ in grants = Approver.shared.active }
    }
}

// MARK: - Command line

struct CommandLineView: View {
    @State private var status = CLIInstaller.status()
    @State private var message: String?

    private static let groups: [(title: String, items: [(String, String)])] = [
        ("Start", [
            ("sx import-env .env --prefix myapp", "Move a .env into the keychain. Writes .env.sx with names only."),
            ("sx run -- npm run dev", "Run with the keys from .env.sx. Values are masked in output."),
            ("sx run --file .dev.vars -- wrangler dev", "For tools that read a file: it exists only while the command runs."),
        ]),
        ("Keys and files", [
            ("sx put myapp/STRIPE_KEY --tag prod", "Add one key. Production keys ask for Touch ID every time."),
            ("sx import-file AuthKey.p8 --name apple/asc", "Store any file: signing keys, certificates."),
            ("sx export apple/asc --out AuthKey.p8", "Put a file back on disk. You only, with Touch ID."),
            ("sx ls", "List names. Values are never printed."),
        ]),
        ("SSH", [
            ("sx ssh import ~/.ssh/id_ed25519", "Keep the key in the keychain instead of a file."),
            ("sx ssh setup --write", "Point ssh and git at the sx agent."),
        ]),
        ("Projects and vaults", [
            ("sx trust", "Approve the commands this project's .sx.toml lets agents run."),
            ("sx vaults", "Which vault (Keychain, Bitwarden, 1Password) this folder uses."),
        ]),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                statusCard
                ForEach(Self.groups, id: \.title) { group in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(group.title).font(.headline)
                        ForEach(group.items, id: \.0) { CommandRow(code: $0.0, note: $0.1) }
                    }
                }
                agentsCard
            }
            .padding(20)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .navigationTitle("Command line")
        .onAppear { status = CLIInstaller.status() }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: status.isInstalled ? "checkmark.circle.fill" : "terminal.fill")
                    .font(.title2).foregroundStyle(status.isInstalled ? Color.green : Color.accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(status.isInstalled ? "The sx command is installed" : "Install the sx command").font(.headline)
                    Text(status.detail).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if status.isInstalled {
                    Button("Reinstall") { install() }
                } else {
                    Button("Install") { install() }.buttonStyle(AccentButtonStyle())
                }
            }
            if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
        }
        .padding(14)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12))
    }

    private var agentsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("With AI agents").font(.headline)
            Label("Commands that only print keys — env, printenv, sh -c, python -c — are refused.", systemImage: "hand.raised.fill")
            Label("Output masking can't be turned off.", systemImage: "eye.slash.fill")
            Label("Each new command needs your Touch ID, unless a trusted .sx.toml allows it.", systemImage: "touchid")
            Text("A program that gets a key can still leak it. Give agents development keys.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .font(.callout)
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.purple.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private func install() {
        message = CLIInstaller.install()
        status = CLIInstaller.status()
    }
}

/// A command in a code block with a copy button that confirms.
struct CommandRow: View {
    let code: String
    let note: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(code).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button(copied ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(code, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                }
                .buttonStyle(.borderless).font(.caption.weight(.semibold))
                .foregroundStyle(copied ? Color.green : Color.secondary)
            }
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            Text(note).font(.caption).foregroundStyle(.secondary).padding(.leading, 2)
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
