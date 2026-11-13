import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Floating request card. macOS will not let a background app pop a Touch ID prompt on its own
/// (cooperative activation cancels it with -4); the user's click on Approve activates the app first.
@MainActor
final class ApprovalPanel {
    struct Request {
        var title: String
        /// Who asks, e.g. "Claude Code" or "Terminal".
        var who: String
        var isAgent = false
        var command: String?
        var project: String?
        var secrets: [String]
        /// No "remember" option: asked every single time (deletes, exports, prod keys…).
        var alwaysAsk: Bool
        /// Shown as a warning only when the key itself is tagged prod.
        var isProduction = false
        /// Shown as a countdown; the broker gives up (denies) at this time.
        var expires: Date?
        /// One plain sentence of context, e.g. where the keys go.
        var note: String?
        /// Hours a "remember" answer lasts; 0 hides that option.
        var rememberHours: Int = 0
    }

    enum Outcome {
        case denied
        case approved(remember: Bool)
        case failed(String)
    }

    private static var current: NSPanel?
    private static var currentAuth: CardAuth?

    static func dismiss() {
        currentAuth?.invalidate()
        current?.close()
        current = nil
        currentAuth = nil
    }

    static func show(_ request: Request, reason: String, onOutcome: @escaping (Outcome) -> Void) {
        current?.close()
        // Non-activating, like Spotlight: it can appear inside another app's full-screen Space and
        // take keys (Esc) without activating sx or switching Spaces.
        let panel = ApprovalWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 240),
                                   styleMask: [.nonactivatingPanel, .titled, .fullSizeContentView],
                                   backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.standardWindowButton(.closeButton)?.isHidden = true
        panel.standardWindowButton(.miniaturizeButton)?.isHidden = true
        panel.standardWindowButton(.zoomButton)?.isHidden = true
        // isFloatingPanel resets the level, so set it first. Above full-screen windows and the Dock.
        panel.isFloatingPanel = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]

        let auth = CardAuth(reason: reason, interactive: true)
        var answered = false
        auth.finish = { outcome in
            guard !answered else { return }
            answered = true
            auth.invalidate()
            panel.close()
            if current === panel { current = nil; currentAuth = nil }
            onOutcome(outcome)
        }
        // The hidden title bar would otherwise push the content down by its height.
        panel.contentView = NSHostingView(rootView: ApprovalView(request: request, auth: auth).ignoresSafeArea())
        currentAuth = auth
        panel.setContentSize(panel.contentView!.fittingSize)
        let f = activeScreen().visibleFrame
        panel.setFrameTopLeftPoint(NSPoint(x: f.maxX - panel.frame.width - 16, y: f.maxY - 16))
        panel.orderFrontRegardless()
        panel.makeKey()
        NSSound(named: "Glass")?.play()
        current = panel
    }

    /// The screen the user is working on: under the pointer (NSScreen.main follows sx's own key window).
    static func activeScreen() -> NSScreen {
        let mouse = NSEvent.mouseLocation
        return NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) } ?? NSScreen.main ?? NSScreen.screens[0]
    }
}

/// A non-activating panel only takes keyboard focus if it says it can.
final class ApprovalWindow: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

extension ApprovalPanel {
    /// The card as a plain view (for screenshots).
    static func preview(_ request: Request) -> some View {
        ApprovalView(request: request, auth: CardAuth(reason: "", interactive: false))
            .background(.background)
    }
}

/// Owns the LAContext for one card. With Touch ID the card itself shows the sensor prompt
/// (LAAuthenticationView), so a touch approves right away — no click, no system dialog.
/// Without biometrics, "Use password" falls back to the system dialog (needs sx active).
final class CardAuth: ObservableObject {
    let reason: String
    let interactive: Bool
    let context = LAContext()
    var finish: (ApprovalPanel.Outcome) -> Void = { _ in }
    @Published var remember = false
    @Published var biometricsReady = false
    @Published var hint: String?

    init(reason: String, interactive: Bool) {
        self.reason = reason
        self.interactive = interactive
        var error: NSError?
        biometricsReady = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func start() {
        guard interactive, biometricsReady else { return }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, err in
            DispatchQueue.main.async {
                if ok { return self.finish(.approved(remember: self.remember)) }
                switch (err as? LAError)?.code {
                case .userFallback?:
                    self.usePassword()
                case .userCancel?, .appCancel?:
                    break // card closed or denied elsewhere
                default:
                    self.biometricsReady = false
                    self.hint = "Touch ID isn't available here — use your password."
                }
            }
        }
    }

    /// System dialog with password / Apple Watch. The click on the card is a user action, so activation is allowed.
    func usePassword() {
        guard interactive else { return }
        context.invalidate()
        let ctx = LAContext()
        NSApp.activate()
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
            DispatchQueue.main.async {
                if ok { self.finish(.approved(remember: self.remember)) }
                else { self.finish(.failed((err as NSError?).map { "\($0.localizedDescription) (\($0.code))" } ?? "denied")) }
            }
        }
    }

    func invalidate() { context.invalidate() }
}

private struct TouchIDView: NSViewRepresentable {
    let context: LAContext

    /// `.small` draws at 32×32 (`.regular` is 64 and spills out of a smaller frame).
    func makeNSView(context ctx: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: self.context, controlSize: .small)
        view.wantsLayer = true
        view.layer?.masksToBounds = true
        return view
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: LAAuthenticationView, context: Context) -> CGSize? {
        CGSize(width: 32, height: 32)
    }

    func updateNSView(_ view: LAAuthenticationView, context ctx: Context) {}
}

private struct ApprovalView: View {
    let request: ApprovalPanel.Request
    @ObservedObject var auth: CardAuth

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Header: unmistakably sx (anti-spoofing), then the question in plain words.
            HStack(alignment: .top, spacing: 12) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(request.who).font(.headline)
                        if request.isAgent {
                            Text("AI agent").font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Color.purple.opacity(0.22), in: Capsule())
                        }
                    }
                    Text(request.title).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Text("sx").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }

            VStack(alignment: .leading, spacing: 8) {
                if let command = request.command { field("Runs", command) }
                if let project = request.project { field("In", abbreviate(project)) }
                if !request.secrets.isEmpty {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        label(request.secrets.count == 1 ? "Key" : "Keys")
                        FlowChips(items: request.secrets)
                    }
                }
                if let note = request.note {
                    Text(note).font(.caption).foregroundStyle(.secondary).padding(.top, 2)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))

            if request.rememberHours > 0 && !request.alwaysAsk {
                Picker("", selection: $auth.remember) {
                    Text("Allow once").tag(false)
                    Text("Allow for \(request.rememberHours) h").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden()
            }

            HStack(spacing: 6) {
                if request.isProduction {
                    Label("Production key — asks every time", systemImage: "exclamationmark.shield.fill").foregroundStyle(.orange)
                } else if let hint = auth.hint {
                    Text(hint)
                }
                Spacer(minLength: 0)
                if let expires = request.expires {
                    Text("Denied automatically in")
                    Text(timerInterval: Date()...expires, countsDown: true).monospacedDigit()
                }
            }
            .font(.caption).foregroundStyle(.secondary)

            // Esc denies; Return does nothing, so a stray keypress never approves.
            HStack(alignment: .center, spacing: 12) {
                Button("Deny", role: .cancel) { auth.finish(.denied) }
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.large)
                Spacer()
                if auth.biometricsReady {
                    HStack(spacing: 10) {
                        if auth.interactive {
                            TouchIDView(context: auth.context).frame(width: 32, height: 32)
                        } else {
                            Image(systemName: "touchid").font(.system(size: 26)).foregroundStyle(Color.accentColor)
                                .frame(width: 32, height: 32)
                        }
                        VStack(alignment: .leading, spacing: 1) {
                            Text("Touch ID to allow").font(.callout.weight(.semibold))
                            Button("or use password") { auth.usePassword() }
                                .buttonStyle(.link).font(.caption)
                        }
                    }
                } else {
                    Button { auth.usePassword() } label: { Label("Allow", systemImage: "lock.open.fill") }
                        .buttonStyle(AccentButtonStyle())
                }
            }
        }
        .onAppear { auth.start() }
        .padding(18)
        .frame(width: 440)
    }

    private func label(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.secondary).frame(width: 40, alignment: .leading)
    }

    private func field(_ k: String, _ v: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            label(k)
            Text(v).font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(3)
        }
    }

    private func abbreviate(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }
}

/// Secret names as compact monospaced chips, wrapping to new lines.
struct FlowChips: View {
    let items: [String]

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(items, id: \.self) { item in
                Text(item).font(.system(.caption, design: .monospaced))
                    .padding(.horizontal, 7).padding(.vertical, 3)
                    .background(Color.accentColor.opacity(0.16), in: RoundedRectangle(cornerRadius: 5))
            }
        }
    }
}

struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 360
        var x: CGFloat = 0, y: CGFloat = 0, row: CGFloat = 0, maxX: CGFloat = 0
        for s in subviews {
            let size = s.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                x = 0
                y += row + spacing
                row = 0
            }
            x += size.width + spacing
            maxX = max(maxX, x - spacing)
            row = max(row, size.height)
        }
        return CGSize(width: min(maxX, width), height: y + row)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, row: CGFloat = 0
        for s in subviews {
            let size = s.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                x = bounds.minX
                y += row + spacing
                row = 0
            }
            s.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            row = max(row, size.height)
        }
    }
}

/// Filled accent button that stays colored in an inactive panel (system prominent buttons turn gray there,
/// and the approval card appears without becoming key).
struct AccentButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 14).padding(.vertical, 7)
            .background(Color.accentColor.opacity(configuration.isPressed ? 0.75 : 1), in: RoundedRectangle(cornerRadius: 8))
    }
}
