import AppKit
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
        var alwaysAsk: Bool
        /// Shown as a countdown; the broker gives up (denies) at this time.
        var expires: Date?
        /// One plain sentence of context, e.g. where the keys go.
        var note: String?
        /// Hours a "remember" answer lasts; 0 hides that option.
        var rememberHours: Int = 0
    }

    enum Decision {
        case deny, once, remember
    }

    private static var current: NSPanel?

    static func dismiss() {
        current?.close()
        current = nil
    }

    static func show(_ request: Request, onAnswer: @escaping (Decision) -> Void) {
        current?.close()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 440, height: 240),
                            styleMask: [.titled, .fullSizeContentView, .utilityWindow],
                            backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        // isFloatingPanel resets the level to .floating, so set it first.
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]

        var answered = false
        let answer: (Decision) -> Void = { decision in
            guard !answered else { return }
            answered = true
            panel.close()
            current = nil
            onAnswer(decision)
        }
        panel.contentView = NSHostingView(rootView: ApprovalView(request: request, answer: answer))
        panel.setContentSize(panel.contentView!.fittingSize)
        if let screen = NSScreen.main {
            let f = screen.visibleFrame
            panel.setFrameTopLeftPoint(NSPoint(x: f.maxX - panel.frame.width - 16, y: f.maxY - 16))
        }
        panel.orderFrontRegardless()
        NSSound(named: "Glass")?.play()
        current = panel
    }
}

extension ApprovalPanel {
    /// The card as a plain view (for screenshots).
    static func preview(_ request: Request) -> some View {
        ApprovalView(request: request, answer: { _ in })
            .background(.background)
    }
}

private struct ApprovalView: View {
    let request: ApprovalPanel.Request
    let answer: (ApprovalPanel.Decision) -> Void

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
                        label("Keys")
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

            HStack(spacing: 6) {
                if request.alwaysAsk {
                    Label("Production key — asks every time", systemImage: "exclamationmark.shield.fill").foregroundStyle(.orange)
                }
                Spacer(minLength: 0)
                if let expires = request.expires {
                    Text("Denied automatically in")
                    Text(timerInterval: Date()...expires, countsDown: true).monospacedDigit()
                }
            }
            .font(.caption).foregroundStyle(.secondary)

            // Esc denies; Return does nothing, so a stray keypress never approves.
            HStack {
                Button("Deny", role: .cancel) { answer(.deny) }
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.large)
                Spacer()
                if request.rememberHours > 0 && !request.alwaysAsk {
                    Button("Allow for \(request.rememberHours) h") { answer(.remember) }
                        .controlSize(.large)
                }
                Button { answer(.once) } label: { Label("Allow once", systemImage: "touchid") }
                    .buttonStyle(AccentButtonStyle())
            }
        }
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
