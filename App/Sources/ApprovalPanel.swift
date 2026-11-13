import AppKit
import SwiftUI

/// Floating request card. macOS will not let a background app pop a Touch ID prompt on its own
/// (cooperative activation cancels it with -4); the user's click on Approve activates the app first.
@MainActor
final class ApprovalPanel {
    struct Request {
        var title: String
        var who: String
        var command: String?
        var project: String?
        var secrets: [String]
        var alwaysAsk: Bool
    }

    private static var current: NSPanel?

    static func dismiss() {
        current?.close()
        current = nil
    }

    static func show(_ request: Request, onAnswer: @escaping (Bool) -> Void) {
        current?.close()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 420, height: 220),
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
        let answer: (Bool) -> Void = { ok in
            guard !answered else { return }
            answered = true
            panel.close()
            current = nil
            onAnswer(ok)
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

private struct ApprovalView: View {
    let request: ApprovalPanel.Request
    let answer: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(request.title, systemImage: "key.horizontal.fill").font(.headline)
            row("Who", request.who)
            if let c = request.command { row("Command", c, mono: true) }
            if let p = request.project { row("Project", p, mono: true) }
            if !request.secrets.isEmpty { row("Secrets", request.secrets.joined(separator: ", "), mono: true) }
            Text(request.alwaysAsk ? "Asks every time (prod or destructive)." : "Approval is remembered for 8 hours for this exact command.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Deny") { answer(false) }.keyboardShortcut(.cancelAction)
                Button("Approve with Touch ID") { answer(true) }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 420)
    }

    private func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(k).font(.caption).foregroundStyle(.secondary).frame(width: 64, alignment: .leading)
            Text(v).font(mono ? .system(.caption, design: .monospaced) : .caption).textSelection(.enabled).lineLimit(3)
        }
    }
}
