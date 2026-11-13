// Renders sx brand assets: app icon (macOS grid), menu bar template, DMG background, favicons.
// Usage: swift design/render.swift <out-dir>
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "design/out"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func color(_ hex: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

func save(_ rep: NSBitmapImageRep, _ name: String) {
    let data = rep.representation(using: .png, properties: [:])!
    try! data.write(to: URL(fileURLWithPath: "\(out)/\(name)"))
}

func canvas(_ w: Int, _ h: Int, _ draw: (CGContext) -> Void) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(NSGraphicsContext.current!.cgContext)
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

/// Superellipse ("squircle") like the macOS icon body.
func squircle(_ r: CGRect, n: CGFloat = 5) -> CGPath {
    let p = CGMutablePath()
    let a = r.width / 2, b = r.height / 2, cx = r.midX, cy = r.midY
    let steps = 720
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let c = cos(t), s = sin(t)
        let x = cx + a * (c >= 0 ? 1 : -1) * pow(abs(c), 2 / n)
        let y = cy + b * (s >= 0 ? 1 : -1) * pow(abs(s), 2 / n)
        i == 0 ? p.move(to: CGPoint(x: x, y: y)) : p.addLine(to: CGPoint(x: x, y: y))
    }
    p.closeSubpath()
    return p
}

/// The mark: a prompt chevron `›` and an underscore that is a key blade with two teeth.
/// Coordinates are in a 1024 design space; `t` maps them to the target.
struct Mark {
    var chevron: CGPath
    var blade: CGPath
    var teeth: CGPath

    init(_ t: CGAffineTransform) {
        let dx: CGFloat = -18, dy: CGFloat = 37
        let c = CGMutablePath()
        c.move(to: CGPoint(x: 330 + dx, y: 620 + dy))
        c.addLine(to: CGPoint(x: 470 + dx, y: 512 + dy))
        c.addLine(to: CGPoint(x: 330 + dx, y: 404 + dy))
        chevron = c.copy(using: [t])!

        let bl = CGMutablePath()
        bl.move(to: CGPoint(x: 540 + dx, y: 404 + dy))
        bl.addLine(to: CGPoint(x: 728 + dx, y: 404 + dy))
        blade = bl.copy(using: [t])!

        let th = CGMutablePath()
        th.addRoundedRect(in: CGRect(x: 618 + dx, y: 318 + dy, width: 40, height: 90), cornerWidth: 14, cornerHeight: 14)
        th.addRoundedRect(in: CGRect(x: 684 + dx, y: 340 + dy, width: 40, height: 68), cornerWidth: 14, cornerHeight: 14)
        teeth = th.copy(using: [t])!
    }
}

func drawMark(_ ctx: CGContext, _ t: CGAffineTransform, scale: CGFloat, mono: NSColor? = nil) {
    let m = Mark(t)
    let w = 64 * scale
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.setLineWidth(w)

    // Chevron
    ctx.saveGState()
    if mono == nil { ctx.setShadow(offset: CGSize(width: 0, height: -6 * scale), blur: 18 * scale, color: color(0x05061A, 0.45).cgColor) }
    ctx.addPath(m.chevron)
    ctx.setStrokeColor((mono ?? color(0xF5F6FF)).cgColor)
    ctx.strokePath()
    ctx.restoreGState()

    // Key blade + teeth (amber gradient)
    ctx.saveGState()
    let bladeOutline = m.blade.copy(strokingWithWidth: w, lineCap: .round, lineJoin: .round, miterLimit: 10)
    let shape = CGMutablePath()
    shape.addPath(bladeOutline)
    shape.addPath(m.teeth)
    if let mono {
        ctx.setFillColor(mono.cgColor)
        for part in [bladeOutline, m.teeth] {
            ctx.addPath(part)
            ctx.fillPath()
        }
    } else {
        ctx.setShadow(offset: CGSize(width: 0, height: -6 * scale), blur: 18 * scale, color: color(0x05061A, 0.45).cgColor)
        ctx.beginTransparencyLayer(auxiliaryInfo: nil)
        let box = shape.boundingBox
        let g = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                           colors: [color(0xFFD978).cgColor, color(0xFF9F3D).cgColor] as CFArray, locations: [0, 1])!
        // Fill each part on its own: overlapping subpaths with opposite winding would punch holes.
        for part in [bladeOutline, m.teeth] {
            ctx.saveGState()
            ctx.addPath(part)
            ctx.clip()
            ctx.drawLinearGradient(g, start: CGPoint(x: box.minX, y: box.maxY), end: CGPoint(x: box.maxX, y: box.minY), options: [])
            ctx.restoreGState()
        }
        ctx.endTransparencyLayer()
    }
    ctx.restoreGState()
}

func drawIcon(_ ctx: CGContext, size: CGFloat) {
    let s = size / 1024
    let body = CGRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let path = squircle(body)

    // Drop shadow under the body (part of the macOS icon grid).
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 * s), blur: 28 * s, color: NSColor(white: 0, alpha: 0.35).cgColor)
    ctx.addPath(path)
    ctx.setFillColor(color(0x15173D).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()
    let space = CGColorSpaceCreateDeviceRGB()
    let bg = CGGradient(colorsSpace: space, colors: [color(0x4A4FC4).cgColor, color(0x262A78).cgColor, color(0x101233).cgColor] as CFArray,
                        locations: [0, 0.45, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: body.minX, y: body.maxY), end: CGPoint(x: body.maxX, y: body.minY), options: [])
    let glow = CGGradient(colorsSpace: space, colors: [color(0xA9B1FF, 0.40).cgColor, color(0xA9B1FF, 0).cgColor] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: CGPoint(x: body.minX + 230 * s, y: body.maxY - 170 * s), startRadius: 0,
                           endCenter: CGPoint(x: body.minX + 230 * s, y: body.maxY - 170 * s), endRadius: 560 * s, options: [])
    // Glass sheen on the top half.
    let sheen = CGGradient(colorsSpace: space, colors: [NSColor(white: 1, alpha: 0.16).cgColor, NSColor(white: 1, alpha: 0).cgColor] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(sheen, start: CGPoint(x: 0, y: body.maxY), end: CGPoint(x: 0, y: body.midY + 40 * s), options: [])
    ctx.restoreGState()

    // Hairline rim.
    ctx.saveGState()
    ctx.addPath(path)
    ctx.setStrokeColor(NSColor(white: 1, alpha: 0.18).cgColor)
    ctx.setLineWidth(max(1, 3 * s))
    ctx.strokePath()
    ctx.restoreGState()

    drawMark(ctx, CGAffineTransform(scaleX: s, y: s), scale: s)
}

// App icon sizes for AppIcon.appiconset.
let iconSet = "\(out)/AppIcon.appiconset"
try? FileManager.default.createDirectory(atPath: iconSet, withIntermediateDirectories: true)
var images: [[String: String]] = []
for (pt, scales) in [(16, [1, 2]), (32, [1, 2]), (128, [1, 2]), (256, [1, 2]), (512, [1, 2])] {
    for sc in scales {
        let px = pt * sc
        let name = "icon_\(pt)x\(pt)\(sc == 2 ? "@2x" : "").png"
        let rep = canvas(px, px) { drawIcon($0, size: CGFloat(px)) }
        let data = rep.representation(using: .png, properties: [:])!
        try! data.write(to: URL(fileURLWithPath: "\(iconSet)/\(name)"))
        images.append(["idiom": "mac", "size": "\(pt)x\(pt)", "scale": "\(sc)x", "filename": name])
    }
}
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
try! JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
    .write(to: URL(fileURLWithPath: "\(iconSet)/Contents.json"))

save(canvas(1024, 1024) { drawIcon($0, size: 1024) }, "sx-icon-1024.png")
save(canvas(256, 256) { drawIcon($0, size: 256) }, "sx-app-icon.png")
save(canvas(64, 64) { drawIcon($0, size: 64) }, "sx-favicon.png")
save(canvas(32, 32) { drawIcon($0, size: 32) }, "sx-favicon-32.png")

// Menu bar template: the mark alone, black on transparent, cropped to the glyph.
for (px, name) in [(18, "MenuIcon.png"), (36, "MenuIcon@2x.png")] {
    let rep = canvas(px, px) { ctx in
        // Glyph bounds in design space incl. stroke: x 280...760, y 318...689.
        let s = CGFloat(px) / 480
        let t = CGAffineTransform(translationX: -280 * s, y: -318 * s + (CGFloat(px) - 371 * s) / 2).scaledBy(x: s, y: s)
        drawMark(ctx, t, scale: s, mono: .black)
    }
    save(rep, name)
}

// DMG background 660x400 @1x and @2x.
for (sc, name) in [(1, "dmg-background.png"), (2, "dmg-background@2x.png")] {
    let w = 660 * sc, h = 400 * sc
    let rep = canvas(w, h) { ctx in
        let S = CGFloat(sc)
        let space = CGColorSpaceCreateDeviceRGB()
        let bg = CGGradient(colorsSpace: space, colors: [color(0x1D2060).cgColor, color(0x0D0F2B).cgColor] as CFArray, locations: [0, 1])!
        ctx.drawLinearGradient(bg, start: CGPoint(x: 0, y: CGFloat(h)), end: CGPoint(x: CGFloat(w), y: 0), options: [])
        let glow = CGGradient(colorsSpace: space, colors: [color(0x8C95FF, 0.22).cgColor, color(0x8C95FF, 0).cgColor] as CFArray, locations: [0, 1])!
        ctx.drawRadialGradient(glow, startCenter: CGPoint(x: 160 * S, y: 330 * S), startRadius: 0,
                               endCenter: CGPoint(x: 160 * S, y: 330 * S), endRadius: 420 * S, options: [])
        // Arrow between the app (x=165) and Applications (x=495) icon centers, y=200 from top.
        let y = CGFloat(h) - 200 * S
        ctx.setStrokeColor(NSColor(white: 1, alpha: 0.55).cgColor)
        ctx.setLineWidth(5 * S)
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)
        ctx.move(to: CGPoint(x: 262 * S, y: y))
        ctx.addLine(to: CGPoint(x: 392 * S, y: y))
        ctx.move(to: CGPoint(x: 372 * S, y: y + 18 * S))
        ctx.addLine(to: CGPoint(x: 394 * S, y: y))
        ctx.addLine(to: CGPoint(x: 372 * S, y: y - 18 * S))
        ctx.strokePath()
        let para = NSMutableParagraphStyle()
        para.alignment = .center
        let title: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 17 * S, weight: .semibold),
                                                    .foregroundColor: NSColor(white: 1, alpha: 0.92), .paragraphStyle: para]
        let sub: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 12.5 * S, weight: .regular),
                                                  .foregroundColor: NSColor(white: 1, alpha: 0.6), .paragraphStyle: para]
        NSAttributedString(string: "Drag sx to Applications", attributes: title)
            .draw(in: CGRect(x: 0, y: 64 * S, width: CGFloat(w), height: 28 * S))
        NSAttributedString(string: "Then open it once. It lives in the menu bar; the `sx` command comes with it.", attributes: sub)
            .draw(in: CGRect(x: 0, y: 38 * S, width: CGFloat(w), height: 22 * S))
    }
    save(rep, name)
}
print("rendered to \(out)")
