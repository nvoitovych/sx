import Foundation

/// Text from a requester (command lines, directory names, host aliases, process names) shown to the
/// person who approves. It must not be able to move the cursor, erase lines, reorder text or hide
/// characters, or a preview could show `npm test` for `curl … | sh`.
public enum DisplayText {
    /// Escapes C0/C1 controls, DEL and invisible or reordering Unicode (bidi overrides, zero-width,
    /// other format characters) as `\u{…}`.
    public static func safe(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            let v = scalar.value
            let control = v < 0x20 || v == 0x7F || (0x80...0x9F).contains(v)
            let invisible = scalar.properties.generalCategory == .format
                || scalar.properties.generalCategory == .lineSeparator
                || scalar.properties.generalCategory == .paragraphSeparator
                || (0xFE00...0xFE0F).contains(v) || (0xE0100...0xE01EF).contains(v) // variation selectors
            if control || invisible {
                out += "\\u{\(String(v, radix: 16))}"
            } else if scalar == "\\" {
                out += "\\\\"
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// A command line as a shell would need it typed, so `["npm test"]` and `["npm", "test"]` differ.
    public static func shellQuoted(_ argv: [String]) -> String {
        // Escape each argument first, then quote: the quoting's own `'\''` must stay as typed.
        argv.map(safe).map { arg in
            let plain = !arg.isEmpty && arg.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.contains($0) && $0.isASCII || "@%+=:,./_-".unicodeScalars.contains($0)
            }
            return plain ? arg : "'" + arg.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }
}
