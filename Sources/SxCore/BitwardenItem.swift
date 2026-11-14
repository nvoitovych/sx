import Foundation

/// The item `bw create item` takes for a secret sx writes. A value of several lines (a key, a
/// certificate) is a secure note; one line is a login holding only the password. `about` goes into a
/// text field and never into the note, so reading the item back returns exactly the value.
public enum BitwardenItem {
    public static func make(name: String, value: String, about: String?,
                            organizationId: String?, collectionId: String?) -> [String: Any] {
        var item: [String: Any] = ["name": name, "favorite": false, "reprompt": 0]
        if value.contains("\n") {
            item["type"] = 2
            item["secureNote"] = ["type": 0]
            item["notes"] = value
        } else {
            item["type"] = 1
            item["login"] = ["password": value]
        }
        if let about, !about.isEmpty { item["fields"] = [["name": "about", "value": about, "type": 0]] }
        if let organizationId { item["organizationId"] = organizationId }
        if let collectionId { item["collectionIds"] = [collectionId] }
        return item
    }

    /// The entry of `bw list …` (organizations, collections) whose name or id is `wanted`; exactly one.
    public static func pick(_ wanted: String, from entries: [[String: Any]], kind: String) throws -> String {
        let hits = entries.filter { $0["name"] as? String == wanted || $0["id"] as? String == wanted }
        guard hits.count == 1, let id = hits[0]["id"] as? String else {
            let names = entries.compactMap { $0["name"] as? String }.sorted().joined(separator: ", ")
            throw ConfigError(hits.isEmpty ? "no \(kind) \(wanted); known: \(names)" : "\(kind) \(wanted) is ambiguous; use its id")
        }
        return id
    }
}
