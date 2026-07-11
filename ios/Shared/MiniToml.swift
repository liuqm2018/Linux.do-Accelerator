import Foundation

/// A deliberately tiny TOML reader covering only what this project's config uses:
/// top-level `key = value` where value is a quoted string, bool, multi-line
/// string array, or an inline table of string=string. Not a general TOML parser.
enum MiniTomlValue {
    case string(String)
    case bool(Bool)
    case array([String])
    case table([String: String])

    var asString: String? { if case let .string(v) = self { return v }; return nil }
    var asBool: Bool? { if case let .bool(v) = self { return v }; return nil }
    var asStringArray: [String]? { if case let .array(v) = self { return v }; return nil }
    var asStringMap: [String: String]? { if case let .table(v) = self { return v }; return nil }
}

enum MiniTomlError: Error { case malformed(String) }

enum MiniToml {
    static func parse(_ text: String) throws -> [String: MiniTomlValue] {
        var result: [String: MiniTomlValue] = [:]
        // Join into logical statements, tolerating multi-line arrays.
        let statements = splitStatements(text)
        for statement in statements {
            guard let eq = statement.firstIndex(of: "=") else { continue }
            let key = unquote(String(statement[..<eq]).trimmingCharacters(in: .whitespaces))
            let rawValue = String(statement[statement.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if key.isEmpty || rawValue.isEmpty { continue }
            result[key] = try parseValue(rawValue)
        }
        return result
    }

    /// Splits into `key = value` chunks. A statement continues across newlines
    /// while inside `[ ]` or `{ }` so multi-line arrays stay together.
    private static func splitStatements(_ text: String) -> [String] {
        var statements: [String] = []
        var current = ""
        var depth = 0

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = stripComment(String(rawLine))
            for ch in line {
                if ch == "[" || ch == "{" { depth += 1 }
                if ch == "]" || ch == "}" { depth = max(0, depth - 1) }
            }
            if current.isEmpty {
                current = line
            } else {
                current += " " + line
            }
            if depth == 0 {
                let trimmed = current.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty { statements.append(trimmed) }
                current = ""
            }
        }
        let leftover = current.trimmingCharacters(in: .whitespaces)
        if !leftover.isEmpty { statements.append(leftover) }
        return statements
    }

    /// Removes `#` comments outside of quoted strings (single-line).
    private static func stripComment(_ line: String) -> String {
        var localInString = false
        var output = ""
        var previous: Character = " "
        for ch in line {
            if ch == "\"" && previous != "\\" { localInString.toggle() }
            if ch == "#" && !localInString { break }
            output.append(ch)
            previous = ch
        }
        return output
    }

    private static func parseValue(_ raw: String) throws -> MiniTomlValue {
        if raw == "true" { return .bool(true) }
        if raw == "false" { return .bool(false) }
        if raw.hasPrefix("\"") { return .string(unquote(raw)) }
        if raw.hasPrefix("[") { return .array(parseArray(raw)) }
        if raw.hasPrefix("{") { return .table(parseInlineTable(raw)) }
        // Bare token: treat as string.
        return .string(raw)
    }

    private static func parseArray(_ raw: String) -> [String] {
        let inner = raw.dropFirst().dropLast() // strip [ ]
        return splitTopLevel(String(inner), separator: ",")
            .map { unquote($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.isEmpty }
    }

    private static func parseInlineTable(_ raw: String) -> [String: String] {
        let inner = raw.dropFirst().dropLast() // strip { }
        var table: [String: String] = [:]
        for pair in splitTopLevel(String(inner), separator: ",") {
            guard let eq = pair.firstIndex(of: "=") else { continue }
            let k = unquote(String(pair[..<eq]).trimmingCharacters(in: .whitespaces))
            let v = unquote(String(pair[pair.index(after: eq)...]).trimmingCharacters(in: .whitespaces))
            if !k.isEmpty { table[k] = v }
        }
        return table
    }

    /// Splits on `separator` but ignores separators inside quotes.
    private static func splitTopLevel(_ text: String, separator: Character) -> [String] {
        var parts: [String] = []
        var current = ""
        var inString = false
        var previous: Character = " "
        for ch in text {
            if ch == "\"" && previous != "\\" { inString.toggle() }
            if ch == separator && !inString {
                parts.append(current)
                current = ""
            } else {
                current.append(ch)
            }
            previous = ch
        }
        if !current.trimmingCharacters(in: .whitespaces).isEmpty { parts.append(current) }
        return parts
    }

    private static func unquote(_ value: String) -> String {
        var v = value.trimmingCharacters(in: .whitespaces)
        if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
            v = String(v.dropFirst().dropLast())
            v = v.replacingOccurrences(of: "\\\"", with: "\"")
        }
        return v
    }
}
