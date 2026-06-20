// HTTP-date (RFC 9110 §5.6.7) formatting + parsing for `Last-Modified` / `If-Modified-Since`. Uses only
// Foundation's essentials-core value types — `Date` + a GMT `Calendar` for the gregorian date math
// (swift-foundation-backed + ICU-free on this toolchain) — paired with FIXED English weekday/month
// tables. The IMF-fixdate wire format is never localized, so a locale-aware formatter (`DateFormatter` /
// `Date.FormatStyle` with name symbols) would needlessly pull `FoundationInternationalization`/ICU; the
// tables give the exact required names with zero locale machinery. `Calendar` is a `Sendable` value type,
// so the cached GMT calendar is shared safely across the concurrent, off-loop static requests this serves.
//
// (NB: an explicit `import FoundationEssentials` would require adding the swiftlang/swift-foundation
// package, but its `release/6.4.x` pins swift-collections 1.1.6 — conflicting with ADTestKit's ≥1.6.0 — so
// the package is not resolvable here; the umbrella import below uses the same essentials types ICU-free.)

import Foundation

enum HTTPDate {
    private static let weekdayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]  // Calendar: 1 = Sun
    private static let monthNames = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]
    private static let utc: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "GMT")!
        return calendar
    }()

    /// `epochSeconds` (UTC) as an IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
    static func format(_ epochSeconds: Int) -> String {
        let date = Date(timeIntervalSince1970: Double(epochSeconds))
        let parts = utc.dateComponents(
            [.weekday, .day, .month, .year, .hour, .minute, .second], from: date)
        guard let weekday = parts.weekday, let day = parts.day, let month = parts.month,
            let year = parts.year, let hour = parts.hour, let minute = parts.minute,
            let second = parts.second
        else { return "" }
        return
            "\(weekdayNames[weekday - 1]), \(pad2(day)) \(monthNames[month - 1]) \(year) "
            + "\(pad2(hour)):\(pad2(minute)):\(pad2(second)) GMT"
    }

    /// Parse an HTTP-date to whole epoch seconds, or `nil`. Accepts the preferred IMF-fixdate; the
    /// obsolete RFC 850 / asctime forms are rare from real clients and intentionally not accepted.
    static func parse(_ string: String) -> Int? {
        // "Wed, 21 Oct 2015 07:28:00 GMT" → ["Wed,","21","Oct","2015","07:28:00","GMT"]
        let tokens = string.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard tokens.count >= 5,
            let day = Int(tokens[1]),
            let monthIndex = monthNames.firstIndex(of: String(tokens[2])),
            let year = Int(tokens[3])
        else { return nil }
        let time = tokens[4].split(separator: ":")
        guard time.count == 3, let hour = Int(time[0]), let minute = Int(time[1]), let second = Int(time[2])
        else { return nil }
        var components = DateComponents()
        components.year = year
        components.month = monthIndex + 1
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        guard let date = utc.date(from: components) else { return nil }
        return Int(date.timeIntervalSince1970.rounded(.down))
    }

    private static func pad2(_ value: Int) -> String { value < 10 ? "0\(value)" : "\(value)" }
}
