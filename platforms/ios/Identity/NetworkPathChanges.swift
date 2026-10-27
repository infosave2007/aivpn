import Foundation

/// Изменение запасного интерфейса не прерывает работающий туннель.
struct NetworkPathChanges {
    private var previous: (satisfied: Bool, primary: String?)?

    mutating func update(satisfied: Bool, interfaces: [String]) -> Bool {
        let current = (satisfied: satisfied, primary: interfaces.first)
        defer { previous = current }
        guard let old = previous, satisfied else { return false }
        return !old.satisfied || current.primary != old.primary
    }
}
