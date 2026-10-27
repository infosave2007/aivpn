import Foundation

enum DeviceIdentityError: Error {
    case invalidKey
}

// Чтение, генерация и сохранение разделены для проверки отказов хранилища и RNG.
func loadDeviceIdentity(
    read: () throws -> Data?,
    generate: () throws -> Data,
    save: (Data) throws -> Void
) throws -> [UInt8] {
    func validate(_ key: Data) throws {
        guard key.count == 32, key.contains(where: { $0 != 0 }) else {
            throw DeviceIdentityError.invalidKey
        }
    }
    if let existing = try read() {
        try validate(existing)
        return Array(existing)
    }
    let generated = try generate()
    try validate(generated)
    try save(generated)
    return Array(generated)
}
