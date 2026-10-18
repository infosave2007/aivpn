import Foundation

// GUI и helper используют один список доверенных путей.
enum ClientBinaryPolicy {
    static let defaultPath = "/Library/Application Support/AIVPN/aivpn-client"
    static let allowedPaths = [
        "/Applications/Aivpn.app/Contents/MacOS/aivpn-client",
        "/Applications/Aivpn.app/Contents/Resources/aivpn-client",
        "/Applications/AIVPN.app/Contents/MacOS/aivpn-client",
        "/Applications/AIVPN.app/Contents/Resources/aivpn-client",
        defaultPath,
    ]

    static func bundledPath(bundlePath: String, isExecutable: (String) -> Bool) -> String? {
        for suffix in ["/Contents/Resources/aivpn-client", "/Contents/MacOS/aivpn-client"] {
            let path = bundlePath + suffix
            if allowedPaths.contains(path), isExecutable(path) {
                return path
            }
        }
        // Для перемещенного приложения helper выбирает установленную системную копию.
        return nil
    }
}
