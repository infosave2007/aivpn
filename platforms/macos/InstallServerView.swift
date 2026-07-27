import SwiftUI

// MARK: - Window controller

/// Hosts `InstallServerRootView` in its own standalone `NSWindow`, same
/// singleton/reuse pattern as `AdminWindowController` (AdminView.swift):
/// `isReleasedWhenClosed = false` so the red close button just hides the
/// window, `show()` brings the same window/state back.
final class InstallServerWindowController: NSWindowController {
    static let shared = InstallServerWindowController()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 660),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(
            rootView: InstallServerRootView()
                .environmentObject(VPNManager.shared)
                .environmentObject(LocalizationManager.shared)
        )
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        window?.title = LocalizationManager.shared.t("install_wizard_title")
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

// MARK: - Wizard step

enum InstallWizardStep: Hashable {
    case target, tofu, installing
}

enum InstallAuthMode: Hashable {
    case password, keyFile
}

enum InstallSourceMode: Hashable {
    case releases, file, url
}

/// Looks up `"install_code_" + code` and falls back to the raw code string
/// when no translation was registered — `LocalizationManager.t()` returns
/// the key itself on a miss, so comparing against the constructed key is
/// how a caller can tell "translated" from "no such entry" without reaching
/// into the manager's private dictionary.
private func codeLabel(_ code: String, _ loc: LocalizationManager) -> String {
    let key = "install_code_" + code
    let val = loc.t(key)
    return val == key ? code : val
}

private func stepLabel(_ step: String, _ loc: LocalizationManager) -> String {
    let key = "install_step_" + step
    let val = loc.t(key)
    return val == key ? step : val
}

/// Renders one `SshInstaller.Marker` (a parsed `##AIVPN {...}` line) as a
/// single localized, human-readable log entry.
private func markerDisplayLine(_ marker: SshInstaller.Marker, _ loc: LocalizationManager) -> String {
    var parts = [stepLabel(marker.step, loc)]
    if let code = marker.code, !code.isEmpty {
        parts.append("(\(codeLabel(code, loc)))")
    }
    if let msg = marker.msg, !msg.isEmpty {
        parts.append("— \(msg)")
    }
    let icon = marker.status == "error" ? "[!]" : (marker.status == "ok" ? "[OK]" : "[i]")
    return "\(icon) " + parts.joined(separator: " ")
}

// MARK: - Store

/// Owns all wizard state and drives `SshInstaller` calls off the main
/// thread. A fresh instance backs each window-controller re-init (there is
/// only ever one, created once — see `InstallServerWindowController`), so
/// state persists across `show()`/close the same way `AdminStore` does.
final class InstallServerStore: ObservableObject {
    @Published var step: InstallWizardStep = .target

    // Target
    @Published var host: String = ""
    @Published var port: String = "22"
    @Published var user: String = "root"
    @Published var authMode: InstallAuthMode = .password
    @Published var password: String = ""
    @Published var keyFilePath: String = ""
    @Published var keyPassphrase: String = ""
    @Published var serverIp: String = ""
    @Published var serverPort: String = ""
    @Published var mode: SshInstaller.Mode = .systemd
    @Published var bindDevice: Bool = true
    @Published var sourceMode: InstallSourceMode = .releases
    @Published var binaryFilePath: String = ""
    @Published var binaryUrl: String = ""
    @Published var showAdvanced: Bool = false

    // TOFU
    @Published var isProbing: Bool = false
    @Published var probeError: String?
    @Published var fingerprint: String = ""
    @Published var showScriptSheet: Bool = false
    @Published var scriptPreview: String = ""
    @Published var scriptSha256: String = ""
    @Published var isLoadingScript: Bool = false

    // Install run
    @Published var logLines: [String] = []
    @Published var isRunning: Bool = false
    @Published var isFinished: Bool = false
    @Published var exitCode: Int32?
    @Published var connectionKey: String?
    @Published var lastMarker: SshInstaller.Marker?

    // Import
    @Published var importedProfileName: String = ""
    @Published var didImport: Bool = false

    var canProbe: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty
            && Int(port) != nil
            && !user.trimmingCharacters(in: .whitespaces).isEmpty
            && (authMode == .password ? !password.isEmpty : !keyFilePath.isEmpty)
    }

    func resetForNewInstall() {
        step = .target
        probeError = nil
        fingerprint = ""
        logLines = []
        isRunning = false
        isFinished = false
        exitCode = nil
        connectionKey = nil
        lastMarker = nil
        didImport = false
        importedProfileName = ""
    }

    func probe() {
        guard let portNum = Int(port) else { return }
        isProbing = true
        probeError = nil
        Task {
            do {
                let fp = try await SshInstaller.probeHostkey(host: host, port: portNum, user: user)
                await MainActor.run {
                    self.fingerprint = fp
                    self.isProbing = false
                    self.step = .tofu
                }
            } catch {
                await MainActor.run {
                    self.probeError = error.localizedDescription
                    self.isProbing = false
                }
            }
        }
    }

    func loadScriptPreview() {
        guard scriptPreview.isEmpty else { return }
        isLoadingScript = true
        DispatchQueue.global(qos: .userInitiated).async {
            let script = SshInstaller.installerScript()
            let sha = SshInstaller.installerScriptSha256()
            DispatchQueue.main.async {
                self.scriptPreview = script
                self.scriptSha256 = sha
                self.isLoadingScript = false
            }
        }
    }

    func startInstall(loc: LocalizationManager) {
        step = .installing
        isRunning = true
        isFinished = false
        logLines = []
        exitCode = nil
        connectionKey = nil
        lastMarker = nil

        let auth: SshInstaller.Auth
        switch authMode {
        case .password:
            auth = .password(password)
        case .keyFile:
            auth = .keyFile(path: keyFilePath, passphrase: keyPassphrase.isEmpty ? nil : keyPassphrase)
        }
        let source: SshInstaller.BinarySource
        switch sourceMode {
        case .releases: source = .releases
        case .file: source = .file(binaryFilePath)
        case .url: source = .url(binaryUrl)
        }
        let portNum = Int(port) ?? 22
        let serverPortNum = Int(serverPort)
        let targetHost = host
        let targetUser = user
        let targetFingerprint = fingerprint
        let targetServerIp = serverIp
        let targetMode = mode
        let targetBindDevice = bindDevice

        Task {
            let code = await SshInstaller.runInstall(
                host: targetHost, port: portNum, user: targetUser, fingerprint: targetFingerprint,
                auth: auth, source: source,
                serverIp: targetServerIp.isEmpty ? nil : targetServerIp,
                serverPort: serverPortNum,
                mode: targetMode, bindDevice: targetBindDevice
            ) { [weak self] line in
                guard let self = self else { return }
                self.logLines.append(line)
                if let marker = SshInstaller.parseMarkerLine(line) {
                    self.lastMarker = marker
                    if marker.step == "client_done", let key = marker.connection_key {
                        self.connectionKey = key
                    }
                }
            }
            await MainActor.run {
                self.exitCode = code
                self.isRunning = false
                self.isFinished = true
                if self.importedProfileName.isEmpty {
                    self.importedProfileName = self.host
                }
            }
        }
    }
}

// MARK: - Root view

struct InstallServerRootView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    @StateObject private var store = InstallServerStore()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(loc.t("install_wizard_title"))
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding(16)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch store.step {
                    case .target:
                        targetStep
                    case .tofu:
                        tofuStep
                    case .installing:
                        installingStep
                    }
                }
                .padding(20)
            }
        }
        .frame(minWidth: 520, minHeight: 560)
        .sheet(isPresented: $store.showScriptSheet) {
            scriptSheet
        }
    }

    // MARK: Step 1 — Target

    private var targetStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(loc.t("install_step_target_title")).font(.headline)

            Group {
                TextField(loc.t("install_host"), text: $store.host)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    TextField(loc.t("install_port"), text: $store.port)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 100)
                    TextField(loc.t("install_user"), text: $store.user)
                        .textFieldStyle(.roundedBorder)
                }
            }

            Picker(loc.t("install_auth_title"), selection: $store.authMode) {
                Text(loc.t("install_auth_password")).tag(InstallAuthMode.password)
                Text(loc.t("install_auth_key_file")).tag(InstallAuthMode.keyFile)
            }
            .pickerStyle(.segmented)

            if store.authMode == .password {
                SecureField(loc.t("install_password_placeholder"), text: $store.password)
                    .textFieldStyle(.roundedBorder)
            } else {
                HStack {
                    TextField(loc.t("install_key_file_path"), text: $store.keyFilePath)
                        .textFieldStyle(.roundedBorder)
                    Button(loc.t("install_browse")) { browseForKeyFile() }
                }
                SecureField(loc.t("install_key_passphrase"), text: $store.keyPassphrase)
                    .textFieldStyle(.roundedBorder)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                TextField(loc.t("install_server_ip"), text: $store.serverIp)
                    .textFieldStyle(.roundedBorder)
                TextField(loc.t("install_server_port"), text: $store.serverPort)
                    .textFieldStyle(.roundedBorder)

                Picker(loc.t("install_mode"), selection: $store.mode) {
                    Text(loc.t("install_mode_systemd")).tag(SshInstaller.Mode.systemd)
                    Text(loc.t("install_mode_docker")).tag(SshInstaller.Mode.docker)
                }
                .pickerStyle(.segmented)

                Toggle(loc.t("install_bind_device"), isOn: $store.bindDevice)
                    .toggleStyle(.checkbox)
                Text(loc.t("install_bind_device_help"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            DisclosureGroup(loc.t("install_advanced"), isExpanded: $store.showAdvanced) {
                VStack(alignment: .leading, spacing: 8) {
                    Picker(loc.t("install_binary_source"), selection: $store.sourceMode) {
                        Text(loc.t("install_binary_source_releases")).tag(InstallSourceMode.releases)
                        Text(loc.t("install_binary_source_file")).tag(InstallSourceMode.file)
                        Text(loc.t("install_binary_source_url")).tag(InstallSourceMode.url)
                    }
                    .pickerStyle(.segmented)

                    if store.sourceMode == .file {
                        HStack {
                            TextField(loc.t("install_binary_file_path"), text: $store.binaryFilePath)
                                .textFieldStyle(.roundedBorder)
                            Button(loc.t("install_browse")) { browseForBinaryFile() }
                        }
                    } else if store.sourceMode == .url {
                        TextField(loc.t("install_binary_url"), text: $store.binaryUrl)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                .padding(.top, 6)
            }

            if let err = store.probeError {
                Text(err).font(.caption).foregroundColor(.red)
            }

            HStack {
                Spacer()
                Button(store.isProbing ? loc.t("install_probing") : loc.t("install_next_probe")) {
                    store.probe()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!store.canProbe || store.isProbing)
            }
        }
    }

    private func browseForKeyFile() {
        let panel = NSOpenPanel()
        panel.title = loc.t("install_key_file_path")
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            store.keyFilePath = url.path
        }
    }

    private func browseForBinaryFile() {
        let panel = NSOpenPanel()
        panel.title = loc.t("install_binary_file_path")
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            store.binaryFilePath = url.path
        }
    }

    // MARK: Step 2 — TOFU

    private var tofuStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(loc.t("install_tofu_title")).font(.headline)
            Text(loc.t("install_tofu_message"))
                .font(.caption)
                .foregroundColor(.secondary)

            Text(store.fingerprint)
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(6)

            Button(loc.t("install_show_script")) {
                store.loadScriptPreview()
                store.showScriptSheet = true
            }
            .buttonStyle(.bordered)

            HStack {
                Button(loc.t("install_cancel")) {
                    store.step = .target
                    store.fingerprint = ""
                }
                Spacer()
                Button(loc.t("install_trust_and_install")) {
                    store.startInstall(loc: loc)
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var scriptSheet: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(loc.t("install_script_title")).font(.headline)
            if store.isLoadingScript {
                ProgressView()
            } else {
                Text(loc.t("install_script_sha256") + ": " + store.scriptSha256)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                ScrollView {
                    Text(store.scriptPreview)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 300)
            }
            HStack {
                Spacer()
                Button(loc.t("install_close")) { store.showScriptSheet = false }
            }
        }
        .padding(20)
        .frame(width: 520, height: 460)
    }

    // MARK: Step 3 — Installing / result

    private var installingStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(loc.t("install_installing_title")).font(.headline)

            if let marker = store.lastMarker {
                Text(markerDisplayLine(marker, loc))
                    .font(.system(size: 12, weight: .medium))
            } else if store.isRunning {
                ProgressView(loc.t("install_step_ssh_connect"))
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(store.logLines.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 220)
            .background(Color(NSColor.textBackgroundColor))
            .cornerRadius(6)

            if store.isFinished {
                resultView
            }
        }
    }

    @ViewBuilder
    private var resultView: some View {
        let ok = store.exitCode == 0
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(ok ? .green : .red)
                Text(ok ? loc.t("install_success_title") : loc.t("install_failure_title"))
                    .font(.headline)
                Text("(\(loc.t("install_exit_code")): \(store.exitCode.map { "\($0)" } ?? "?"))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if ok, let key = store.connectionKey {
                VStack(alignment: .leading, spacing: 8) {
                    Text(key)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(3)
                        .truncationMode(.middle)
                    TextField(loc.t("install_profile_name"), text: $store.importedProfileName)
                        .textFieldStyle(.roundedBorder)
                    if store.didImport {
                        Text(loc.t("install_imported"))
                            .font(.caption)
                            .foregroundColor(.green)
                    } else {
                        Button(loc.t("install_import_profile")) {
                            let name = store.importedProfileName.trimmingCharacters(in: .whitespaces)
                            _ = vpn.addKey(name: name.isEmpty ? store.host : name, keyValue: key)
                            store.didImport = true
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            } else if ok {
                Text(loc.t("install_no_connection_key"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack {
                Button(loc.t("install_start_over")) { store.resetForNewInstall() }
                Spacer()
                Button(loc.t("install_close")) { InstallServerWindowController.shared.window?.orderOut(nil) }
            }
        }
        .padding(.top, 6)
    }
}
