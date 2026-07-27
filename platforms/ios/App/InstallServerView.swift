import Foundation
import SwiftUI
import Combine

// In-app SSH server installer (C3-iOS): 3-step wizard — Target (connection
// details) → TOFU (host-key confirmation) → Install (live progress) — on
// top of SshInstallApi.swift's wrapper around aivpn-ios-core's
// `ssh-install` FFI surface (crates/aivpn-ios-core/include/aivpn_core.h,
// wrapping crates/aivpn-common/src/ssh_install.rs). Presented from
// ContentView.swift as a sheet, gated the same way as AdminView (admin-only).
//
// Mirrors AdminView.swift's NavigationStack + Form + sheet structure.

// MARK: - Live install log line

private struct InstallLogLine: Identifiable {
    let id = UUID()
    let text: String
    let isError: Bool
}

// MARK: - Install run state (owns the poll timer)

/// Owns the `aivpn_ssh_install_start`/`aivpn_ssh_install_poll` job
/// lifecycle for one install attempt: starts the job, polls it on a
/// ~300ms `Timer` (draining every currently-queued event per tick so a
/// burst of remote output never visibly lags), and frees the handle once
/// the job reports `.done` (or the view disappears first). Not
/// `@MainActor`-isolated as a type — same style as VPNManager.swift's
/// `trafficTimer`/`durationTimer`, which also mutate `@Published` state
/// directly from `Timer.scheduledTimer` closures with no actor
/// annotation — every mutation here happens on the main run loop because
/// `Timer.scheduledTimer` fires there by default (`RunLoop.main` unless
/// explicitly moved to another run loop, which this never does).
final class SshInstallRunner: ObservableObject {
    @Published private(set) var logLines: [InstallLogLine] = []
    @Published private(set) var isRunning = false
    @Published private(set) var finishedExitCode: Int?
    @Published private(set) var finishedConnectionKey: String?
    @Published private(set) var startError: String?

    private var handle: Int64?
    private var timer: Timer?

    func start(paramsJson: String, loc: LocalizationManager) {
        stopPolling()
        logLines = []
        finishedExitCode = nil
        finishedConnectionKey = nil
        startError = nil

        let h = SshInstallApi.installStart(paramsJson: paramsJson)
        guard h >= 1 else {
            startError = loc.t("install_bad_params")
            return
        }
        handle = h
        isRunning = true
        timer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            self?.pollOnce(loc: loc)
        }
    }

    private func pollOnce(loc: LocalizationManager) {
        guard let h = handle else { return }
        // Drain everything currently queued this tick, not just one event,
        // so the log doesn't visibly lag a fast-moving install behind the
        // 300ms cadence.
        while true {
            switch SshInstallApi.installPoll(handle: h) {
            case .event(let json):
                append(event: json, loc: loc)
            case .pending:
                return
            case .done, .badHandle:
                stopPolling()
                return
            }
        }
    }

    private func append(event json: String, loc: LocalizationManager) {
        guard let data = json.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let type = obj["type"] as? String else {
            return
        }
        switch type {
        case "connected":
            let fp = obj["fingerprint"] as? String ?? ""
            logLines.append(InstallLogLine(text: "\(loc.t("install_log_connected")) \(fp)", isError: false))
        case "uploading":
            let what = obj["what"] as? String ?? ""
            logLines.append(InstallLogLine(text: "\(loc.t("install_log_uploading")) \(what)", isError: false))
        case "line":
            if let line = obj["line"] as? String, !line.isEmpty {
                logLines.append(InstallLogLine(text: line, isError: line.hasPrefix("ERROR")))
            }
        case "marker":
            let step = obj["step"] as? String ?? ""
            let status = obj["status"] as? String ?? ""
            let code = obj["code"] as? String
            let msg = obj["msg"] as? String
            logLines.append(InstallLogLine(
                text: formatMarker(step: step, status: status, code: code, msg: msg, loc: loc),
                isError: status == "error"
            ))
        case "finished":
            let exitCode = (obj["exit_code"] as? NSNumber)?.intValue ?? -1
            let key = obj["connection_key"] as? String
            finishedExitCode = exitCode
            finishedConnectionKey = key
            logLines.append(InstallLogLine(
                text: "\(loc.t("install_log_finished")) \(exitCode)",
                isError: exitCode != 0
            ))
        default:
            break
        }
    }

    /// Localizes `code` via an `install_code_<code>` lookup key when known;
    /// falls back to the script's own (English) `msg` — never invented —
    /// for any code not in LocalizationManager's table (there are ~50
    /// distinct codes across deploy/install-server.sh; only the
    /// operator-relevant subset is localized, per this task's brief).
    private func formatMarker(step: String, status: String, code: String?, msg: String?, loc: LocalizationManager) -> String {
        let body: String
        if let code, !code.isEmpty {
            let key = "install_code_\(code)"
            let translated = loc.t(key)
            body = translated == key ? (msg ?? code) : translated
        } else {
            body = msg ?? ""
        }
        return "[\(step)/\(status)] \(body)"
    }

    private func stopPolling() {
        timer?.invalidate()
        timer = nil
        isRunning = false
        if let h = handle {
            SshInstallApi.installFree(handle: h)
        }
        handle = nil
    }

    deinit {
        timer?.invalidate()
        // Best-effort: stop being able to poll the job if the view
        // disappears mid-install. Does NOT cancel the remote script (see
        // aivpn_ssh_install_free's doc comment) — it keeps running to
        // completion with no observer, which is the documented behavior.
        if let h = handle {
            SshInstallApi.installFree(handle: h)
        }
    }
}

// MARK: - Main wizard

struct InstallServerView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @EnvironmentObject private var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss

    private enum Step { case target, tofu, install }
    private enum AuthKind: String { case password, keyPem = "key_pem" }
    private enum ModeKind: String { case systemd, docker }

    @State private var step: Step = .target

    // MARK: Target fields
    @State private var host: String = ""
    @State private var portText: String = "22"
    @State private var user: String = "root"
    @State private var authKind: AuthKind = .password
    @State private var password: String = ""
    @State private var pem: String = ""
    @State private var pemPassphrase: String = ""
    @State private var modeKind: ModeKind = .systemd
    @State private var hasServerIp: Bool = false
    @State private var serverIp: String = ""
    @State private var hasServerPort: Bool = false
    @State private var serverPortText: String = ""
    /// Always stays `false` — see the footer text on this toggle and the
    /// `device_pubkey_b64` comment in `buildParamsJson()` for why: iOS has
    /// no FFI getter for its own device static public key, so device
    /// binding can never actually be requested from this wizard. Kept as a
    /// (disabled) Toggle rather than removed outright so the limitation is
    /// visible in the UI instead of silently absent.
    @State private var deviceBindingRequested: Bool = false

    // MARK: TOFU
    @State private var isProbing = false
    @State private var probeError: String?
    @State private var fingerprint: String?
    @State private var showScriptSheet = false
    @State private var isLoadingScript = false
    @State private var scriptText: String = ""
    @State private var scriptSha256: String = ""

    // MARK: Install
    @StateObject private var runner = SshInstallRunner()
    @State private var showImportSheet = false

    var body: some View {
        NavigationStack {
            Group {
                switch step {
                case .target: targetForm
                case .tofu: tofuStep
                case .install: installStep
                }
            }
            .navigationTitle(loc.t("install_wizard_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc.t("cancel")) { dismiss() }
                }
            }
        }
        .onChange(of: step) { newStep in
            if newStep == .tofu, fingerprint == nil, !isProbing {
                Task { await probe() }
            }
            if newStep == .install, runner.logLines.isEmpty, !runner.isRunning {
                runner.start(paramsJson: buildParamsJson(), loc: loc)
            }
        }
        .sheet(isPresented: $showScriptSheet) {
            scriptSheet
                .environmentObject(loc)
        }
        .sheet(isPresented: $showImportSheet) {
            InstallImportKeySheet(
                connectionKey: runner.finishedConnectionKey ?? "",
                suggestedName: host,
                onImported: {
                    showImportSheet = false
                    dismiss()
                },
                onCancel: { showImportSheet = false }
            )
            .environmentObject(vpn)
            .environmentObject(loc)
        }
    }

    // MARK: - Step 1: Target

    private var targetForm: some View {
        Form {
            Section(header: Text(loc.t("install_target_section"))) {
                TextField(loc.t("install_host"), text: $host)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                HStack {
                    Text(loc.t("install_port"))
                    Spacer()
                    TextField("22", text: $portText)
                        .multilineTextAlignment(.trailing)
                        .keyboardType(.numberPad)
                        .frame(width: 80)
                }
                TextField(loc.t("install_user"), text: $user)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }

            Section(header: Text(loc.t("install_auth_section"))) {
                Picker(loc.t("install_auth_section"), selection: $authKind) {
                    Text(loc.t("install_auth_password")).tag(AuthKind.password)
                    Text(loc.t("install_auth_key_pem")).tag(AuthKind.keyPem)
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                if authKind == .password {
                    SecureField(loc.t("install_password"), text: $password)
                } else {
                    TextField(loc.t("install_pem"), text: $pem, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(4...10)
                        .font(.system(size: 11, design: .monospaced))
                    SecureField(loc.t("install_pem_passphrase"), text: $pemPassphrase)
                }
            }

            Section(header: Text(loc.t("install_mode_section"))) {
                Picker(loc.t("install_mode_section"), selection: $modeKind) {
                    Text(loc.t("install_mode_systemd")).tag(ModeKind.systemd)
                    Text(loc.t("install_mode_docker")).tag(ModeKind.docker)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }

            Section(footer: Text(loc.t("install_server_ip_hint"))) {
                Toggle(loc.t("install_server_ip_toggle"), isOn: $hasServerIp.animation())
                if hasServerIp {
                    TextField(loc.t("install_server_ip"), text: $serverIp)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                }
                Toggle(loc.t("install_server_port_toggle"), isOn: $hasServerPort.animation())
                if hasServerPort {
                    TextField(loc.t("install_server_port"), text: $serverPortText)
                        .keyboardType(.numberPad)
                }
            }

            Section(footer: Text(loc.t("install_device_binding_hint"))) {
                Toggle(loc.t("install_device_binding_toggle"), isOn: $deviceBindingRequested)
                    .disabled(true)
            }

            if let probeError, step == .target {
                Section {
                    Text(probeError).font(.caption).foregroundColor(.red)
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(loc.t("install_next")) {
                    probeError = nil
                    fingerprint = nil
                    step = .tofu
                }
                .disabled(!targetIsValid)
            }
        }
    }

    private var targetIsValid: Bool {
        guard !host.trimmingCharacters(in: .whitespaces).isEmpty,
              !user.trimmingCharacters(in: .whitespaces).isEmpty,
              UInt16(portText.trimmingCharacters(in: .whitespaces)) != nil else {
            return false
        }
        switch authKind {
        case .password: return !password.isEmpty
        case .keyPem: return !pem.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    // MARK: - Step 2: TOFU

    private var tofuStep: some View {
        VStack(spacing: 20) {
            if isProbing {
                ProgressView(loc.t("install_probing"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let fingerprint {
                VStack(spacing: 16) {
                    Image(systemName: "key.viewfinder")
                        .font(.system(size: 40))
                        .foregroundColor(.accentColor)
                    Text(fingerprint)
                        .font(.system(size: 15, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(10)
                    Text(loc.t("install_fingerprint_hint"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)

                    Button(loc.t("install_show_script")) {
                        showScriptSheet = true
                        if scriptText.isEmpty { Task { await loadScriptInfo() } }
                    }
                    .buttonStyle(.bordered)

                    HStack(spacing: 12) {
                        Button(loc.t("install_back")) { step = .target }
                            .buttonStyle(.bordered)
                        Button(loc.t("install_trust")) { step = .install }
                            .buttonStyle(.borderedProminent)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 12) {
                    if let probeError {
                        Text(probeError)
                            .font(.subheadline)
                            .foregroundColor(.red)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                    HStack(spacing: 12) {
                        Button(loc.t("install_back")) { step = .target }
                            .buttonStyle(.bordered)
                        Button(loc.t("retry")) { Task { await probe() } }
                            .buttonStyle(.borderedProminent)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(loc.t("install_tofu_title"))
        .navigationBarTitleDisplayMode(.inline)
    }

    @MainActor
    private func probe() async {
        isProbing = true
        probeError = nil
        guard let portNum = UInt16(portText.trimmingCharacters(in: .whitespaces)) else {
            probeError = loc.t("install_invalid_port")
            isProbing = false
            return
        }
        let result = await SshInstallApi.probeHostkey(
            host: host.trimmingCharacters(in: .whitespaces),
            port: portNum,
            user: user.trimmingCharacters(in: .whitespaces)
        )
        isProbing = false
        if let fp = result {
            fingerprint = fp
        } else {
            probeError = loc.t("install_probe_failed")
        }
    }

    @MainActor
    private func loadScriptInfo() async {
        isLoadingScript = true
        async let shaTask = SshInstallApi.bundleSha256()
        async let scriptTask = SshInstallApi.installScript()
        scriptSha256 = await shaTask
        scriptText = await scriptTask
        isLoadingScript = false
    }

    private var scriptSheet: some View {
        NavigationStack {
            Group {
                if isLoadingScript {
                    ProgressView(loc.t("admin_loading"))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(loc.t("install_script_sha256"))
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(scriptSha256)
                                .font(.system(size: 12, design: .monospaced))
                                .textSelection(.enabled)
                            Divider()
                            Text(scriptText)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .padding()
                    }
                }
            }
            .navigationTitle(loc.t("install_script_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { showScriptSheet = false }
                }
            }
        }
    }

    // MARK: - Step 3: Install

    private var installStep: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(runner.logLines) { line in
                            Text(line.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(line.isError ? .red : .primary)
                                .id(line.id)
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .onChange(of: runner.logLines.count) { _ in
                    if let last = runner.logLines.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }

            Divider()

            VStack(spacing: 10) {
                if let startError = runner.startError {
                    Text(startError).font(.caption).foregroundColor(.red)
                } else if let exitCode = runner.finishedExitCode {
                    if exitCode == 0 {
                        Label(loc.t("install_success"), systemImage: "checkmark.circle.fill")
                            .foregroundColor(.green)
                    } else {
                        Text("\(loc.t("install_failed")): \(exitCode)")
                            .foregroundColor(.red)
                    }
                    if let key = runner.finishedConnectionKey, !key.isEmpty {
                        Button(loc.t("install_import_button")) { showImportSheet = true }
                            .buttonStyle(.borderedProminent)
                    } else {
                        Text(loc.t("install_no_key_hint"))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    Button(loc.t("install_close")) { dismiss() }
                        .buttonStyle(.bordered)
                } else {
                    ProgressView(loc.t("install_running"))
                }
            }
            .padding()
        }
        .navigationTitle(loc.t("install_installing_title"))
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - params_json builder

    /// Builds the JSON body for `aivpn_ssh_install_start`, per the wire
    /// contract documented in SshInstallApi.swift's file header (mirrors
    /// `install_params_from_json` in crates/aivpn-common/src/ssh_install.rs).
    private func buildParamsJson() -> String {
        let authDict: [String: Any]
        switch authKind {
        case .password:
            authDict = ["type": "password", "password": password]
        case .keyPem:
            // NOT a ternary between NSNull() and String — Swift's `?:`
            // resolves both branches to a single concrete type before
            // considering the enclosing `[String: Any]` context, and
            // NSNull/String don't unify. Same reason AdminApi.swift's
            // tri-state PATCH fields (e.g. `exit_node`) always branch with
            // if/switch instead of a ternary when one side is NSNull().
            let trimmedPass = pemPassphrase.trimmingCharacters(in: .whitespacesAndNewlines)
            var d: [String: Any] = ["type": "key_pem", "pem": pem]
            if trimmedPass.isEmpty {
                d["passphrase"] = NSNull()
            } else {
                d["passphrase"] = trimmedPass
            }
            authDict = d
        }

        var dict: [String: Any] = [
            "host": host.trimmingCharacters(in: .whitespaces),
            "port": Int(portText.trimmingCharacters(in: .whitespaces)) ?? 22,
            "user": user.trimmingCharacters(in: .whitespaces),
            "auth": authDict,
            "fingerprint": fingerprint ?? "",
            "binary": ["type": "default"],
            "mode": modeKind.rawValue,
            // device_pubkey_b64: always null on iOS. grep-confirmed: there
            // is no `aivpn_get_device_pubkey`-equivalent export in
            // aivpn_core.h — the only device static keypair material
            // touching this FFI surface is `static_privkey`, consumed
            // internally by aivpn_run_tunnel for JIT enrollment, never
            // exposed back out as a public key the app could read. Without
            // it, deploy/install-server.sh's create_admin_client step is
            // skipped server-side (see its "no --device-pubkey supplied,
            // skipping auto-admin client creation" marker) — so
            // `finished.connection_key` will always be null for an
            // iOS-driven install. TODO(iOS device-binding-for-SSH-install):
            // add an aivpn_core.h getter for the device's own static
            // public key if/when device-bound auto-admin creation from
            // this wizard is wanted on iOS — do NOT add ad hoc FFI here
            // without going through that header (task constraint).
            "device_pubkey_b64": NSNull(),
            "extra_args": [],
        ]
        if hasServerIp {
            let trimmed = serverIp.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { dict["server_ip"] = trimmed }
        }
        if hasServerPort, let p = Int(serverPortText.trimmingCharacters(in: .whitespaces)) {
            dict["server_port"] = p
        }

        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let json = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return json
    }
}

// MARK: - Import connection key sheet

/// Minimal "add key" flow reusing `VPNManager.addKey`/`ConnectionKey`'s own
/// validation — functionally equivalent to ContentView.swift's private
/// `KeyEditSheet` (same validation, same save path), but a separate type
/// here because `KeyEditSheet` is file-private to ContentView.swift and
/// this wizard lives in its own file.
private struct InstallImportKeySheet: View {
    /// Already in `aivpn://<base64url-json>` form — see
    /// `mgmt_service::connection_key` server-side, which formats it that
    /// way before install-server.sh ever echoes it back in the `finished`
    /// marker — so this is NOT re-prefixed before validation/saving.
    let connectionKey: String
    let suggestedName: String
    let onImported: () -> Void
    let onCancel: () -> Void

    @EnvironmentObject private var vpn: VPNManager
    @EnvironmentObject private var loc: LocalizationManager
    @State private var name: String
    @State private var error: String?

    init(connectionKey: String, suggestedName: String, onImported: @escaping () -> Void, onCancel: @escaping () -> Void) {
        self.connectionKey = connectionKey
        self.suggestedName = suggestedName
        self.onImported = onImported
        self.onCancel = onCancel
        _name = State(initialValue: suggestedName)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(loc.t("key_name"), text: $name)
                        .autocorrectionDisabled()
                }
                Section {
                    Text(connectionKey)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(4)
                }
                if let error {
                    Section { Text(error).foregroundColor(.red).font(.caption) }
                }
            }
            .navigationTitle(loc.t("install_import_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc.t("cancel")) { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("admin_save")) { save() }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    private func save() {
        guard ConnectionKey.isValidKeyString(connectionKey) else {
            error = loc.t("error_invalid_key")
            return
        }
        guard vpn.addKey(name: name.trimmingCharacters(in: .whitespaces), keyValue: connectionKey) else {
            error = loc.t("duplicate_key")
            return
        }
        onImported()
    }
}
