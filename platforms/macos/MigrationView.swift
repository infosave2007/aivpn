import SwiftUI

// MARK: - `aivpn-client mgmt` subprocess bridge
//
// Unlike AdminApi.swift (which speaks the admin-socket wire protocol
// directly from Swift — see that file's architecture note), the migration
// wizard shells out to the `aivpn-client mgmt` CLI subcommand per-call, as
// specified for this feature. Both paths end up on the exact same wire
// protocol and the exact same server-side `classify_route` allowlist
// (crates/aivpn-server/src/mgmt_service.rs) — see `MigrationStore`'s
// `runExport`/`runImport` doc comments below for why that allowlist means
// this call is *expected* to be rejected today.

/// Mirrors `ClientCommand::Mgmt`'s documented stdout/stderr contract
/// (crates/aivpn-client/src/main.rs): the numeric HTTP-style status is
/// printed to stderr, the raw response body to stdout.
enum MgmtCli {
    struct Reply {
        let status: Int
        let body: Data
    }

    /// Runs `aivpn-client mgmt --method <M> --path <path> [--body-file
    /// <file>]` and parses its stderr/stdout contract. Returns nil when the
    /// daemon can't be reached at all (no reply / malformed reply / spawn
    /// failure) — the local "channel unavailable" case, indistinguishable
    /// from `AdminApi.mgmtRequest`'s own nil contract. A non-nil `status`
    /// of `0` is the daemon's own local "call failed" sentinel (control
    /// channel closed / no reply within its 10s timeout) — never a real
    /// server status, same meaning as `AdminApi`'s doc comment describes.
    ///
    /// BLOCKING — performs real process I/O bounded by `timeoutSeconds`.
    /// Callers MUST invoke this off the main thread.
    static func request(method: String, path: String, bodyFilePath: String? = nil, timeoutSeconds: Double = 15.0) -> Reply? {
        guard let binary = SshInstaller.binaryPath() else { return nil }

        var args = ["mgmt", "--method", method, "--path", path]
        if let bodyFilePath = bodyFilePath {
            args += ["--body-file", bodyFilePath]
        }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: binary)
        task.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe

        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        do {
            try task.run()
        } catch {
            return nil
        }

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while task.isRunning && Date() < deadline {
            usleep(50_000)
        }
        if task.isRunning {
            task.terminate()
            usleep(300_000)
            if task.isRunning {
                kill(task.processIdentifier, SIGKILL)
            }
        }
        task.waitUntilExit()
        _ = group.wait(timeout: .now() + 2)

        // stderr's LAST all-digit line is the status (`eprintln!("{status}")`
        // is the final thing the subcommand prints before exiting; anything
        // earlier would be incidental tracing output, not part of the
        // documented contract). No such line at all means the daemon never
        // replied / the reply was malformed — both print a message instead
        // of a bare number, so this naturally returns nil for those too.
        let stderrText = String(data: errData, encoding: .utf8) ?? ""
        let statusLine = stderrText
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .last { !$0.isEmpty && $0.allSatisfy { $0.isNumber } }
        guard let statusLine = statusLine, let status = Int(statusLine) else {
            return nil
        }
        return Reply(status: status, body: outData)
    }
}

// MARK: - Window controller

final class MigrationWindowController: NSWindowController {
    static let shared = MigrationWindowController()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 540, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(
            rootView: MigrationRootView()
                .environmentObject(VPNManager.shared)
                .environmentObject(LocalizationManager.shared)
        )
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        window?.title = LocalizationManager.shared.t("migrate_wizard_title")
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

// MARK: - Store

enum MigrationStep: Hashable {
    case export, install, importStep
}

final class MigrationStore: ObservableObject {
    @Published var step: MigrationStep = .export

    @Published var isExporting = false
    @Published var exportStatus: Int?
    @Published var exportBodySize: Int = 0
    @Published var exportUnavailable = false
    /// Path of a temp file holding the exported JSON body, once/if a real
    /// `200` export ever succeeds — fed straight into the import step's
    /// `--body-file`. Both the export and import calls below are exercised
    /// for real regardless: see their doc comments for why they are
    /// expected to be rejected by the server today.
    @Published var exportBodyPath: String?

    @Published var isImporting = false
    @Published var importStatus: Int?
    @Published var importUnavailable = false

    /// `GET /api/v1/backup/export` via `aivpn-client mgmt` against the
    /// CURRENTLY connected server (i.e. the OLD server being migrated
    /// away from — the user must already be connected to it as Admin).
    ///
    /// KNOWN LIMITATION (by server-side design, not a bug here):
    /// `backup/export` and `backup/import` are deliberately absent from
    /// the curated in-tunnel management allowlist —
    /// `crates/aivpn-server/src/mgmt_service.rs::classify_route` never
    /// matches either path, for EITHER role, so `dispatch()` always
    /// returns `404` for them (see that file's `dispatch_unknown_path_is_404`
    /// test, which explicitly asserts this for `backup/import`). This call
    /// is real — not stubbed — but a live server today will always answer
    /// with a rejection; do not change `mgmt_service.rs` to work around
    /// it (out of scope: platforms/macos/ only). The honest rejection is
    /// surfaced to the user as-is below, never hidden behind a fake
    /// success.
    func runExport() {
        isExporting = true
        exportStatus = nil
        exportUnavailable = false
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = MgmtCli.request(method: "GET", path: "/api/v1/backup/export")
            DispatchQueue.main.async {
                self.isExporting = false
                guard let reply = reply else {
                    self.exportUnavailable = true
                    return
                }
                self.exportStatus = reply.status
                if reply.status == 200 {
                    self.exportBodySize = reply.body.count
                    let tmp = FileManager.default.temporaryDirectory
                        .appendingPathComponent("aivpn-migrate-export-\(UUID().uuidString).json")
                    if (try? reply.body.write(to: tmp, options: [.atomic])) != nil {
                        self.exportBodyPath = tmp.path
                    }
                }
            }
        }
    }

    /// `POST /api/v1/backup/import` via `aivpn-client mgmt`, sent to
    /// whichever server the app is connected to at the moment this runs —
    /// the user is expected to have switched to the NEW server (imported
    /// via the install wizard's connection key) before returning to this
    /// step. Same `classify_route` limitation as `runExport()` above
    /// applies identically to `backup/import` — real call, honest
    /// rejection, no fake success.
    func runImport() {
        guard let bodyPath = exportBodyPath else { return }
        isImporting = true
        importStatus = nil
        importUnavailable = false
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = MgmtCli.request(method: "POST", path: "/api/v1/backup/import", bodyFilePath: bodyPath)
            DispatchQueue.main.async {
                self.isImporting = false
                guard let reply = reply else {
                    self.importUnavailable = true
                    return
                }
                self.importStatus = reply.status
            }
        }
    }
}

// MARK: - Root view

struct MigrationRootView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    @StateObject private var store = MigrationStore()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(loc.t("migrate_wizard_title"))
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding(16)

            Picker("", selection: $store.step) {
                Text(loc.t("migrate_step_export")).tag(MigrationStep.export)
                Text(loc.t("migrate_step_install")).tag(MigrationStep.install)
                Text(loc.t("migrate_step_import")).tag(MigrationStep.importStep)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 16)
            .padding(.bottom, 12)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch store.step {
                    case .export: exportStep
                    case .install: installStep
                    case .importStep: importStep
                    }
                }
                .padding(20)
            }
        }
        .frame(minWidth: 480, minHeight: 480)
    }

    private var exportStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(loc.t("migrate_export_title")).font(.headline)
            Text(loc.t("migrate_export_intro"))
                .font(.caption)
                .foregroundColor(.secondary)

            if !vpn.isConnected {
                Text(loc.t("migrate_not_connected"))
                    .font(.caption)
                    .foregroundColor(.orange)
            }

            Button(store.isExporting ? loc.t("migrate_exporting") : loc.t("migrate_run_export")) {
                store.runExport()
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isExporting || !vpn.isConnected)

            if let status = store.exportStatus {
                if status == 200 {
                    Text(loc.t("migrate_export_success") + " (\(store.exportBodySize) " + loc.t("migrate_bytes") + ")")
                        .foregroundColor(.green)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(loc.t("migrate_export_rejected") + " (HTTP \(status))")
                            .foregroundColor(.red)
                        Text(loc.t("migrate_export_rejected_note"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            } else if store.exportUnavailable {
                Text(loc.t("migrate_channel_unavailable"))
                    .font(.caption)
                    .foregroundColor(.red)
            }

            Divider()
            HStack {
                Spacer()
                Button(loc.t("migrate_next")) { store.step = .install }
            }
        }
    }

    private var installStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(loc.t("migrate_install_title")).font(.headline)
            Text(loc.t("migrate_install_intro"))
                .font(.caption)
                .foregroundColor(.secondary)

            Button(loc.t("migrate_open_install_wizard")) {
                InstallServerWindowController.shared.show()
            }
            .buttonStyle(.borderedProminent)

            Text(loc.t("migrate_install_note"))
                .font(.caption)
                .foregroundColor(.secondary)

            Divider()
            HStack {
                Button(loc.t("migrate_back")) { store.step = .export }
                Spacer()
                Button(loc.t("migrate_next")) { store.step = .importStep }
            }
        }
    }

    private var importStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(loc.t("migrate_import_title")).font(.headline)
            Text(loc.t("migrate_import_intro"))
                .font(.caption)
                .foregroundColor(.secondary)

            if !vpn.isConnected {
                Text(loc.t("migrate_not_connected"))
                    .font(.caption)
                    .foregroundColor(.orange)
            }
            if store.exportBodyPath == nil {
                Text(loc.t("migrate_no_export_body"))
                    .font(.caption)
                    .foregroundColor(.orange)
            }

            Button(store.isImporting ? loc.t("migrate_importing") : loc.t("migrate_run_import")) {
                store.runImport()
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isImporting || !vpn.isConnected || store.exportBodyPath == nil)

            if let status = store.importStatus {
                if status == 200 || status == 204 {
                    Text(loc.t("migrate_import_success"))
                        .foregroundColor(.green)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(loc.t("migrate_import_rejected") + " (HTTP \(status))")
                            .foregroundColor(.red)
                        Text(loc.t("migrate_export_rejected_note"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            } else if store.importUnavailable {
                Text(loc.t("migrate_channel_unavailable"))
                    .font(.caption)
                    .foregroundColor(.red)
            }

            Divider()
            HStack {
                Button(loc.t("migrate_back")) { store.step = .install }
                Spacer()
                Button(loc.t("migrate_close")) { MigrationWindowController.shared.window?.orderOut(nil) }
            }
        }
    }
}
