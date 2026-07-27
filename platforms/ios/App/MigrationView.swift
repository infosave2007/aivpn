import Foundation
import SwiftUI

// Migration guide (C3-iOS "Migration" wizard): walks the operator through
// moving from an existing aivpn-server to a freshly SSH-installed one —
// Export (from the OLD server, over the currently-connected tunnel) →
// Install (embeds InstallServerView.swift's SSH installer wizard) →
// Import (into the NEW server, once the app is reconnected to it).
//
// IMPORTANT, VERIFIED LIMITATION — read before assuming Export/Import will
// ever succeed as shipped today:
//
// `GET /api/v1/backup/export` and `POST /api/v1/backup/import` are NOT in
// crates/aivpn-server/src/mgmt_service.rs::classify_route's curated
// in-tunnel allowlist at all — that function's own doc comment says so
// explicitly ("no PUT /config, no backup/import, ...", and there is no
// `Route::Backup*` variant in its `Route` enum for either verb, export
// included). `authorize()` denies any `(method, path)` pair
// `classify_route` doesn't recognize for EVERY role, including Admin,
// before the request ever reaches `dispatch` (see gateway.rs's
// `MgmtRequest` handling around the `authorize(...)` check) — so both
// calls below are expected to be REJECTED by the server, typically with
// HTTP 403 and an empty body.
//
// This view makes the real FFI calls anyway — no mocking, no fake success
// — and surfaces whatever the server actually returns, honestly. This
// mirrors the note left by the Android/Linux agents on their own
// migration flows for the same reason. If a future server change adds a
// curated backup route to the tunnel allowlist, this view starts working
// with no changes needed here. Until then, the middle "Install" step (SSH
// server install, via InstallServerView) is the part of this guide that
// actually provisions something; Export/Import will show a clear
// rejection instead of silently doing nothing.

struct MigrationView: View {
    @EnvironmentObject private var vpn: VPNManager
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var isExporting = false
    @State private var exportedData: Data?
    @State private var exportFileURL: URL?
    @State private var exportError: String?

    @State private var showInstallWizard = false

    @State private var isImporting = false
    @State private var importError: String?
    @State private var importSucceeded = false

    var body: some View {
        NavigationStack {
            Form {
                Section(
                    header: Text(loc.t("migrate_step1_title")),
                    footer: Text(loc.t("migrate_step1_hint"))
                ) {
                    if !vpn.isConnected {
                        Label(loc.t("migrate_not_connected"), systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                    Button {
                        Task { await exportBackup() }
                    } label: {
                        if isExporting {
                            ProgressView()
                        } else {
                            Label(loc.t("migrate_export_button"), systemImage: "square.and.arrow.up")
                        }
                    }
                    .disabled(isExporting || !vpn.isConnected)

                    if let exportFileURL, let exportedData {
                        Label(
                            loc.t("migrate_export_size").replacingOccurrences(
                                of: "{bytes}", with: "\(exportedData.count)"
                            ),
                            systemImage: "checkmark.circle"
                        )
                        .font(.caption)
                        .foregroundColor(.green)
                        ShareLink(item: exportFileURL) {
                            Label(loc.t("admin_share"), systemImage: "square.and.arrow.up")
                        }
                    }
                    if let exportError {
                        Text(exportError).font(.caption).foregroundColor(.red)
                    }
                }

                Section(
                    header: Text(loc.t("migrate_step2_title")),
                    footer: Text(loc.t("migrate_step2_hint"))
                ) {
                    Button {
                        showInstallWizard = true
                    } label: {
                        Label(loc.t("migrate_open_install"), systemImage: "server.rack")
                    }
                }

                Section(
                    header: Text(loc.t("migrate_step3_title")),
                    footer: Text(loc.t("migrate_step3_hint"))
                ) {
                    Button {
                        Task { await importBackup() }
                    } label: {
                        if isImporting {
                            ProgressView()
                        } else {
                            Label(loc.t("migrate_import_button"), systemImage: "square.and.arrow.down")
                        }
                    }
                    .disabled(isImporting || exportedData == nil || !vpn.isConnected)

                    if importSucceeded {
                        Label(loc.t("migrate_import_success"), systemImage: "checkmark.circle")
                            .foregroundColor(.green)
                    }
                    if let importError {
                        Text(importError).font(.caption).foregroundColor(.red)
                    }
                }
            }
            .navigationTitle(loc.t("migrate_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .sheet(isPresented: $showInstallWizard) {
            InstallServerView()
                .environmentObject(vpn)
                .environmentObject(loc)
        }
    }

    @MainActor
    private func exportBackup() async {
        isExporting = true
        exportError = nil
        let result = await MigrationRawApi.request(method: 0, path: "/api/v1/backup/export", body: Data())
        isExporting = false
        guard let result else {
            exportError = loc.t("migrate_transport_error")
            return
        }
        guard (200...299).contains(Int(result.status)) else {
            exportError = loc.t("migrate_server_rejected").replacingOccurrences(
                of: "{status}", with: "\(result.status)"
            )
            return
        }
        exportedData = result.body
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("aivpn-backup-\(Int(Date().timeIntervalSince1970)).json")
        do {
            try result.body.write(to: url)
            exportFileURL = url
        } catch {
            // The export itself succeeded server-side — only writing the
            // shareable temp file failed (disk full, etc). Surface that
            // distinctly rather than pretending the whole step failed.
            exportError = loc.t("migrate_export_file_write_failed")
        }
    }

    @MainActor
    private func importBackup() async {
        guard let data = exportedData else { return }
        isImporting = true
        importError = nil
        importSucceeded = false
        let result = await MigrationRawApi.request(method: 1, path: "/api/v1/backup/import", body: data)
        isImporting = false
        guard let result else {
            importError = loc.t("migrate_transport_error")
            return
        }
        guard (200...299).contains(Int(result.status)) else {
            importError = loc.t("migrate_server_rejected").replacingOccurrences(
                of: "{status}", with: "\(result.status)"
            )
            return
        }
        importSucceeded = true
    }
}

// MARK: - Raw mgmt-request helper (file-scoped)
//
// Not routed through AdminApi.swift's curated methods — that enum only
// exposes the client-management surface it was designed for. This calls
// `aivpn_mgmt_request` directly with the two routes this file's header
// comment documents as EXPECTED to be rejected by the server, using the
// same low-level written-len-or-needed-len buffer convention
// AdminApi.swift's `mgmtRequestBlocking` documents (aivpn_core.h).
private enum MigrationRawApi {
    struct RawResult {
        let status: UInt16
        let body: Data
    }

    /// Larger initial buffer than AdminApi's 64KB default — a full backup
    /// export (if the server ever allows it) could be considerably bigger
    /// than a single client-list response.
    private static let initialBufferCapacity = 256 * 1024

    static func request(method: UInt8, path: String, body: Data) async -> RawResult? {
        await Task.detached(priority: .userInitiated) {
            requestBlocking(method: method, path: path, body: body)
        }.value
    }

    private static func requestBlocking(method: UInt8, path: String, body: Data) -> RawResult? {
        var status: UInt16 = 0
        var cap = initialBufferCapacity
        var bodyBytes = [UInt8](body)

        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = path.withCString { pathPtr in
                bodyBytes.withUnsafeMutableBufferPointer { bodyBufPtr in
                    outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                        aivpn_mgmt_request(
                            method,
                            pathPtr,
                            bodyBufPtr.baseAddress,
                            bodyBufPtr.count,
                            &status,
                            outBufPtr.baseAddress,
                            outBufPtr.count
                        )
                    }
                }
            }
            if written < 0 {
                return nil
            }
            if written <= cap {
                return RawResult(status: status, body: Data(outBuf.prefix(written)))
            }
            // Needed length reported (written > cap) — retry once with a
            // buffer of exactly that size, same convention as
            // AdminApi.swift's mgmtRequestBlocking.
            cap = written
        }
        return nil
    }
}
