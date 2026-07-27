import SwiftUI
import NetworkExtension

// MARK: - Helpers

private func formatBytes(_ bytes: Int64) -> String {
    let kb = Double(bytes) / 1024
    let mb = kb / 1024
    let gb = mb / 1024
    if gb >= 1 { return String(format: "%.2f GB", gb) }
    if mb >= 1 { return String(format: "%.2f MB", mb) }
    if kb >= 1 { return String(format: "%.1f KB", kb) }
    return "\(bytes) B"
}

private func formatDuration(_ t: TimeInterval) -> String {
    let h = Int(t) / 3600
    let m = (Int(t) % 3600) / 60
    let s = Int(t) % 60
    if h > 0 { return String(format: "%02d:%02d:%02d", h, m, s) }
    return String(format: "%02d:%02d", m, s)
}

// MARK: - Key row

private struct KeyRowView: View {
    let key: ConnectionKey
    let isSelected: Bool
    let onSelect: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void
    let onAddNew: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                .foregroundColor(isSelected ? .accentColor : .secondary)
                .font(.title3)
                .onTapGesture { onSelect() }

            VStack(alignment: .leading, spacing: 2) {
                Text(key.name)
                    .font(.body)
                    .fontWeight(isSelected ? .semibold : .regular)
                if let s = key.serverAddress {
                    Text(s)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            Spacer()
            if key.isRecordingAdminKey {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .foregroundColor(.orange)
                    .font(.caption)
            }
            Menu {
                Button { onAddNew() } label: { Label("Add Key", systemImage: "plus.circle") }
                Divider()
                Button { onEdit() } label: { Label("Edit", systemImage: "pencil") }
                Button(role: .destructive) { onDelete() } label: { Label("Delete", systemImage: "trash") }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .contextMenu {
            Button { onAddNew() } label: { Label("Add Key", systemImage: "plus.circle") }
            Button { onEdit() } label: { Label("Edit", systemImage: "pencil") }
            Button(role: .destructive) { onDelete() } label: { Label("Delete", systemImage: "trash") }
        }
    }
}

// MARK: - Add / Edit key sheet

private struct KeyEditSheet: View {
    let existingKey: ConnectionKey?
    /// Returns nil on success, or a localized error message on failure.
    /// Parameters: name, key value, mTLS cert, server signing key (base64).
    let onSave: (String, String, String?, String?) -> String?
    let onCancel: () -> Void

    @State private var name: String
    @State private var value: String
    @State private var mtlsCert: String
    @State private var serverSigningKey: String
    @State private var error: String?
    @EnvironmentObject private var loc: LocalizationManager

    init(existingKey: ConnectionKey?, onSave: @escaping (String, String, String?, String?) -> String?, onCancel: @escaping () -> Void) {
        self.existingKey = existingKey
        self.onSave = onSave
        self.onCancel = onCancel
        _name     = State(initialValue: existingKey?.name ?? "")
        _value    = State(initialValue: existingKey.map { "aivpn://\($0.keyValue)" } ?? "")
        _mtlsCert = State(initialValue: existingKey?.mtlsCert ?? "")
        _serverSigningKey = State(initialValue: existingKey?.serverSigningKey ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(loc.t("key_name"), text: $name)
                        .autocorrectionDisabled()
                    TextField(loc.t("enter_key"), text: $value, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(3...6)
                }
                Section(header: Text("mTLS")) {
                    TextField(loc.t("mtls_cert_hint"), text: $mtlsCert, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(1...4)
                        .font(.system(size: 12, design: .monospaced))
                }
                Section(header: Text(loc.t("server_signing_key"))) {
                    TextField(loc.t("server_signing_key_hint"), text: $serverSigningKey, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(1...3)
                        .font(.system(size: 12, design: .monospaced))
                }
                if let e = error {
                    Section { Text(e).foregroundColor(.red).font(.caption) }
                }
            }
            .navigationTitle(existingKey == nil ? loc.t("add_key") : loc.t("edit"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc.t("cancel")) { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("save_key")) {
                        let cert = mtlsCert.trimmingCharacters(in: .whitespacesAndNewlines)
                        let signKey = serverSigningKey.trimmingCharacters(in: .whitespacesAndNewlines)
                        error = onSave(name.trimmingCharacters(in: .whitespaces),
                                       value.trimmingCharacters(in: .whitespaces),
                                       cert.isEmpty ? nil : cert,
                                       signKey.isEmpty ? nil : signKey)
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty ||
                              value.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}

// MARK: - Status ring

private struct StatusRing: View {
    let isConnected: Bool
    let isConnecting: Bool
    let isDisconnecting: Bool

    private var isAnimating: Bool { isConnecting || isDisconnecting }

    private var color: Color {
        if isDisconnecting { return .orange }
        return isConnected ? .green : (isConnecting ? .orange : .red)
    }
    private var symbol: String {
        if isDisconnecting { return "stop.circle" }
        return isConnected ? "lock.fill" : (isConnecting ? "arrow.triangle.2.circlepath" : "lock.open.fill")
    }

    var body: some View {
        ZStack {
            Circle()
                .stroke(color.opacity(0.2), lineWidth: 6)
                .frame(width: 76, height: 76)
            Circle()
                .trim(from: 0, to: isAnimating ? 0.6 : 1)
                .stroke(color, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                .frame(width: 76, height: 76)
                .rotationEffect(.degrees(-90))
                .animation(isAnimating
                    ? .linear(duration: 1.2).repeatForever(autoreverses: false)
                    : .easeInOut, value: isAnimating)
            Image(systemName: symbol)
                .font(.system(size: 24, weight: .medium))
                .foregroundColor(color)
        }
    }
}

// MARK: - Recording section

private struct RecordingSection: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    @State private var serviceName: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(loc.t("record_new_mask"))
                .font(.headline)

            switch vpn.recordingState {
            case .idle:
                HStack {
                    TextField(loc.t("record_service_name"), text: $serviceName)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                    Button(loc.t("record_new_mask")) {
                        vpn.startMaskRecording(serviceName: serviceName)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(serviceName.trimmingCharacters(in: .whitespaces).isEmpty)
                }

            case .starting(let svc):
                Label(loc.t("recording_starting"), systemImage: "record.circle")
                    .foregroundColor(.orange)
                Text(svc).font(.caption).foregroundColor(.secondary)

            case .recording(let svc):
                VStack(alignment: .leading, spacing: 6) {
                    Label(loc.t("recording_active"), systemImage: "record.circle.fill")
                        .foregroundColor(.red)
                    Text(svc).font(.caption).foregroundColor(.secondary)
                    Button(loc.t("stop_recording"), role: .destructive) {
                        vpn.stopMaskRecording()
                    }
                    .buttonStyle(.bordered)
                }

            case .stopping:
                Label(loc.t("recording_stopping"), systemImage: "stop.circle")
                    .foregroundColor(.orange)

            case .analyzing:
                Label(loc.t("recording_analyzing"), systemImage: "waveform.path.ecg")
                    .foregroundColor(.blue)

            case .success(let svc, _):
                Label(loc.t("recording_success"), systemImage: "checkmark.seal.fill")
                    .foregroundColor(.green)
                Text(svc).font(.caption).foregroundColor(.secondary)
                Button(loc.t("dismiss")) {
                    vpn.recordingState = .idle
                    serviceName = ""
                }
                .font(.caption)

            case .failed(let svc, let reason):
                VStack(alignment: .leading, spacing: 4) {
                    Label(loc.t("recording_failed"), systemImage: "xmark.octagon.fill")
                        .foregroundColor(.red)
                    Text("\(svc): \(reason)").font(.caption).foregroundColor(.secondary)
                    Button(loc.t("dismiss")) {
                        vpn.recordingState = .idle
                    }
                    .font(.caption)
                }
            }

            if let result = vpn.lastRecordingResult {
                Divider()
                HStack {
                    Image(systemName: result.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(result.succeeded ? .green : .red)
                    VStack(alignment: .leading) {
                        Text(result.title).font(.caption).bold()
                        Text(result.details).font(.caption2).foregroundColor(.secondary)
                    }
                    Spacer()
                    Button(loc.t("dismiss")) { vpn.clearRecordingResult() }
                        .font(.caption2)
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }
}

// MARK: - Card container

private struct CardView<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }
}

// MARK: - Main ContentView

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    @Environment(\.openURL) private var openURL

    @AppStorage("fullTunnel") private var fullTunnel: Bool = true
    @AppStorage("adaptiveLevel") private var adaptiveLevel: Int = 0
    @AppStorage("killSwitch") private var killSwitch: Bool = false
    @State private var showDiagnostics: Bool = false
    @State private var showAddKey: Bool = false
    @State private var editingKey: ConnectionKey?
    @State private var deleteKeyId: String?
    @State private var showDeleteConfirm: Bool = false
    @State private var showSplitTunnel: Bool = false
    @State private var showBootstrapDiscovery: Bool = false
    @State private var showAdmin: Bool = false
    // C3-iOS: SSH server-install wizard + migration guide, gated the same
    // way as showAdmin (server-assigned Admin role only) — see
    // InstallServerView.swift / MigrationView.swift.
    @State private var showInstallWizard: Bool = false
    @State private var showMigration: Bool = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Fixed header — status ring stays visible even when user scrolls
                statusCard
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .padding(.bottom, 4)

                Divider()

                ScrollView {
                    VStack(spacing: 16) {
                        if vpn.isConnected { trafficCard }
                        keysCard
                        if !vpn.isConnected { settingsCard }
                        if vpn.isConnected && vpn.recordingCapabilityKnown && vpn.canRecordMasks {
                            RecordingSection()
                                .environmentObject(vpn)
                                .environmentObject(loc)
                        }
                        footerView
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .padding(.bottom, 16)
                }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                connectCard
                    .padding(.horizontal, 16)
                    .padding(.top, 12)
                    .padding(.bottom, 8)
                    .background(.ultraThinMaterial, ignoresSafeAreaEdges: .bottom)
            }
            .navigationTitle("AIVPN")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { loc.toggleLanguage() } label: {
                        Text(loc.language == "en" ? "RU" : "EN")
                            .font(.caption)
                            .padding(4)
                            .background(Color(.secondarySystemBackground))
                            .cornerRadius(6)
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showSplitTunnel = true } label: {
                        Image(systemName: "network")
                    }
                }
                // In-app admin (P3.2): only the server-assigned Admin role
                // (2) may reach the client-management screen — Viewer/User
                // never see the button at all. `vpn.isConnected` gates
                // AdminApi.role() being meaningful (it caches the last
                // Capabilities push, reset to User at the start of each
                // session) and also re-evaluates this every second while
                // connected via VPNManager's durationTimer-driven
                // @Published updates, so the button appears shortly after
                // the post-handshake Capabilities message arrives without
                // any extra polling here.
                if vpn.isConnected && AdminApi.role() == 2 {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { showAdmin = true } label: {
                            Image(systemName: "person.badge.key.fill")
                        }
                    }
                    // C3-iOS: SSH server install + migration wizards, same
                    // admin-only gate as the button above. Grouped under one
                    // Menu rather than two more standalone toolbar icons to
                    // avoid nav-bar overflow next to the language/split-tunnel/
                    // admin buttons already there.
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Menu {
                            Button {
                                showInstallWizard = true
                            } label: {
                                Label(loc.t("install_wizard_title"), systemImage: "server.rack")
                            }
                            Button {
                                showMigration = true
                            } label: {
                                Label(loc.t("migrate_title"), systemImage: "shippingbox")
                            }
                        } label: {
                            Image(systemName: "wrench.and.screwdriver")
                        }
                        .accessibilityLabel(Text(loc.t("install_wizard_title")))
                    }
                }
            }
            .toolbarBackground(Color(.secondarySystemBackground), for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
        .sheet(isPresented: $showAddKey) {
            KeyEditSheet(existingKey: nil,
                onSave: { name, val, cert, signingKey in
                    // Strict check (32-byte `k` in base64 or hex + non-empty `s`),
                    // mirroring the tunnel's parser — not just "serverAddress parsed".
                    guard ConnectionKey.isValidKeyString(val) else {
                        return loc.t("error_invalid_key")
                    }
                    guard vpn.addKey(name: name, keyValue: val, mtlsCert: cert,
                                     serverSigningKey: signingKey) else {
                        return loc.t("duplicate_key")
                    }
                    showAddKey = false
                    return nil
                },
                onCancel: { showAddKey = false }
            )
            .environmentObject(loc)
        }
        .sheet(item: $editingKey) { key in
            KeyEditSheet(existingKey: key,
                onSave: { name, val, cert, signingKey in
                    // Same strict validation as the add sheet above.
                    guard ConnectionKey.isValidKeyString(val) else {
                        return loc.t("error_invalid_key")
                    }
                    guard vpn.updateKey(id: key.id, name: name, keyValue: val, mtlsCert: cert,
                                        serverSigningKey: signingKey) else {
                        return loc.t("duplicate_key")
                    }
                    editingKey = nil
                    return nil
                },
                onCancel: { editingKey = nil }
            )
            .environmentObject(loc)
        }
        .confirmationDialog(loc.t("delete_key_confirm"),
                            isPresented: $showDeleteConfirm,
                            titleVisibility: .visible) {
            Button(loc.t("delete"), role: .destructive) {
                if let id = deleteKeyId { vpn.deleteKey(id: id) }
                deleteKeyId = nil
            }
            Button(loc.t("cancel"), role: .cancel) { deleteKeyId = nil }
        } message: {
            Text(loc.t("delete_key_message"))
        }
        .sheet(isPresented: $showSplitTunnel) {
            SplitTunnelView().environmentObject(loc)
        }
        .sheet(isPresented: $showBootstrapDiscovery) {
            BootstrapDiscoveryView()
                .environmentObject(vpn)
                .environmentObject(loc)
        }
        .sheet(isPresented: $showAdmin) {
            AdminView()
                .environmentObject(loc)
        }
        .sheet(isPresented: $showInstallWizard) {
            InstallServerView()
                .environmentObject(vpn)
                .environmentObject(loc)
        }
        .sheet(isPresented: $showMigration) {
            MigrationView()
                .environmentObject(vpn)
                .environmentObject(loc)
        }
        .sheet(isPresented: $showDiagnostics) {
            NavigationStack {
                VStack(spacing: 20) {
                    if vpn.isBenchRunning {
                        ProgressView(loc.t("bench_running"))
                    } else if let result = vpn.benchResult {
                        VStack(spacing: 8) {
                            Text("\(loc.t("bench_quality_label")): \(result.quality)/100")
                                .font(.title2).fontWeight(.bold)
                                .foregroundColor(result.quality >= 80 ? .green : result.quality >= 50 ? .orange : .red)
                            Text("\(loc.t("bench_p50_label")): \(result.p50ms) \(loc.t("bench_ms"))")
                                .font(.subheadline).foregroundColor(.secondary)
                            Text(result.serverAddr)
                                .font(.caption2).foregroundColor(.secondary)
                        }
                    } else {
                        Text(loc.t("bench_idle"))
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding()
                    }
                    Button(loc.t("run_benchmark")) {
                        vpn.runBenchmark()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(vpn.isBenchRunning || vpn.selectedKey == nil)
                }
                .navigationTitle(loc.t("diagnostics"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button(loc.t("done")) { showDiagnostics = false }
                    }
                }
                .padding()
            }
        }
    }

    // MARK: - Status card

    private var statusCard: some View {
        VStack(spacing: 10) {
            StatusRing(isConnected: vpn.isConnected, isConnecting: vpn.isConnecting, isDisconnecting: vpn.isDisconnecting)
            Text(statusLabel)
                .font(.headline)
                .foregroundColor(statusColor)
            if let err = vpn.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .lineLimit(4)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if vpn.lastError != nil && !vpn.isConnected && !vpn.isConnecting {
                HStack(spacing: 8) {
                    Button {
                        vpn.retryManagerSetup()
                    } label: {
                        Label(loc.t("retry"), systemImage: "arrow.clockwise")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Button {
                        if let url = URL(string: "prefs:root=VPN") { openURL(url) }
                    } label: {
                        Label(loc.t("open_settings"), systemImage: "gear")
                            .font(.caption)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .padding(.horizontal, 16)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    // MARK: - Traffic card

    private var trafficCard: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                statCell(icon: "arrow.up.circle.fill", color: .blue,
                         label: loc.t("upload"), value: formatBytes(vpn.bytesSent))
                Divider().frame(height: 52)
                statCell(icon: "arrow.down.circle.fill", color: .green,
                         label: loc.t("download"), value: formatBytes(vpn.bytesReceived))
                Divider().frame(height: 52)
                statCell(icon: "clock.fill", color: .orange,
                         label: loc.t("duration"), value: formatDuration(vpn.connectionDuration))
                Divider().frame(height: 52)
                statCell(
                    icon: "chart.bar.fill",
                    color: vpn.liveQuality >= 80 ? .green : vpn.liveQuality >= 50 ? .orange : .red,
                    label: loc.t("quality"),
                    value: vpn.liveQuality > 0 ? "\(vpn.liveQuality)/100" : "—"
                )
            }
            if vpn.serverAdaptiveLevel >= 2 {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "waveform.path")
                        .foregroundColor(.purple)
                        .font(.caption)
                    Text(loc.t("fec_active"))
                        .font(.caption)
                        .foregroundColor(.purple)
                    Spacer()
                    Text("L\(vpn.serverAdaptiveLevel)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
            }
        }
        .frame(maxWidth: .infinity)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    // MARK: - Keys card

    private var keysCard: some View {
        CardView {
            HStack {
                Text(loc.t("connection_keys"))
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.secondary)
                Spacer()
                Button { showAddKey = true } label: {
                    Image(systemName: "plus.circle.fill")
                        .font(.title3)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 14)
            .padding(.bottom, 10)

            Divider().padding(.leading, 16)

            if vpn.keys.isEmpty {
                VStack(spacing: 8) {
                    Text(loc.t("no_keys_yet")).foregroundColor(.secondary)
                    Button(loc.t("add_first_key")) { showAddKey = true }
                        .buttonStyle(.bordered)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
            } else {
                ForEach(vpn.keys) { key in
                    KeyRowView(
                        key: key,
                        isSelected: vpn.selectedKeyId == key.id,
                        onSelect: { vpn.selectKey(id: key.id) },
                        onEdit: { editingKey = key },
                        onDelete: {
                            deleteKeyId = key.id
                            showDeleteConfirm = true
                        },
                        onAddNew: { showAddKey = true }
                    )
                    .padding(.horizontal, 16)
                    .padding(.vertical, 2)

                    if key.id != vpn.keys.last?.id {
                        Divider().padding(.leading, 16)
                    }
                }
                .padding(.bottom, 8)
            }

            // Collapsed by default: operator-facing flow for discovering a
            // server without an existing aivpn:// key, via signed rotating
            // bootstrap descriptors (CDN/GitHub/Telegram). See
            // BootstrapDiscovery.swift for the fetch/verify implementation.
            DisclosureGroup(loc.t("advanced_section")) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(loc.t("advanced_hint"))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Button(loc.t("bootstrap_open_discovery")) {
                        showBootstrapDiscovery = true
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 12)
        }
    }

    // MARK: - Settings card

    private var settingsCard: some View {
        CardView {
            Text(loc.t("settings"))
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundColor(.secondary)
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 10)

            Divider().padding(.leading, 16)

            VStack(spacing: 0) {
                Toggle(loc.t("full_tunnel"), isOn: $fullTunnel)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                Toggle(loc.t("kill_switch"), isOn: $killSwitch)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                HStack {
                    Text(loc.t("adaptive_mode"))
                    Spacer()
                    Picker("", selection: $adaptiveLevel) {
                        Text(loc.t("adaptive_off")).tag(0)
                        Text(loc.t("adaptive_light")).tag(1)
                        Text(loc.t("adaptive_aggressive")).tag(2)
                        Text(loc.t("adaptive_satellite")).tag(3)
                    }
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                HStack {
                    Text(loc.t("mask_profile"))
                    Spacer()
                    Picker("", selection: $vpn.preferredMask) {
                        Text(loc.t("mask_auto")).tag("auto")
                        if vpn.maskCatalog.isEmpty {
                            // Fallback until the server catalog has been received.
                            Text("WebRTC Zoom").tag("webrtc_zoom_v3")
                            Text("QUIC/HTTPS").tag("quic_https_v2")
                            Text("Yandex Telemost").tag("webrtc_yandex_telemost_v1")
                            Text("VK Teams").tag("webrtc_vk_teams_v1")
                            Text("SberJazz").tag("webrtc_sberjazz_v1")
                        } else {
                            ForEach(vpn.maskCatalog.filter { $0.mask_id != "auto" }) { item in
                                Text(item.label + (item.generated ? loc.t("mask_auto_marker") : ""))
                                    .tag(item.mask_id)
                            }
                        }
                    }
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                // §3 Polymorphic masks: no effect while `preferredMask == "auto"`
                // since there is no concrete base mask id to perturb (see
                // VPNManager.connect()).
                Toggle(loc.t("polymorphic_mode"), isOn: $vpn.polymorphicEnabled)
                    .disabled(vpn.preferredMask == "auto")
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                // §2 crowdsourced blocking feedback — opt-in, OFF by default.
                Toggle(loc.t("share_mask_feedback"), isOn: $vpn.shareMaskFeedback)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                Toggle(loc.t("receive_mask_hints"), isOn: $vpn.receiveMaskHints)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                Divider().padding(.leading, 16)

                HStack {
                    Text(loc.t("country_code"))
                    Spacer()
                    TextField(loc.t("country_code_placeholder"), text: $vpn.countryCode)
                        .multilineTextAlignment(.trailing)
                        .autocapitalization(.allCharacters)
                        .disableAutocorrection(true)
                        .frame(width: 60)
                        .onChange(of: vpn.countryCode) { newValue in
                            let filtered = String(newValue.uppercased().prefix(2).filter { $0.isLetter })
                            if filtered != newValue { vpn.countryCode = filtered }
                        }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
        }
    }

    // MARK: - Connect card

    private var connectCard: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    showDiagnostics = true
                } label: {
                    Label(loc.t("diagnostics"), systemImage: "chart.bar.xaxis")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(vpn.selectedKey == nil)

                Button {
                    showSplitTunnel = true
                } label: {
                    Label(loc.t("split_tunnel_title"), systemImage: "network")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }

            Button {
                if vpn.isConnected {
                    vpn.disconnect()
                } else {
                    guard let key = vpn.selectedKey else { return }
                    vpn.connect(key: key, fullTunnel: fullTunnel,
                                adaptiveLevel: adaptiveLevel, killSwitch: killSwitch)
                }
            } label: {
                Label(
                    vpn.isConnected ? loc.t("disconnect") : loc.t("connect"),
                    systemImage: vpn.isConnected ? "stop.circle.fill" : "play.circle.fill"
                )
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(vpn.isConnected ? .red : .accentColor)
            .disabled(vpn.isConnecting || vpn.isDisconnecting || (!vpn.isConnected && vpn.selectedKey == nil))
            .controlSize(.large)
        }
    }

    // MARK: - Footer

    private var footerView: some View {
        Text(loc.t("version_footer"))
            .font(.caption2)
            .foregroundColor(.secondary)
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.top, 8)
    }

    // MARK: - Computed helpers

    private var statusLabel: String {
        if vpn.isDisconnecting { return loc.t("status_disconnecting") }
        if vpn.isConnecting { return loc.t("status_connecting") }
        return vpn.isConnected ? loc.t("status_connected") : loc.t("status_disconnected")
    }

    private var statusColor: Color {
        if vpn.isDisconnecting { return .orange }
        return vpn.isConnected ? .green : (vpn.isConnecting ? .orange : .secondary)
    }

    private func statCell(icon: String, color: Color, label: String, value: String) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon).foregroundColor(color).font(.title3)
            Text(value).font(.system(.body, design: .monospaced)).bold()
            Text(label).font(.caption2).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
    }

}

