import SwiftUI

/// One entry of the server-pushed mask catalog (mirrors the JSON aivpn-client
/// writes to the temp file: `[{"mask_id","label","generated"},...]`).
struct MaskCatalogItem: Identifiable, Decodable {
    let mask_id: String
    let label: String
    let generated: Bool
    var id: String { mask_id }
}

/// Read the catalog aivpn-client persisted, trying the same paths it writes to.
/// Returns [] when no catalog has been received yet (caller keeps presets).
func loadMaskCatalogFile() -> [MaskCatalogItem] {
    var paths: [String] = []
    if let xdg = ProcessInfo.processInfo.environment["XDG_RUNTIME_DIR"] {
        paths.append(xdg + "/aivpn/mask_catalog.json")
    }
    paths.append("/var/run/aivpn/mask_catalog.json")
    paths.append("/tmp/aivpn-mask-catalog.json")
    for path in paths {
        guard let data = FileManager.default.contents(atPath: path) else { continue }
        if let items = try? JSONDecoder().decode([MaskCatalogItem].self, from: data) {
            // Only surface ids the helper's/client's pattern gate will accept
            // (lowercase alphanumerics + underscore, ≤64 chars) — a corrupted
            // or tampered catalog entry must not become a doomed connect.
            return items.filter {
                $0.mask_id == "auto" ||
                $0.mask_id.range(of: "^[a-z0-9_]{1,64}$", options: .regularExpression) != nil
            }
        }
    }
    return []
}

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    
    @State private var connectionKey: String = ""
    @State private var keyName: String = ""
    @State private var showKeyInput: Bool = false
    @State private var showConnectionKey: Bool = false
    @AppStorage("fullTunnel") private var fullTunnel: Bool = false
    @AppStorage("excludeRoutes") private var excludeRoutes: String = ""
    @AppStorage("proxyMode") private var proxyMode: Bool = false
    @AppStorage("proxyPort") private var proxyPort: String = "1080"
    @AppStorage("adaptiveLevel") private var adaptiveLevel: Int = 0
    @AppStorage("dnsProxyAddr") private var dnsProxyAddr: String = ""
    @AppStorage("killSwitch") private var killSwitch: Bool = false
    @AppStorage("preferred_mask") private var preferredMask: String = "auto"
    @AppStorage("polymorphicMask") private var polymorphicMask: Bool = false
    @AppStorage("shareMaskFeedback") private var shareMaskFeedback: Bool = false
    @AppStorage("receiveMaskHints") private var receiveMaskHints: Bool = false
    @AppStorage("maskCountryCode") private var maskCountryCode: String = ""
    @AppStorage("themePreference") private var themePreference: String = "system"
    @State private var showDiagnostics: Bool = false
    // P3.3-macOS: cached server-assigned role, refreshed (off main thread —
    // AdminApi.role() blocks on a socket round trip up to 10s) whenever the
    // tunnel connects. nil = unknown/unreachable/not connected; the admin
    // section only ever shows for an explicit AdminApi.roleAdmin match, so
    // "unknown" and "not admin" both fail closed to "hidden", never a
    // false-positive reveal.
    @State private var adminRole: UInt8? = nil
    @State private var benchRunning: Bool = false
    @State private var benchResult: BenchDisplayResult? = nil
    @State private var editingKeyId: String?
    @State private var editingKeyName: String = ""
    @State private var showDeleteConfirm = false
    @State private var keyToDelete: ConnectionKey?
    @State private var mtlsCertPath: String = ""
    @State private var recordingServiceName: String = ""
    // Server-pushed mask catalog (written by aivpn-client to a temp file). Drives
    // the dynamic mask Picker + its "(авто)" marker for auto-generated masks.
    @State private var maskCatalog: [MaskCatalogItem] = []
    @AppStorage("connectOnLaunch") private var connectOnLaunch: Bool = false
    // Advanced/operator bootstrap discovery (per-key, collapsed by default —
    // only needed when there's no working aivpn:// key yet).
    @State private var showBootstrapAdvanced: Bool = false
    @State private var bootstrapCdnUrl: String = ""
    @State private var bootstrapTelegramToken: String = ""
    @State private var bootstrapTelegramChat: String = ""
    @State private var bootstrapGithub: String = ""
    @State private var serverSigningKey: String = ""
    private let recordingDarkGreen = Color(red: 0.0, green: 0.35, blue: 0.16)

    var body: some View {
        // The NSPopover hosting this view has a fixed contentSize (see AivpnApp.swift).
        // Conditional sections below (Add Key form, recording panel, diagnostics, etc.)
        // can push the VStack's ideal height well past that fixed window size. Without
        // a ScrollView, anything past the fixed height renders outside the popover's
        // window bounds — invisible and un-clickable, even though the state that reveals
        // it (e.g. showKeyInput) toggled correctly. This was the actual reason "Add First
        // Key" appeared to do nothing: the form did open, just entirely below the fold.
        ScrollView {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 24, height: 24)
                Text("AIVPN")
                    .font(.headline)
                Spacer()
                // Language toggle
                Button(action: { loc.toggleLanguage() }) {
                    Text(loc.language == "en" ? "🇷🇺" : "🇬🇧")
                        .font(.title3)
                        .buttonStyle(.plain)
                }
                .buttonStyle(.plain)
                .help(loc.language == "en" ? "Русский" : "English")
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            // Helper status indicator
            HStack {
                Circle()
                    .fill(vpn.helperAvailable ? Color.green : (vpn.isCheckingHelper ? .secondary : Color.orange))
                    .frame(width: 8, height: 8)
                Text(helperStatusText)
                    .font(.caption2)
                    .foregroundColor(helperStatusColor)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.top, 6)
            .padding(.bottom, 2)

            Divider()

            // Connection status
            VStack(spacing: 8) {
                HStack {
                    Circle()
                        .fill(vpn.isConnected ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(vpn.isConnected ? loc.t("status_connected") :
                         vpn.isConnecting ? loc.t("connecting") :
                         loc.t("status_disconnected"))
                        .font(.subheadline)
                        .foregroundColor(vpn.isConnected ? .green : .secondary)
                    Spacer()
                }

                if vpn.isConnected {
                    HStack {
                        Text("↓ \(formatBytes(vpn.bytesReceived))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        if vpn.qualityScore > 0 {
                            Text("Q: \(vpn.qualityScore)/100")
                                .font(.caption)
                                .foregroundColor(vpn.qualityScore >= 80 ? .green :
                                                 vpn.qualityScore >= 50 ? .orange : .red)
                            Spacer()
                        }
                        if vpn.serverAdaptiveLevel > 0 {
                            let adaptiveLabels = ["Off", "Light", "Aggressive", "Satellite"]
                            let label = adaptiveLabels.indices.contains(vpn.serverAdaptiveLevel) ? adaptiveLabels[vpn.serverAdaptiveLevel] : "Level \(vpn.serverAdaptiveLevel)"
                            Text("A: \(label)")
                                .font(.caption)
                                .foregroundColor(.cyan)
                            Spacer()
                        }
                        if vpn.serverAdaptiveLevel >= 2 {
                            Text(loc.t("fec_badge"))
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 2)
                                .background(Color.orange)
                                .cornerRadius(4)
                            Spacer()
                        }
                        Text("↑ \(formatBytes(vpn.bytesSent))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if let error = vpn.lastError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .lineLimit(2)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()

            // Connection Keys List - ALWAYS VISIBLE
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(loc.t("connection_keys"))
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button(action: {
                        withAnimation {
                            showKeyInput = true
                            keyName = ""
                            connectionKey = ""
                            editingKeyId = nil
                            mtlsCertPath = ""
                            bootstrapCdnUrl = ""
                            bootstrapTelegramToken = ""
                            bootstrapTelegramChat = ""
                            bootstrapGithub = ""
                            serverSigningKey = ""
                            showBootstrapAdvanced = false
                        }
                    }) {
                        Image(systemName: "plus.circle.fill")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .help(loc.t("add_key"))
                }

                if vpn.keys.isEmpty && !showKeyInput {
                    // Empty state — hidden while the add-key form is open, so the
                    // "Add First Key" button can't be clicked again instead of Save.
                    VStack(spacing: 8) {
                        Image(systemName: "key")
                            .font(.system(size: 32))
                            .foregroundColor(.secondary)
                        Text(loc.t("no_keys_yet"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Button(loc.t("add_first_key")) {
                            withAnimation {
                                showKeyInput = true
                                keyName = ""
                                connectionKey = ""
                                editingKeyId = nil
                                mtlsCertPath = ""
                                bootstrapCdnUrl = ""
                                bootstrapTelegramToken = ""
                                bootstrapTelegramChat = ""
                                bootstrapGithub = ""
                                serverSigningKey = ""
                                showBootstrapAdvanced = false
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                } else {
                    // Keys list
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(vpn.keys) { key in
                                KeyRowView(
                                    key: key,
                                    isSelected: vpn.selectedKeyId == key.id,
                                    isConnected: vpn.isConnected,
                                    onSelect: {
                                        vpn.selectKey(id: key.id)
                                    },
                                    onEdit: {
                                        editingKeyId = key.id
                                        editingKeyName = key.name
                                        keyName = key.name
                                        connectionKey = key.keyValue
                                        mtlsCertPath = key.mtlsCertPath ?? ""
                                        bootstrapCdnUrl = key.bootstrapCdnUrl ?? ""
                                        bootstrapTelegramToken = key.bootstrapTelegramToken ?? ""
                                        bootstrapTelegramChat = key.bootstrapTelegramChat ?? ""
                                        bootstrapGithub = key.bootstrapGithub ?? ""
                                        serverSigningKey = key.serverSigningKey ?? ""
                                        showBootstrapAdvanced = [key.bootstrapCdnUrl, key.bootstrapTelegramToken,
                                                                  key.bootstrapTelegramChat, key.bootstrapGithub,
                                                                  key.serverSigningKey]
                                            .contains { !($0 ?? "").isEmpty }
                                        withAnimation {
                                            showKeyInput = true
                                        }
                                    },
                                    onDelete: {
                                        keyToDelete = key
                                        showDeleteConfirm = true
                                    }
                                )
                                .contentShape(Rectangle()) // Make entire row clickable
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .frame(maxHeight: 180)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.3))
            .cornerRadius(8)

            Divider()

            // Add Key Form (shown when adding new key)
            if showKeyInput {
                VStack(spacing: 8) {
                    TextField(loc.t("key_name"), text: $keyName)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11))
                    
                    HStack(spacing: 4) {
                        if showConnectionKey {
                            TextField(loc.t("enter_key"), text: $connectionKey)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 10))
                                .help("aivpn://...")
                        } else {
                            SecureField(loc.t("enter_key"), text: $connectionKey)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 10))
                                .help("aivpn://...")
                        }
                        Button(action: { showConnectionKey.toggle() }) {
                            Image(systemName: showConnectionKey ? "eye.slash" : "eye")
                                .foregroundColor(.secondary)
                                .font(.system(size: 11))
                        }
                        .buttonStyle(.plain)
                    }

                    HStack {
                        Toggle(loc.t("full_tunnel"), isOn: $fullTunnel)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("full_tunnel_help"))
                            .disabled(proxyMode)
                        Spacer()
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text(loc.t("exclude_routes_label"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField(loc.t("exclude_routes_placeholder"), text: $excludeRoutes)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 11, design: .monospaced))
                            .help(loc.t("exclude_routes_help"))
                            .disabled(proxyMode)
                    }

                    HStack {
                        Toggle(loc.t("proxy_mode"), isOn: $proxyMode)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("proxy_mode_help"))
                        Spacer()
                    }

                    if proxyMode {
                        HStack(spacing: 4) {
                            Text(loc.t("proxy_port"))
                                .font(.caption)
                                .foregroundColor(.secondary)
                            TextField("1080", text: $proxyPort)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .frame(width: 64)
                                .onChange(of: proxyPort) { newValue in
                                    let filtered = newValue.filter { $0.isNumber }
                                    if filtered != newValue { proxyPort = filtered }
                                }
                            Spacer()
                        }
                        if let cert = vpn.selectedKey?.mtlsCertPath, !cert.isEmpty {
                            HStack(spacing: 4) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.system(size: 10))
                                    .foregroundColor(.orange)
                                Text(loc.t("mtls_ignored_in_proxy_mode"))
                                    .font(.caption2)
                                    .foregroundColor(.orange)
                            }
                        }
                    }
                    
                    HStack {
                        Text(loc.t("adaptive_mode"))
                            .font(.caption)
                            .help(loc.t("adaptive_mode_help"))
                        Spacer()
                        Picker("", selection: $adaptiveLevel) {
                            Text(loc.t("adaptive_off")).tag(0)
                            Text(loc.t("adaptive_light")).tag(1)
                            Text(loc.t("adaptive_aggressive")).tag(2)
                            Text(loc.t("adaptive_satellite")).tag(3)
                        }
                        .pickerStyle(.menu)
                        .frame(maxWidth: 160)
                        .font(.caption)
                    }

                    HStack {
                        Text(loc.t("mask_profile"))
                            .font(.caption)
                            .help(loc.t("mask_profile_help"))
                        Spacer()
                        Picker("", selection: $preferredMask) {
                            Text(loc.t("mask_auto")).tag("auto")
                            if maskCatalog.isEmpty {
                                // Fallback until the server catalog has been received.
                                Text("WebRTC / Zoom").tag("webrtc_zoom_v3")
                                Text("QUIC / HTTPS").tag("quic_https_v2")
                                Text("Yandex Telemost").tag("webrtc_yandex_telemost_v1")
                                Text("VK Teams").tag("webrtc_vk_teams_v1")
                                Text("SberJazz").tag("webrtc_sberjazz_v1")
                            } else {
                                ForEach(maskCatalog.filter { $0.mask_id != "auto" }) { item in
                                    Text(item.label + (item.generated ? loc.t("mask_auto_marker") : ""))
                                        .tag(item.mask_id)
                                }
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(maxWidth: 160)
                        .font(.caption)
                        .onAppear { maskCatalog = loadMaskCatalogFile() }
                        .onChange(of: preferredMask) { newValue in
                            // "Auto" has no fixed base mask to polymorph from —
                            // leaving the toggle checked would be inert (disabled
                            // but still true), silently no-op'ing on connect.
                            if newValue == "auto" { polymorphicMask = false }
                        }
                    }

                    HStack {
                        Toggle(loc.t("polymorphic_mask"), isOn: $polymorphicMask)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("polymorphic_mask_help"))
                            .disabled(preferredMask == "auto")
                        Spacer()
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text(loc.t("mask_feedback_section"))
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Toggle(loc.t("share_mask_feedback"), isOn: $shareMaskFeedback)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("share_mask_feedback_help"))

                        Toggle(loc.t("receive_mask_hints"), isOn: $receiveMaskHints)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("receive_mask_hints_help"))

                        TextField(loc.t("country_code_placeholder"), text: $maskCountryCode)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 11))
                            .help(loc.t("country_code_help"))
                            .frame(width: 120)
                            .onChange(of: maskCountryCode) { newValue in
                                let filtered = String(newValue.uppercased().filter { $0.isASCII && $0.isLetter }.prefix(2))
                                if filtered != newValue { maskCountryCode = filtered }
                            }
                    }

                    TextField(loc.t("mtls_cert_path"), text: $mtlsCertPath)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11))
                        .help(loc.t("mtls_cert_path_help"))

                    TextField(loc.t("dns_proxy_placeholder"), text: $dnsProxyAddr)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11))
                        .help(loc.t("dns_proxy_help"))

                    HStack {
                        Toggle(loc.t("kill_switch"), isOn: $killSwitch)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("kill_switch_help"))
                            .disabled(proxyMode)
                        Spacer()
                    }

                    // Advanced/operator bootstrap discovery — collapsed by default.
                    // Lets a client with no working aivpn:// key yet discover a
                    // usable server/mask via signed multi-channel fallback.
                    DisclosureGroup(isExpanded: $showBootstrapAdvanced) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(loc.t("bootstrap_advanced_hint"))
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)

                            TextField(loc.t("bootstrap_cdn_url"), text: $bootstrapCdnUrl)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .help(loc.t("bootstrap_cdn_url_help"))

                            TextField(loc.t("bootstrap_telegram_token"), text: $bootstrapTelegramToken)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .help(loc.t("bootstrap_telegram_token_help"))

                            TextField(loc.t("bootstrap_telegram_chat"), text: $bootstrapTelegramChat)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .help(loc.t("bootstrap_telegram_chat_help"))

                            TextField(loc.t("bootstrap_github"), text: $bootstrapGithub)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .help(loc.t("bootstrap_github_help"))

                            TextField(loc.t("server_signing_key"), text: $serverSigningKey)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11))
                                .help(loc.t("server_signing_key_help"))
                        }
                        .padding(.top, 4)
                    } label: {
                        Text(loc.t("bootstrap_advanced_label"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    HStack(spacing: 8) {
                        Button(loc.t("cancel")) {
                            withAnimation {
                                showKeyInput = false
                                keyName = ""
                                connectionKey = ""
                                mtlsCertPath = ""
                                editingKeyId = nil
                                bootstrapCdnUrl = ""
                                bootstrapTelegramToken = ""
                                bootstrapTelegramChat = ""
                                bootstrapGithub = ""
                                serverSigningKey = ""
                                showBootstrapAdvanced = false
                            }
                        }
                        .buttonStyle(.bordered)

                        Button(loc.t("save_key")) {
                            let name = keyName.isEmpty ? "Key \(vpn.keys.count + 1)" : keyName

                            // Strict validation (base64 JSON with non-empty `s` and a
                            // 32-byte `k` — standard base64, the server's real format,
                            // or 64-hex) so a malformed key is rejected right here
                            // with a clear error instead of failing opaquely at
                            // connect time. Mirrors the tunnel/client parser rules.
                            guard ConnectionKey.isValidKeyString(connectionKey) else {
                                vpn.lastError = loc.t("error_invalid_key")
                                return
                            }

                            let cert = mtlsCertPath.trimmingCharacters(in: .whitespaces)
                            let cdnUrl = bootstrapCdnUrl.trimmingCharacters(in: .whitespaces)
                            let telegramToken = bootstrapTelegramToken.trimmingCharacters(in: .whitespaces)
                            let telegramChat = bootstrapTelegramChat.trimmingCharacters(in: .whitespaces)
                            let github = bootstrapGithub.trimmingCharacters(in: .whitespaces)
                            let signingKey = serverSigningKey.trimmingCharacters(in: .whitespaces)
                            if let editId = editingKeyId {
                                if vpn.updateKey(id: editId, name: name, keyValue: connectionKey,
                                                 mtlsCertPath: cert.isEmpty ? nil : cert,
                                                 bootstrapCdnUrl: cdnUrl.isEmpty ? nil : cdnUrl,
                                                 bootstrapTelegramToken: telegramToken.isEmpty ? nil : telegramToken,
                                                 bootstrapTelegramChat: telegramChat.isEmpty ? nil : telegramChat,
                                                 bootstrapGithub: github.isEmpty ? nil : github,
                                                 serverSigningKey: signingKey.isEmpty ? nil : signingKey) {
                                    withAnimation {
                                        showKeyInput = false
                                        keyName = ""
                                        connectionKey = ""
                                        mtlsCertPath = ""
                                        editingKeyId = nil
                                        bootstrapCdnUrl = ""
                                        bootstrapTelegramToken = ""
                                        bootstrapTelegramChat = ""
                                        bootstrapGithub = ""
                                        serverSigningKey = ""
                                        showBootstrapAdvanced = false
                                    }
                                } else {
                                    vpn.lastError = loc.t("duplicate_key")
                                }
                            } else {
                                if vpn.addKey(name: name, keyValue: connectionKey,
                                              mtlsCertPath: cert.isEmpty ? nil : cert,
                                              bootstrapCdnUrl: cdnUrl.isEmpty ? nil : cdnUrl,
                                              bootstrapTelegramToken: telegramToken.isEmpty ? nil : telegramToken,
                                              bootstrapTelegramChat: telegramChat.isEmpty ? nil : telegramChat,
                                              bootstrapGithub: github.isEmpty ? nil : github,
                                              serverSigningKey: signingKey.isEmpty ? nil : signingKey) {
                                    withAnimation {
                                        showKeyInput = false
                                        keyName = ""
                                        connectionKey = ""
                                        mtlsCertPath = ""
                                        bootstrapCdnUrl = ""
                                        bootstrapTelegramToken = ""
                                        bootstrapTelegramChat = ""
                                        bootstrapGithub = ""
                                        serverSigningKey = ""
                                        showBootstrapAdvanced = false
                                    }
                                } else {
                                    vpn.lastError = loc.t("duplicate_key")
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)

                        Spacer()
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }

            Divider()

            if let result = vpn.lastRecordingResult {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(result.succeeded ? loc.t("recording_result_success_title") : loc.t("recording_result_failed_title"))
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(result.succeeded ? recordingDarkGreen : .red)

                            Text(result.details)
                                .font(.caption)
                                .foregroundColor(.primary)
                                .fixedSize(horizontal: false, vertical: true)
                        }

                        Spacer()

                        Button(loc.t("dismiss")) {
                            vpn.clearRecordingResult()
                        }
                        .buttonStyle(.plain)
                        .font(.caption)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                Divider()
            }

            if vpn.isConnected && vpn.recordingCapabilityKnown && vpn.canRecordMasks {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(loc.t("record_new_mask"))
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.secondary)
                        Spacer()
                    }

                    Text(loc.t("recording_desc"))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    TextField(loc.t("record_service_name"), text: $recordingServiceName)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11))

                    Button(action: {
                        switch vpn.recordingState {
                        case .recording, .starting:
                            vpn.stopMaskRecording()
                        default:
                            let trimmed = recordingServiceName.trimmingCharacters(in: .whitespacesAndNewlines)
                            let service = trimmed.isEmpty ? "mask_\(Int(Date().timeIntervalSince1970))" : trimmed
                            recordingServiceName = service
                            vpn.startMaskRecording(serviceName: service)
                        }
                    }) {
                        HStack {
                            Spacer()
                            Image(systemName: recordingButtonIcon)
                            Text(recordingButtonTitle)
                            Spacer()
                        }
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(recordingButtonDisabled)

                    Text(recordingStatusText)
                        .font(.caption)
                        .foregroundColor(recordingStatusColor)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                Divider()
            }

            // Diagnostics panel (when connected)
            if vpn.isConnected {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(loc.t("diagnostics"))
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button(action: { showDiagnostics.toggle() }) {
                            Image(systemName: showDiagnostics ? "chevron.up" : "chevron.down")
                                .font(.caption2)
                        }
                        .buttonStyle(.plain)
                    }

                    if showDiagnostics {
                        if let result = benchResult {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text("Quality: \(result.qualityScore)/100")
                                        .font(.system(size: 12, weight: .semibold))
                                        .foregroundColor(result.qualityScore >= 80 ? .green :
                                                         result.qualityScore >= 50 ? .orange : .red)
                                    Spacer()
                                    Text("Loss: \(String(format: "%.1f", result.lossPct))%")
                                        .font(.caption)
                                        .foregroundColor(result.lossPct > 5 ? .red : .secondary)
                                }
                                Text("P50: \(Int(result.p50))ms  P95: \(Int(result.p95))ms  P99: \(Int(result.p99))ms")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        } else if benchRunning {
                            HStack(spacing: 6) {
                                ProgressView().scaleEffect(0.6)
                                Text(loc.t("bench_running"))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        } else {
                            Text(loc.t("bench_idle"))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Button(action: {
                            guard let keyModel = vpn.selectedKey ?? vpn.keys.first,
                                  let addr = serverAddrFromConnectionKey(keyModel.fullKey) else { return }
                            benchRunning = true
                            benchResult = nil
                            vpn.runBench(serverAddr: addr) { result in
                                benchResult = result
                                benchRunning = false
                            }
                        }) {
                            HStack {
                                Spacer()
                                Text(benchRunning ? loc.t("bench_running") : loc.t("run_benchmark"))
                                Spacer()
                            }
                            .padding(.vertical, 4)
                        }
                        .buttonStyle(.bordered)
                        .disabled(benchRunning)
                        .font(.caption)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Color(NSColor.controlBackgroundColor).opacity(0.3))
                .cornerRadius(8)

                Divider()
            }

            // Admin: client-management console (P3.3-macOS). Only ever shown
            // when the server-assigned role cached from the last Capabilities
            // control message is Admin (2) — never assignable from this app,
            // the server decides. Opens its own window (AdminWindowController)
            // rather than an inline section: the popover is a fixed 360×440
            // and a client list + add-client form + QR/save-panel flow needs
            // real room, the same way "Manage…"/"Preferences…" in other
            // menu-bar apps opens a separate window instead of growing the
            // popover indefinitely.
            if vpn.isConnected, adminRole == AdminApi.roleAdmin {
                Button(action: { AdminWindowController.shared.show() }) {
                    HStack {
                        Image(systemName: "person.2.badge.gearshape")
                            .font(.caption)
                        Text(loc.t("admin_panel_button"))
                            .font(.caption)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                // Wave C3-macOS: SSH server install + migration wizards.
                // Same admin-only gate as "Manage clients" above — both
                // open their own standalone window (InstallServerWindowController /
                // MigrationWindowController), mirroring AdminWindowController.
                Button(action: { InstallServerWindowController.shared.show() }) {
                    HStack {
                        Image(systemName: "server.rack")
                            .font(.caption)
                        Text(loc.t("install_wizard_button"))
                            .font(.caption)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                Button(action: { MigrationWindowController.shared.show() }) {
                    HStack {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.caption)
                        Text(loc.t("migrate_wizard_button"))
                            .font(.caption)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                Divider()
            }

            // Connect / Disconnect button
            Button(action: {
                if vpn.isConnected {
                    vpn.disconnect()
                } else {
                    guard let selectedKey = vpn.selectedKey ?? vpn.keys.first else {
                        vpn.lastError = loc.t("no_key_selected")
                        return
                    }
                    
                    // No dead "re-check helper" branch here: in non-proxy mode
                    // the button is disabled while the helper is unavailable,
                    // and proxy mode doesn't use the helper at all.
                    if proxyMode {
                        // Proxy mode explicitly means "SOCKS5, no root". Never fall
                        // through to the full-tunnel helper connect on a bad port —
                        // that would silently start a root VPN the user didn't ask for.
                        guard let port = Int(proxyPort), port > 1024 else {
                            vpn.lastError = loc.t("proxy_port_invalid")
                            return
                        }
                        vpn.connectProxy(key: selectedKey.keyValue, proxyPort: port,
                                         preferredMask: preferredMask == "auto" ? nil : preferredMask,
                                         polymorphicBase: (polymorphicMask && preferredMask != "auto") ? preferredMask : nil,
                                         shareMaskFeedback: shareMaskFeedback,
                                         receiveMaskHints: receiveMaskHints,
                                         countryCode: maskCountryCode.count == 2 ? maskCountryCode : nil)
                    } else {
                        vpn.connect(key: selectedKey.keyValue, fullTunnel: fullTunnel,
                                    mtlsCertPath: selectedKey.mtlsCertPath,
                                    excludeRoutes: excludeRoutes.isEmpty ? nil : excludeRoutes,
                                    adaptiveLevel: adaptiveLevel,
                                    dnsProxy: dnsProxyAddr.isEmpty ? nil : dnsProxyAddr,
                                    killSwitch: killSwitch,
                                    preferredMask: preferredMask == "auto" ? nil : preferredMask,
                                    polymorphicBase: (polymorphicMask && preferredMask != "auto") ? preferredMask : nil,
                                    shareMaskFeedback: shareMaskFeedback,
                                    receiveMaskHints: receiveMaskHints,
                                    countryCode: maskCountryCode.count == 2 ? maskCountryCode : nil,
                                    bootstrapCdnUrl: selectedKey.bootstrapCdnUrl,
                                    bootstrapTelegramToken: selectedKey.bootstrapTelegramToken,
                                    bootstrapTelegramChat: selectedKey.bootstrapTelegramChat,
                                    bootstrapGithub: selectedKey.bootstrapGithub,
                                    serverSigningKey: selectedKey.serverSigningKey)
                    }
                }
            }) {
                HStack {
                    Spacer()
                    if vpn.isConnecting {
                        ProgressView()
                            .scaleEffect(0.7)
                            .frame(width: 16, height: 16)
                        Text(loc.t("connecting"))
                    } else if vpn.isConnected {
                        Image(systemName: "stop.circle.fill")
                        Text(loc.t("disconnect"))
                    } else {
                        Image(systemName: "play.circle.fill")
                        Text(loc.t("connect"))
                    }
                    Spacer()
                }
                .padding(.vertical, 6)
                .foregroundStyle(connectButtonForegroundColor)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(connectButtonBackgroundColor)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(connectButtonBorderColor, lineWidth: connectButtonEnabled ? 0 : 1)
                )
            }
            .buttonStyle(.plain)
            .disabled(!connectButtonEnabled)
            .opacity(connectButtonEnabled ? 1.0 : 0.92)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()

            // Autoconnect toggle
            HStack {
                Toggle(loc.t("connect_on_launch"), isOn: $connectOnLaunch)
                    .toggleStyle(.checkbox)
                    .font(.caption2)
                    .help(loc.t("connect_on_launch_help"))
                    .onChange(of: connectOnLaunch) { newValue in
                        LaunchAgentManager.shared.setEnabled(newValue)
                    }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 4)

            // Theme picker (System / Light / Dark)
            HStack {
                Text(loc.t("theme"))
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .help(loc.t("theme_help"))
                Spacer()
                Picker("", selection: $themePreference) {
                    Text(loc.t("theme_system")).tag("system")
                    Text(loc.t("theme_light")).tag("light")
                    Text(loc.t("theme_dark")).tag("dark")
                }
                .pickerStyle(.menu)
                .frame(maxWidth: 120)
                .font(.caption2)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 4)

            Divider()

            // Footer
            HStack {
                Text("AIVPN v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?")")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                Spacer()
                Button(loc.t("quit")) {
                    // Synchronous disconnect with a short timeout: the async
                    // disconnect() races NSApp.terminate — the process would die
                    // before the helper IPC completes, leaving the VPN up.
                    vpn.disconnectBlocking()
                    NSApp.terminate(nil)
                }
                .font(.caption2)
                .buttonStyle(.plain)
                .foregroundColor(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        }
        .frame(width: 360, height: 440)
        .preferredColorScheme(colorSchemeOverride)
        .onAppear {
            connectOnLaunch = LaunchAgentManager.shared.isEnabled
            if vpn.isConnected {
                refreshAdminRole()
            }
        }
        .onReceive(vpn.$isConnected) { connected in
            if let appDelegate = NSApp.delegate as? AppDelegate {
                appDelegate.updateStatusIcon(connected: connected)
            }
            if connected {
                refreshAdminRole()
            } else {
                // Role is only meaningful for a live session (cached from
                // Capabilities, reset server-side on reconnect) — clear it
                // immediately on disconnect so a stale Admin reveal can't
                // outlive the session that granted it.
                adminRole = nil
            }
        }
        .confirmationDialog(loc.t("delete_key_confirm"), isPresented: $showDeleteConfirm) {
            Button(loc.t("delete"), role: .destructive) {
                if let key = keyToDelete {
                    vpn.deleteKey(id: key.id)
                }
                keyToDelete = nil
            }
            Button(loc.t("cancel"), role: .cancel) {}
        } message: {
            Text(loc.t("delete_key_message"))
        }
    }

    /// Maps the persisted "system"/"light"/"dark" preference to a ColorScheme override.
    /// nil means "follow the system appearance" (SwiftUI's default behavior).
    private var colorSchemeOverride: ColorScheme? {
        switch themePreference {
        case "light":
            return .light
        case "dark":
            return .dark
        default:
            return nil
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024.0) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(bytes) / 1024.0 / 1024.0) }
        return String(format: "%.1f GB", Double(bytes) / 1024.0 / 1024.0 / 1024.0)
    }

    private var helperStatusText: String {
        if vpn.helperAvailable {
            return loc.t("helper_ready")
        }
        if vpn.isCheckingHelper {
            return loc.t("helper_starting")
        }
        return loc.t("helper_missing")
    }

    private var helperStatusColor: Color {
        if vpn.helperAvailable || vpn.isCheckingHelper {
            return .secondary
        }
        return .orange
    }

    private var connectButtonEnabled: Bool {
        // Proxy mode (SOCKS5) never talks to the privileged helper — the
        // client is launched directly as the current user — so it must not be
        // gated on helper availability.
        !vpn.isConnecting && (proxyMode || vpn.helperAvailable) && !vpn.keys.isEmpty
    }

    private var connectButtonBackgroundColor: Color {
        if vpn.isConnected {
            return .red
        }
        if vpn.isConnecting || connectButtonEnabled {
            return .blue
        }
        return Color(nsColor: .controlBackgroundColor)
    }

    private var connectButtonForegroundColor: Color {
        if vpn.isConnected || vpn.isConnecting || connectButtonEnabled {
            return .white
        }
        return Color(nsColor: .labelColor)
    }

    private var connectButtonBorderColor: Color {
        Color(nsColor: .separatorColor)
    }

    private var recordingStatusText: String {
        switch vpn.recordingState {
        case .idle:
            return loc.t("recording_ready")
        case .starting:
            return loc.t("recording_starting")
        case .recording:
            return loc.t("recording_active")
        case .stopping:
            return loc.t("recording_stopping")
        case .analyzing:
            return loc.t("recording_analyzing")
        case .success(_, let maskId):
            if let maskId, !maskId.isEmpty {
                return "\(loc.t("recording_success")): \(maskId)"
            }
            return loc.t("recording_success")
        case .failed(_, let reason):
            let lowerReason = reason.lowercased()
            if lowerReason.contains("self-test") || lowerReason.contains("verification") || lowerReason.contains("провер") {
                return loc.t("recording_self_test_failed") + ": " + reason
            }
            return loc.t("recording_failed") + ": " + reason
        }
    }

    private var recordingStatusColor: Color {
        switch vpn.recordingState {
        case .idle:
            return recordingDarkGreen
        case .starting, .recording, .stopping, .analyzing:
            return recordingDarkGreen
        case .success:
            return recordingDarkGreen
        case .failed:
            return .red
        }
    }

    private var recordingButtonTitle: String {
        switch vpn.recordingState {
        case .recording, .starting:
            return loc.t("stop_recording")
        default:
            return loc.t("record_new_mask")
        }
    }

    private var recordingButtonIcon: String {
        switch vpn.recordingState {
        case .recording, .starting:
            return "stop.circle.fill"
        default:
            return "waveform.badge.magnifyingglass"
        }
    }

    private var recordingButtonDisabled: Bool {
        switch vpn.recordingState {
        case .stopping, .analyzing:
            return true
        default:
            return false
        }
    }

    /// Refreshes `adminRole` from the running daemon. `AdminApi.role()`
    /// performs a blocking socket round trip (up to 10s) so it MUST run off
    /// the main thread — SwiftUI would otherwise freeze the whole popover
    /// for up to that long on every connect. A stale/failed read (nil) just
    /// keeps the admin section hidden; it never shows a wrong role.
    private func refreshAdminRole() {
        DispatchQueue.global(qos: .utility).async {
            let role = AdminApi.role()
            DispatchQueue.main.async {
                adminRole = role
            }
        }
    }
}

// MARK: - Bench Display

/// Extract server address from an `aivpn://` connection key (base64url JSON ["s"] field).
func serverAddrFromConnectionKey(_ key: String) -> String? {
    guard key.hasPrefix("aivpn://") else { return nil }
    var b64 = String(key.dropFirst(8))
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    guard let data = Data(base64Encoded: b64),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let s = json["s"] as? String else { return nil }
    return s
}

struct BenchDisplayResult {
    let p50: Double
    let p95: Double
    let p99: Double
    let lossPct: Double
    let qualityScore: Int
}

// MARK: - Key Row View

struct KeyRowView: View {
    let key: ConnectionKey
    let isSelected: Bool
    let isConnected: Bool
    let onSelect: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    @EnvironmentObject var loc: LocalizationManager
    @State private var isHovering = false
    
    var body: some View {
        HStack(spacing: 10) {
            // Selection radio button - larger and more visible
            Circle()
                .fill(isSelected ? Color.green : Color.clear)
                .overlay(
                    Circle()
                        .stroke(isSelected ? Color.green : Color.gray, lineWidth: 2)
                )
                .frame(width: 16, height: 16)
            
            // Key info - full width clickable
            VStack(alignment: .leading, spacing: 3) {
                Text(key.name)
                    .font(.system(size: 12))
                    .fontWeight(isSelected ? .semibold : .regular)

                if key.isRecordingAdminKey {
                    Text("recording-admin")
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(.orange)
                }
                
                if let server = key.serverAddress {
                    HStack(spacing: 4) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 9))
                        Text(server)
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
                if let vpnIP = key.vpnIP {
                    HStack(spacing: 4) {
                        Image(systemName: "network")
                            .font(.system(size: 9))
                        Text(vpnIP)
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Connection status indicator
            if isSelected && isConnected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.system(size: 16))
                    .padding(.trailing, 4)
            }
            
            // Actions menu - larger button
            Menu {
                Button(action: onEdit) {
                    Label(loc.t("edit"), systemImage: "pencil")
                }
                Button(role: .destructive, action: onDelete) {
                    Label(loc.t("delete"), systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundColor(.secondary)
                    .font(.system(size: 14))
                    .padding(4)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? Color.green.opacity(0.1) : 
                      isHovering ? Color.gray.opacity(0.05) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.green.opacity(0.4) : Color.clear, lineWidth: 1.5)
        )
        .onHover { hovering in
            isHovering = hovering
        }
        .onTapGesture {
            onSelect()
        }
        // Make entire row clickable
        .contentShape(Rectangle())
    }
}
