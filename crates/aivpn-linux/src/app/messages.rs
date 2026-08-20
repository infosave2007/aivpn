//! `Message` — the iced Application's event/action enum. Moved verbatim out
//! of `app/mod.rs` (pure move, no behavior change).

use super::*;

#[derive(Debug, Clone)]
pub enum Message {
    /// Extra settings section (see `aivpn_common::ui_ext`): open/close the
    /// panel, edit one field, apply. The GUI treats these generically — it
    /// never learns what a field means.
    ToggleExtPanel,
    ExtToggleChanged(String, bool),
    ExtTextChanged(String, String),
    ExtSelectChanged(String, usize),
    ExtApply,
    Connect,
    /// The previous aivpn-client child has fully exited (reconnect path):
    /// its SIGTERM cleanup — route restore, kill-switch removal — is done,
    /// so it is now safe to spawn the new client.
    OldClientReaped,
    Disconnect,
    StatusReceived(VpnStatus),
    /// 3c: the client printed "AIVPN-STATUS bootstrap-fallback" — it gave up
    /// on the descriptor-derived mask after repeated dead handshakes and is
    /// using the built-in default mask instead. Orthogonal to `VpnStatus`
    /// (can be true while Connecting or Connected), so it isn't folded into
    /// that enum.
    BootstrapFallbackDetected,
    LogLine(String),
    ClearLog,
    SelectProfile(usize),
    ShowAddDialog,
    ShowEditDialog(usize),
    DlgNameChanged(String),
    DlgKeyChanged(String),
    DlgMtlsCertChanged(String),
    DlgFullTunnelToggled(bool),
    DlgSave,
    DlgCancel,
    RemoveProfile(usize),
    ToggleTheme,
    ToggleLang,
    ToggleKillSwitch(bool),
    AdaptiveLevelChanged(AdaptiveOption),
    DnsProxyChanged(String),
    ExcludeRoutesChanged(String),
    IncludeRoutesChanged(String),
    ToggleSocks5(bool),
    Socks5AddrChanged(String),
    StatsRefresh(TrafficStats),
    ToggleAutostart(bool),
    MaskOptionChanged(String),
    TogglePolymorphicMask(bool),
    ToggleShareMaskFeedback(bool),
    ToggleReceiveMaskHints(bool),
    CountryCodeChanged(String),
    TrayEvent(crate::tray::TrayAction),
    WindowCloseRequested(iced::window::Id),
    // Bootstrap descriptor discovery (advanced/operator settings)
    ToggleBootstrapPanel,
    BootstrapCdnUrlChanged(String),
    BootstrapTelegramTokenChanged(String),
    BootstrapTelegramChatChanged(String),
    BootstrapGithubChanged(String),
    ServerSigningKeyChanged(String),
    // Recording
    RecordServiceChanged(String),
    StartRecording,
    StopRecording,
    RecordingPoll(Option<RecordingSnapshot>),
    DismissRecordingResult,
    // Bench / Diagnostics
    RunDiagnostics,
    DiagnosticsResult(Option<String>),
    // Log panel
    ToggleLogPanel,
    SaveLog,
    SaveLogPathChosen(Option<std::path::PathBuf>),
    // ── Admin client-management panel (in-tunnel management API bridge) ────
    ToggleAdminPanel,
    AdminRoleLoaded(Result<u8, String>),
    AdminRefreshClients,
    AdminClientsLoaded(Result<Vec<ClientRecord>, String>),
    AdminNewNameChanged(String),
    AdminNewOneTimeToggled(bool),
    AdminNewExpiresChanged(String),
    AdminNewExitNodeChanged(String),
    /// G-B1: pick_list convenience selector beside `AdminNewExitNodeChanged`'s
    /// free-text field — `Default`/`Node(addr)` overwrite the field,
    /// `Custom` is a no-op (see `ExitNodeSelection`).
    AdminNewExitNodePicked(ExitNodeChoice),
    AdminAddClient,
    AdminAddClientResult(Result<ClientRecord, String>),
    AdminToggleEnabled(String, bool),
    AdminToggleEnabledResult(Result<ClientRecord, String>),
    AdminStartEdit(String),
    AdminEditNameChanged(String),
    AdminEditExpiresChanged(String),
    AdminEditExitNodeChanged(String),
    /// G-B1: same convenience selector as `AdminNewExitNodePicked`, for the
    /// per-client edit row's exit-node field.
    AdminEditExitNodePicked(ExitNodeChoice),
    AdminEditSave,
    AdminEditCancel,
    AdminEditResult(Result<ClientRecord, String>),
    AdminResetDevice(String),
    AdminResetDeviceResult(String, Result<(), String>),
    AdminRevokeRequest(String),
    AdminRevokeCancel,
    AdminRevokeConfirm(String),
    AdminRevokeResult(String, Result<(), String>),
    AdminShowKey(String),
    AdminKeyLoaded(String, Result<String, String>),
    AdminCloseKeyView,
    AdminCopyKey(String),
    AdminSaveKeyToFile,
    AdminSaveKeyPathChosen(Option<std::path::PathBuf>),
    AdminRequestQr(String),
    AdminQrLoaded(String, Result<Vec<u8>, String>),
    AdminSaveQrToFile,
    AdminSaveQrPathChosen(Option<std::path::PathBuf>),
    // ── Pool topology panel (B3: pool nodes + health, admin-role gated) ────
    TogglePoolPanel,
    PoolRefresh,
    PoolNodesLoaded(Result<Vec<PoolNode>, String>),
    PoolHealthLoaded(Result<PoolHealth, String>),
    // ── G-A2: audit-log panel (Viewer + Admin, GET-only, hash-chain view) ──
    ToggleAuditPanel,
    AuditRefresh,
    AuditLogLoaded(Result<AuditLogView, String>),
    // ── G-A3: Server Settings (Admin-only apply-with-rollback) ──────────
    ToggleServerSettingsPanel,
    ServerSettingsMaskClientPicked(AdminClientChoice),
    ServerSettingsMaskPicked(MaskChoice),
    ServerSettingsApplyMask,
    ServerSettingsExitNodeChanged(String),
    /// G-B1-style convenience selector beside `ServerSettingsExitNodeChanged`'s
    /// free-text field — `Default`/`Node(addr)` overwrite the field, `Custom`
    /// is a no-op (see `ExitNodeSelection`).
    ServerSettingsExitNodePicked(ExitNodeChoice),
    ServerSettingsApplyExitNode,
    ServerSettingsApplyResult(ServerSettingsPendingKind, Result<String, String>),
    ServerSettingsConfirm,
    ServerSettingsConfirmResult(Result<(), String>),
    /// Once-a-second tick while `server_settings_pending.is_some()` — see
    /// the conditional `Subscription` in `subscription()`.
    ServerSettingsCountdownTick,
    // ── C3: "Install server via SSH" wizard ─────────────────────────────
    ToggleInstallWizard,
    InstallHostChanged(String),
    InstallPortChanged(String),
    InstallUserChanged(String),
    InstallAuthModeToggled(bool),
    InstallPasswordChanged(String),
    InstallKeyFileChanged(String),
    InstallKeyPassphraseChanged(String),
    InstallBinarySourceChanged(InstallBinarySourceKind),
    InstallBinaryUrlChanged(String),
    InstallBinaryFileChanged(String),
    InstallBinaryFileBrowse,
    InstallBinaryFilePicked(Option<std::path::PathBuf>),
    InstallServerIpChanged(String),
    InstallServerPortChanged(String),
    InstallModeToggled(bool),
    InstallBindDeviceToggled(bool),
    InstallShowScript,
    InstallScriptLoaded(Result<(String, String), String>),
    InstallHideScript,
    InstallProbe,
    InstallProbeResult(Result<String, String>),
    InstallTrustFingerprint,
    InstallDistrust,
    InstallStart,
    InstallWizardLine(InstallLine),
    InstallWizardFinished(i32),
    InstallWizardSpawnError(String),
    InstallReset,
    InstallImportProfile,
    // Misc
    Noop,
}
