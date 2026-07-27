use crate::admin::{self, AdminRequest, AdminResponse};
use crate::install_wizard;
use crate::{SshBinarySourceChoice, SshWizardStage, ADMIN_SETTINGS_CONFIRM_TIMEOUT};
use std::time::Instant;

impl super::AivpnApp {
    // ── Admin panel (P3.4) ──────────────────────────────────────────────

    /// Drain every pending `AdminResponse` and apply it to UI state. Called
    /// once per `tick()`.
    pub(crate) fn poll_admin(&mut self) {
        while let Ok(msg) = self.admin_rx.try_recv() {
            match msg {
                AdminResponse::Role(r) => match r {
                    Ok(role) => {
                        self.admin_role = Some(role);
                        // G-A1: the client list is a plain GET the server's
                        // `authorize()` already permits a Viewer — only the
                        // mutating controls inside `draw_admin_clients_
                        // section` stay Admin-only, gated by `can_mutate`.
                        if role >= 1 && !self.admin_clients_loaded {
                            self.admin_clients_loaded = true;
                            self.refresh_admin_clients();
                        }
                        // B3: pool topology is Viewer(1)+Admin(2) readable —
                        // see `mgmt_service.rs`'s `authorize`.
                        if role >= 1 && !self.admin_pool_loaded {
                            self.admin_pool_loaded = true;
                            self.refresh_admin_pool();
                        }
                        // G-A2: audit log is likewise Viewer(1)+Admin(2)
                        // GET-only readable.
                        if role >= 1 && !self.admin_audit_loaded {
                            self.admin_audit_loaded = true;
                            self.refresh_admin_audit();
                        }
                    }
                    Err(_) => {
                        // Fails closed: an unreadable/unknown role never
                        // shows the panel, same as an explicit User role.
                        self.admin_role = Some(0);
                    }
                },
                AdminResponse::Clients(r) => {
                    self.admin_clients_loading = false;
                    match r {
                        Ok(list) => {
                            self.admin_clients = list;
                            self.admin_clients_error = None;
                        }
                        Err(e) => self.admin_clients_error = Some(e),
                    }
                }
                // `editing` comes from the ORIGINATING request, not from
                // "is the edit form open right now" — see the variant's doc
                // comment in admin.rs (BUG FIX: overlapping add/edit used to
                // misroute errors and close the wrong form).
                AdminResponse::ClientSaved { editing, result } => {
                    if editing {
                        self.admin_edit_busy = false;
                    } else {
                        self.admin_add_busy = false;
                    }
                    match result {
                        Ok(_) => {
                            if editing {
                                self.admin_edit_id = None;
                                self.admin_edit_error = None;
                            } else {
                                self.admin_show_add = false;
                                self.admin_add_error = None;
                            }
                            self.refresh_admin_clients();
                        }
                        Err(e) => {
                            if editing {
                                self.admin_edit_error = Some(e);
                            } else {
                                self.admin_add_error = Some(e);
                            }
                        }
                    }
                }
                AdminResponse::ClientDeleted { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::ClientRevoked { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    if self.admin_revoke_id.as_deref() == Some(id.as_str()) {
                        self.admin_revoke_id = None;
                    }
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::DeviceReset { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::ConnectionKey { id, result } => {
                    // Only touch UI state if this answers the client the
                    // viewer window CURRENTLY shows — a stale response for a
                    // previously-viewed client must not clear the loading
                    // spinner of the request still in flight for the current
                    // one (BUG FIX, review: `loading = false` used to run
                    // before this id check).
                    if self.admin_key_id.as_deref() == Some(id.as_str()) {
                        self.admin_key_loading = false;
                        match result {
                            Ok(key) => {
                                self.admin_key_value = Some(key);
                                self.admin_key_error = None;
                            }
                            Err(e) => self.admin_key_error = Some(e),
                        }
                    }
                }
                AdminResponse::Qr { id, result } => {
                    // Same stale-response guard as ConnectionKey above.
                    if self.admin_key_id.as_deref() == Some(id.as_str()) {
                        self.admin_qr_loading = false;
                        match result {
                            Ok(png) => {
                                self.admin_qr_png = Some(png);
                                self.admin_qr_texture = None; // rebuilt lazily on next draw
                                self.admin_qr_error = None;
                            }
                            Err(e) => self.admin_qr_error = Some(e),
                        }
                    }
                }
                AdminResponse::Status(r) => {
                    if let Ok(s) = r {
                        self.admin_status = Some(s);
                    }
                }
                AdminResponse::AuditLog(r) => {
                    self.admin_audit_loading = false;
                    match r {
                        Ok(view) => {
                            self.admin_audit = view.entries;
                            self.admin_audit_verified = view.verified;
                            self.admin_audit_broken_at = view.broken_at;
                            self.admin_audit_error = None;
                        }
                        Err(e) => self.admin_audit_error = Some(e),
                    }
                }
                AdminResponse::PoolNodes(r) => {
                    self.admin_pool_nodes_loading = false;
                    match r {
                        Ok(list) => {
                            self.admin_pool_nodes = list;
                            self.admin_pool_nodes_error = None;
                        }
                        Err(e) => self.admin_pool_nodes_error = Some(e),
                    }
                }
                AdminResponse::PoolHealth(r) => {
                    // Best-effort: a failed health fetch leaves the last
                    // known summary on screen rather than blanking it —
                    // `admin_pool_nodes_error` above already surfaces a
                    // pool-unreachable condition from the paired call.
                    if let Ok(h) = r {
                        self.admin_pool_health = Some(h);
                    }
                }
                AdminResponse::ConfigApplied { setting, result } => {
                    match setting {
                        admin::ConfigSetting::ActiveMask => self.admin_settings_mask_busy = false,
                        admin::ConfigSetting::ExitNode => self.admin_settings_exit_busy = false,
                    }
                    match result {
                        Ok(applied) => {
                            let deadline = Some(Instant::now() + ADMIN_SETTINGS_CONFIRM_TIMEOUT);
                            match setting {
                                admin::ConfigSetting::ActiveMask => {
                                    self.admin_settings_mask_token = Some(applied.token);
                                    self.admin_settings_mask_deadline = deadline;
                                    self.admin_settings_mask_error = None;
                                    self.admin_settings_mask_rolled_back = false;
                                }
                                admin::ConfigSetting::ExitNode => {
                                    self.admin_settings_exit_token = Some(applied.token);
                                    self.admin_settings_exit_deadline = deadline;
                                    self.admin_settings_exit_error = None;
                                    self.admin_settings_exit_rolled_back = false;
                                }
                            }
                        }
                        Err(e) => match setting {
                            admin::ConfigSetting::ActiveMask => {
                                self.admin_settings_mask_error = Some(e)
                            }
                            admin::ConfigSetting::ExitNode => {
                                self.admin_settings_exit_error = Some(e)
                            }
                        },
                    }
                }
                AdminResponse::ConfigConfirmed { setting, result } => {
                    match setting {
                        admin::ConfigSetting::ActiveMask => {
                            self.admin_settings_mask_confirm_busy = false
                        }
                        admin::ConfigSetting::ExitNode => {
                            self.admin_settings_exit_confirm_busy = false
                        }
                    }
                    match result {
                        Ok(()) => match setting {
                            admin::ConfigSetting::ActiveMask => {
                                self.admin_settings_mask_token = None;
                                self.admin_settings_mask_deadline = None;
                                self.admin_settings_mask_rolled_back = false;
                            }
                            admin::ConfigSetting::ExitNode => {
                                self.admin_settings_exit_token = None;
                                self.admin_settings_exit_deadline = None;
                                self.admin_settings_exit_rolled_back = false;
                            }
                        },
                        // Deliberately leaves token/deadline intact on a
                        // confirm error: it might be transient (the token
                        // itself may still be valid server-side), so the
                        // user gets another shot at Confirm before the
                        // LOCAL countdown (see `tick()`) times it out on
                        // its own. Only that local timeout — not a failed
                        // confirm call — ever sets `*_rolled_back`.
                        Err(e) => self.show_error(e),
                    }
                }
            }
        }
    }

    // ── SSH server-install wizard (C3) ──────────────────────────────────

    /// Drain every pending streamed `InstallLine` plus the one-shot probe/
    /// script results, and apply them to wizard UI state. Called once per
    /// `tick()`, mirroring `poll_admin`.
    pub(crate) fn poll_ssh_install(&mut self) {
        // BUG FIX (review): `ssh_install_rx` is a fresh channel per install
        // run (see `start_ssh_install`), not a single app-lifetime pair —
        // that was the original bug. A single shared Sender/Receiver never
        // dropped for the app's whole lifetime meant closing the wizard
        // mid-install (the window's native ✕, handled by `close_ssh_wizard`)
        // left the background `spawn_install` thread still writing into the
        // same channel; if the user then reopened the wizard and started a
        // SECOND install, both threads' lines/markers interleaved into one
        // `ssh_install_log`, and whichever thread's `gui_process` terminal
        // marker arrived first could silently end the WRONG run's progress
        // display. Recreating the channel per run, and dropping it in
        // `close_ssh_wizard`, isolates each run: an abandoned thread's
        // `tx.send` starts failing (it already handles that — see
        // `spawn_install`'s doc comment) instead of polluting a later run.
        let mut rx_disconnected = false;
        // G-C1: set inside the `rx`-borrowing loop below, acted on after it
        // ends — `import_ssh_install_key` takes `&mut self`, which the
        // borrow checker can't reconcile with the outstanding `&self.
        // ssh_install_rx` borrow `rx` holds for the loop's duration (unlike
        // the direct field writes below, a `&mut self` method call is
        // opaque to it and would conflict).
        let mut auto_import_key = false;
        if let Some(rx) = &self.ssh_install_rx {
            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        if let install_wizard::InstallLine::Marker {
                            step,
                            status,
                            connection_key,
                            ..
                        } = &line
                        {
                            if let Some(key) = connection_key {
                                self.ssh_install_connection_key = Some(key.clone());
                                // G-C1: auto-import the moment the terminal
                                // success marker's key shows up — no more
                                // waiting on a manual "Import profile"
                                // click. `should_auto_import` also guards
                                // against double-importing if this marker
                                // is somehow observed twice in one run.
                                if install_wizard::should_auto_import(
                                    status,
                                    connection_key,
                                    self.ssh_import_done,
                                ) {
                                    auto_import_key = true;
                                }
                            }
                            // `gui_process` is spawn_install's own synthetic
                            // marker, always sent exactly once when the
                            // child exits (see install_wizard.rs's doc
                            // comment) — the one reliable "the subprocess is
                            // done" signal, regardless of whether the remote
                            // script/CLI got far enough to emit its own
                            // `done`/`client_done` markers.
                            if step == "gui_process" {
                                self.ssh_install_running = false;
                                self.ssh_install_done_ok = Some(status == "ok");
                                self.ssh_wizard_stage = SshWizardStage::Done;
                            }
                        }
                        self.ssh_install_log.push(line);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        rx_disconnected = true;
                        break;
                    }
                }
            }
        }
        // G-C1: now that `rx`'s borrow of `self.ssh_install_rx` has ended,
        // it's safe to call the `&mut self` import path.
        if auto_import_key {
            self.import_ssh_install_key();
        }
        if rx_disconnected {
            self.ssh_install_rx = None;
            // The sender thread is gone without ever sending its terminal
            // `gui_process` marker (e.g. it panicked) — don't leave the UI
            // stuck showing "Installing…" forever.
            if self.ssh_install_running {
                self.ssh_install_running = false;
                self.ssh_install_done_ok = Some(false);
                self.ssh_wizard_stage = SshWizardStage::Done;
            }
        }

        if let Some(rx) = &self.ssh_probe_rx {
            match rx.try_recv() {
                Ok(Ok(fingerprint)) => {
                    self.ssh_fingerprint = Some(fingerprint);
                    self.ssh_probe_busy = false;
                    self.ssh_probe_error = None;
                    self.ssh_probe_rx = None;
                }
                Ok(Err(e)) => {
                    self.ssh_probe_error = Some(e);
                    self.ssh_probe_busy = false;
                    self.ssh_probe_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.ssh_probe_busy = false;
                    self.ssh_probe_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(rx) = &self.ssh_script_rx {
            match rx.try_recv() {
                Ok(Ok((sha256, script))) => {
                    self.ssh_script_sha256 = Some(sha256);
                    self.ssh_script_text = Some(script);
                    self.ssh_script_loading = false;
                    self.ssh_script_error = None;
                    self.ssh_script_rx = None;
                }
                Ok(Err(e)) => {
                    self.ssh_script_error = Some(e);
                    self.ssh_script_loading = false;
                    self.ssh_script_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.ssh_script_loading = false;
                    self.ssh_script_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    /// `ssh-install probe` (TOFU step 1) on a background thread — see
    /// `install_wizard::probe`'s doc comment.
    pub(crate) fn start_ssh_probe(&mut self) {
        let host = self.ssh_host.trim().to_string();
        if host.is_empty() {
            self.ssh_probe_error = Some("Host is required".to_string());
            return;
        }
        let port: u16 = match self.ssh_port.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.ssh_probe_error = Some("Invalid port".to_string());
                return;
            }
        };
        let user = if self.ssh_user.trim().is_empty() {
            "root".to_string()
        } else {
            self.ssh_user.trim().to_string()
        };

        self.ssh_probe_busy = true;
        self.ssh_probe_error = None;
        self.ssh_fingerprint = None;
        self.ssh_trusted = false;

        let client_binary = self.vpn.client_binary.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_probe_rx = Some(rx);
        std::thread::spawn(move || {
            let result = install_wizard::probe(&client_binary, &host, port, &user);
            let _ = tx.send(result);
        });
    }

    /// `ssh-install script` + `--sha256-only` (paranoid-mode review) on a
    /// background thread — see `install_wizard::fetch_script`'s doc
    /// comment.
    pub(crate) fn start_fetch_script(&mut self) {
        if self.ssh_script_loading {
            return;
        }
        self.ssh_script_loading = true;
        self.ssh_script_error = None;
        let client_binary = self.vpn.client_binary.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_script_rx = Some(rx);
        std::thread::spawn(move || {
            let result = install_wizard::fetch_script(&client_binary);
            let _ = tx.send(result);
        });
    }

    /// Builds an `InstallTarget` from the wizard's form fields and starts
    /// `install_wizard::spawn_install` streaming into `ssh_install_rx`.
    /// Requires [`Self::ssh_fingerprint`] to already be `Some` (TOFU step 1
    /// must have completed) — the caller-side "Install" button is disabled
    /// otherwise, so this is an invariant, not a user-facing error path.
    pub(crate) fn start_ssh_install(&mut self) {
        let fingerprint = match &self.ssh_fingerprint {
            Some(f) => f.clone(),
            None => return,
        };
        let port: u16 = self.ssh_port.trim().parse().unwrap_or(22);
        let user = if self.ssh_user.trim().is_empty() {
            "root".to_string()
        } else {
            self.ssh_user.trim().to_string()
        };

        let (auth, secret) = if self.ssh_auth_key_mode {
            let has_passphrase = !self.ssh_key_passphrase.is_empty();
            (
                install_wizard::InstallAuth::KeyFile {
                    path: std::path::PathBuf::from(self.ssh_key_path.trim()),
                    has_passphrase,
                },
                has_passphrase.then(|| self.ssh_key_passphrase.clone()),
            )
        } else {
            (
                install_wizard::InstallAuth::Password,
                Some(self.ssh_password.clone()),
            )
        };

        // GAP-G3: default/URL/local-file — see `SshBinarySourceChoice`'s doc
        // comment. A blank URL/path silently falls back to `Default`
        // (`install_wizard::build_run_args` already trims+skips a blank
        // URL; a blank file path is passed through as-is, same as every
        // other path field in this wizard — `ssh-install run` itself is the
        // one that will reject an empty/missing `--binary-file`).
        let binary_source = match self.ssh_binary_source_choice {
            SshBinarySourceChoice::Default => install_wizard::BinarySource::Default,
            SshBinarySourceChoice::Url => {
                install_wizard::BinarySource::Url(self.ssh_binary_url.trim().to_string())
            }
            SshBinarySourceChoice::LocalFile => install_wizard::BinarySource::LocalFile(
                std::path::PathBuf::from(self.ssh_binary_file_path.trim()),
            ),
        };

        let target = install_wizard::InstallTarget {
            host: self.ssh_host.trim().to_string(),
            port,
            user,
            fingerprint,
            auth,
            mode: if self.ssh_mode_docker {
                install_wizard::InstallModeChoice::Docker
            } else {
                install_wizard::InstallModeChoice::Systemd
            },
            binary_source,
            server_ip: (!self.ssh_server_ip.trim().is_empty())
                .then(|| self.ssh_server_ip.trim().to_string()),
            server_port: self.ssh_server_port.trim().parse().ok(),
            bind_device: self.ssh_bind_device,
        };

        self.ssh_install_running = true;
        self.ssh_install_log.clear();
        self.ssh_install_connection_key = None;
        self.ssh_install_done_ok = None;
        self.ssh_import_done = false;
        self.ssh_wizard_stage = SshWizardStage::Installing;

        // Fresh channel per run — see `ssh_install_rx`'s doc comment (review
        // bug fix) for why this must not be a single app-lifetime pair.
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_install_rx = Some(rx);
        install_wizard::spawn_install(self.vpn.client_binary.clone(), target, secret, tx);
    }

    /// Adds the finished install's `connection_key` to `keys` under an
    /// auto-generated name, same validation path as the manual "Add key"
    /// dialog (`KeyStorage::add_key`).
    pub(crate) fn import_ssh_install_key(&mut self) {
        let Some(key) = self.ssh_install_connection_key.clone() else {
            return;
        };
        let name = if self.ssh_host.trim().is_empty() {
            "SSH install".to_string()
        } else {
            format!("SSH install ({})", self.ssh_host.trim())
        };
        match self
            .keys
            .add_key(&name, &key, false, None, None, Vec::new(), Vec::new())
        {
            Ok(()) => self.ssh_import_done = true,
            Err(e) => self.show_error(format!("Failed to import profile: {e}")),
        }
    }

    /// Closes the wizard and clears every per-run field (but not the
    /// host/port/user/mode/options form fields — left in place so
    /// reopening after a finished/failed run doesn't force retyping them).
    pub(crate) fn close_ssh_wizard(&mut self) {
        self.ssh_wizard_open = false;
        self.ssh_wizard_stage = SshWizardStage::Form;
        self.ssh_password.clear();
        self.ssh_key_passphrase.clear();
        self.ssh_probe_busy = false;
        self.ssh_probe_error = None;
        self.ssh_probe_rx = None;
        self.ssh_fingerprint = None;
        self.ssh_trusted = false;
        self.ssh_show_script = false;
        self.ssh_script_loading = false;
        self.ssh_script_rx = None;
        self.ssh_script_text = None;
        self.ssh_script_sha256 = None;
        self.ssh_script_error = None;
        self.ssh_install_running = false;
        self.ssh_install_log.clear();
        self.ssh_install_connection_key = None;
        self.ssh_install_done_ok = None;
        self.ssh_import_done = false;
        // Review bug fix: drop the receiver so a still-running background
        // install thread's `tx.send` starts failing (it already handles
        // that gracefully) instead of continuing to feed a NEW run's state
        // if the user reopens the wizard and starts another install before
        // this one's remote script has finished — see `ssh_install_rx`'s
        // and `poll_ssh_install`'s doc comments.
        self.ssh_install_rx = None;
    }

    pub(crate) fn refresh_admin_pool(&mut self) {
        self.admin_pool_nodes_loading = true;
        self.admin_pool_nodes_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::PoolNodes,
            self.admin_tx.clone(),
        );
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::PoolHealth,
            self.admin_tx.clone(),
        );
    }

    pub(crate) fn refresh_admin_clients(&mut self) {
        self.admin_clients_loading = true;
        self.admin_clients_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::ListClients,
            self.admin_tx.clone(),
        );
    }

    /// G-A2: refresh the audit-log panel — Viewer(1)+Admin(2), same as
    /// `refresh_admin_pool`.
    pub(crate) fn refresh_admin_audit(&mut self) {
        self.admin_audit_loading = true;
        self.admin_audit_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::AuditLog,
            self.admin_tx.clone(),
        );
    }

    /// Clear every admin-panel field back to its pre-session default.
    /// Called when the session leaves the Connected state — the panel
    /// (and its cached role/clients/dialogs) belongs to that one session
    /// only, never carries over to the next connect.
    pub(crate) fn reset_admin_state(&mut self) {
        self.admin_role = None;
        self.admin_clients_loaded = false;
        self.admin_clients.clear();
        self.admin_clients_loading = false;
        self.admin_clients_error = None;
        self.admin_busy_ids.clear();
        self.admin_status = None;
        self.admin_audit_loaded = false;
        self.admin_audit.clear();
        self.admin_audit_verified = None;
        self.admin_audit_broken_at = None;
        self.admin_audit_loading = false;
        self.admin_audit_error = None;
        self.admin_show_add = false;
        self.admin_add_error = None;
        self.admin_add_busy = false;
        self.admin_add_exit_node.clear();
        self.admin_add_exit_custom_mode = false;
        self.admin_edit_id = None;
        self.admin_edit_error = None;
        self.admin_edit_busy = false;
        self.admin_edit_exit_node.clear();
        self.admin_edit_exit_custom_mode = false;
        self.admin_pool_loaded = false;
        self.admin_pool_nodes.clear();
        self.admin_pool_nodes_loading = false;
        self.admin_pool_nodes_error = None;
        self.admin_pool_health = None;
        self.admin_key_id = None;
        self.admin_key_value = None;
        self.admin_key_loading = false;
        self.admin_key_error = None;
        self.admin_key_saved_msg = None;
        self.admin_qr_png = None;
        self.admin_qr_texture = None;
        self.admin_qr_loading = false;
        self.admin_qr_error = None;
        self.admin_qr_saved_msg = None;
        self.admin_revoke_id = None;
        self.admin_settings_mask_client.clear();
        self.admin_settings_mask_id.clear();
        self.admin_settings_mask_busy = false;
        self.admin_settings_mask_error = None;
        self.admin_settings_mask_token = None;
        self.admin_settings_mask_deadline = None;
        self.admin_settings_mask_confirm_busy = false;
        self.admin_settings_mask_rolled_back = false;
        self.admin_settings_exit_node.clear();
        self.admin_settings_exit_custom_mode = false;
        self.admin_settings_exit_busy = false;
        self.admin_settings_exit_error = None;
        self.admin_settings_exit_token = None;
        self.admin_settings_exit_deadline = None;
        self.admin_settings_exit_confirm_busy = false;
        self.admin_settings_exit_rolled_back = false;
    }

    /// Save the currently-displayed connection key to a `.txt` file next to
    /// the user's Downloads (falling back to their home directory). No file
    /// dialog is bundled here — this crate is kept dependency-light and
    /// already ships no `rfd`/similar — so the destination is fixed rather
    /// than user-chosen; the resulting path is shown back in the UI.
    pub(crate) fn save_admin_key_to_file(&mut self, key: &str) {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(format!("aivpn-key-{}.txt", self.sanitized_admin_key_name()));
        match std::fs::write(&path, key) {
            Ok(()) => self.admin_key_saved_msg = Some(path.display().to_string()),
            Err(e) => self.admin_key_error = Some(format!("Failed to save key: {e}")),
        }
    }

    /// Save the currently-displayed QR PNG next to the user's Downloads
    /// (same rationale/fallback as `save_admin_key_to_file`).
    pub(crate) fn save_admin_qr_to_file(&mut self, png: &[u8]) {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(format!("aivpn-key-{}.png", self.sanitized_admin_key_name()));
        match std::fs::write(&path, png) {
            Ok(()) => self.admin_qr_saved_msg = Some(path.display().to_string()),
            Err(e) => self.admin_qr_error = Some(format!("Failed to save QR: {e}")),
        }
    }

    /// Filesystem-safe stem derived from the client name currently shown in
    /// the key/QR viewer — falls back to "client" if the name has no
    /// alphanumeric characters at all (e.g. emoji-only names).
    pub(crate) fn sanitized_admin_key_name(&self) -> String {
        let safe: String = self
            .admin_key_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if safe.is_empty() {
            "client".to_string()
        } else {
            safe
        }
    }
}
