use crate::admin::{self, AdminRequest};
use crate::assets::{decode_png_rgba, format_unix_ago};
use crate::install_wizard;
use crate::localization::{t, Lang};
use crate::{SshBinarySourceChoice, SshWizardStage};
use std::time::Instant;

impl super::AivpnApp {
    /// G-B1: exit-node picker shared by the add/edit forms — a `ComboBox`
    /// listing "(default)", every known pool-node address
    /// (`admin::exit_node_addresses`), and "custom", instead of a bare
    /// free-text field. `value` is the form's existing `host:port` string
    /// (unchanged wire representation — still empty for default, still
    /// free text for a manual entry), `custom_mode` is the form's
    /// `admin_*_exit_custom_mode` flag (see its doc comment for why the
    /// UI needs it in addition to `admin::classify_exit_node`). No `&self`
    /// param: called as `Self::draw_exit_node_picker(...)` from both forms
    /// so the caller can pass either the add- or edit-form's fields
    /// without a disjoint-field-borrow conflict against `self`.
    pub(crate) fn draw_exit_node_picker(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        id_salt: &str,
        value: &mut String,
        custom_mode: &mut bool,
        known_addresses: &[String],
    ) {
        use eframe::egui;

        let choice = if *custom_mode {
            admin::ExitNodeChoice::Custom
        } else {
            admin::classify_exit_node(value, known_addresses)
        };
        let default_label = t(lang, "admin_exit_node_default");
        let custom_label = t(lang, "admin_exit_node_custom");
        let selected_text = match &choice {
            admin::ExitNodeChoice::Default => default_label.to_string(),
            admin::ExitNodeChoice::Node(addr) => addr.clone(),
            admin::ExitNodeChoice::Custom => custom_label.to_string(),
        };

        egui::ComboBox::from_id_salt(id_salt)
            .selected_text(selected_text)
            .width(230.0)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Default, default_label)
                    .clicked()
                {
                    value.clear();
                    *custom_mode = false;
                }
                for addr in known_addresses {
                    let is_selected =
                        matches!(&choice, admin::ExitNodeChoice::Node(a) if a == addr);
                    if ui.selectable_label(is_selected, addr).clicked() {
                        *value = addr.clone();
                        *custom_mode = false;
                    }
                }
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Custom, custom_label)
                    .clicked()
                {
                    *custom_mode = true;
                }
            })
            .response
            .on_hover_text(t(lang, "admin_exit_node_live_hint"));

        if matches!(choice, admin::ExitNodeChoice::Custom) {
            ui.add(
                egui::TextEdit::singleline(value)
                    .desired_width(f32::INFINITY)
                    .hint_text("exit.example.com:51820"),
            );
        }
    }

    /// Client-list + add/edit forms + pool topology + audit log — drawn
    /// inline inside the main scroll area (see call site in `update()`),
    /// following the same pattern as the Recording/Diagnostics sections
    /// above it. Only ever called for `admin_role == Some(1)` (Viewer) or
    /// `Some(2)` (Admin) — see the call site's `matches!` guard — so every
    /// subsection below is reachable by both roles; `can_mutate`
    /// (`is_admin`) is threaded down to `draw_admin_clients_section` to
    /// hide the mutating controls (add/edit/enable-disable/reset-device/
    /// revoke) for a Viewer, leaving read-only access to clients/pool/audit
    /// (G-A1) — the same GET-only allowlist the server's `authorize()`
    /// already grants that role.
    pub(crate) fn draw_admin_panel(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        let is_admin = self.admin_role == Some(2);

        // GAP-G2/G1: the SSH-install wizard's entry point moved to the main
        // screen (always visible, no connection/admin role required — see
        // `update()`'s header area); the migration wizard was removed
        // entirely (web-only per GAP-G1). Nothing wizard-related belongs
        // here anymore.
        self.draw_admin_clients_section(ui, lang, is_admin);

        // ── Pool topology (B3) — Viewer + Admin ─────────────────────────
        self.draw_admin_pool_section(ui, lang);

        // ── Audit log (G-A2) — Viewer + Admin, GET-only ──────────────────
        self.draw_audit_panel(ui, lang);

        // ── Server Settings (G-A3) — Admin ONLY, unlike every section ────
        // above: this mutates server-wide/per-client heavy config, so it
        // gets no Viewer read-only rendering at all (contrast
        // `draw_admin_clients_section`'s `can_mutate` split, which still
        // shows a Viewer the client list itself, just without the mutating
        // controls).
        if is_admin {
            self.draw_admin_server_settings_section(ui, lang);
        }
    }

    /// Client list + add/edit forms + server status — visible to both
    /// Viewer and Admin (G-A1); `can_mutate` (`true` only for a confirmed
    /// Admin) gates every mutating control inside — the "+ add" button,
    /// the add/edit forms, and each row's Edit/Reset-device/Revoke
    /// buttons. "Key / QR" stays available to both: it's a plain GET the
    /// server's `authorize()` already permits a Viewer (`connection-key`
    /// is a curated GET route; QR rendering never touches the mgmt API at
    /// all — it's the client daemon's own admin-socket protocol,
    /// independent of the server-assigned role).
    pub(crate) fn draw_admin_clients_section(
        &mut self,
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        can_mutate: bool,
    ) {
        use eframe::egui;

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(t(lang, "admin_panel")).strong());
            if !can_mutate {
                ui.label(
                    egui::RichText::new(t(lang, "admin_view_only"))
                        .size(11.0)
                        .weak(),
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(t(lang, "admin_refresh")).clicked() {
                    self.refresh_admin_clients();
                }
                if can_mutate && ui.small_button("  +  ").clicked() {
                    self.admin_show_add = true;
                    self.admin_edit_id = None;
                    self.admin_add_name.clear();
                    self.admin_add_one_time = false;
                    self.admin_add_expiry.clear();
                    self.admin_add_exit_node.clear();
                    self.admin_add_exit_custom_mode = false;
                    self.admin_add_error = None;
                }
            });
        });

        if self.admin_clients_loading {
            ui.weak(t(lang, "admin_loading"));
        }
        if let Some(err) = &self.admin_clients_error {
            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
        }

        let frame = egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(4i8))
            .corner_radius(egui::CornerRadius::same(4));
        frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt("admin_clients")
                .max_height(200.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if self.admin_clients.is_empty() && !self.admin_clients_loading {
                        ui.weak(t(lang, "admin_no_clients"));
                    }
                    // Snapshot first: the per-row buttons below mutate
                    // `self` (busy set, dialog state), so nothing here may
                    // hold a borrow of `self.admin_clients` while that runs.
                    let clients = self.admin_clients.clone();
                    for c in &clients {
                        let busy = self.admin_busy_ids.contains(&c.id);
                        ui.group(|ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let status_color = if c.enabled {
                                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                } else {
                                    egui::Color32::from_rgb(0x78, 0x78, 0x78)
                                };
                                ui.colored_label(status_color, "●");
                                ui.label(egui::RichText::new(&c.name).strong());
                                ui.label(
                                    egui::RichText::new(format!("({})", c.role))
                                        .size(11.0)
                                        .weak(),
                                );
                                if c.one_time {
                                    ui.label(
                                        egui::RichText::new(t(lang, "admin_one_time_badge"))
                                            .size(10.0)
                                            .weak(),
                                    );
                                }
                            });
                            ui.label(egui::RichText::new(&c.vpn_ip).size(11.0).weak());
                            if let Some(exp) = &c.expires_at {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {exp}",
                                        t(lang, "admin_expires")
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                            if let Some(exit) = &c.exit_node {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {exit}",
                                        t(lang, "admin_exit_node")
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(!busy, egui::Button::new(t(lang, "admin_key_qr")))
                                    .clicked()
                                {
                                    self.admin_key_id = Some(c.id.clone());
                                    self.admin_key_name = c.name.clone();
                                    self.admin_key_value = None;
                                    self.admin_key_error = None;
                                    self.admin_key_saved_msg = None;
                                    self.admin_key_loading = true;
                                    self.admin_qr_png = None;
                                    self.admin_qr_texture = None;
                                    self.admin_qr_error = None;
                                    self.admin_qr_saved_msg = None;
                                    admin::spawn(
                                        self.vpn.client_binary.clone(),
                                        AdminRequest::ConnectionKey { id: c.id.clone() },
                                        self.admin_tx.clone(),
                                    );
                                }
                                // G-A1: Edit/Reset-device/Revoke all mutate
                                // server state — hidden entirely for a
                                // Viewer rather than shown-disabled, same
                                // treatment as the "+ add" button above.
                                if can_mutate {
                                    if ui
                                        .add_enabled(!busy, egui::Button::new(t(lang, "edit")))
                                        .clicked()
                                    {
                                        self.admin_show_add = false;
                                        self.admin_edit_id = Some(c.id.clone());
                                        self.admin_edit_name = c.name.clone();
                                        self.admin_edit_enabled = c.enabled;
                                        self.admin_edit_expiry =
                                            c.expires_at.clone().unwrap_or_default();
                                        self.admin_edit_exit_node =
                                            c.exit_node.clone().unwrap_or_default();
                                        self.admin_edit_exit_custom_mode = false;
                                        self.admin_edit_error = None;
                                    }
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(t(lang, "admin_reset_device")),
                                        )
                                        .clicked()
                                    {
                                        self.admin_busy_ids.insert(c.id.clone());
                                        admin::spawn(
                                            self.vpn.client_binary.clone(),
                                            AdminRequest::ResetDevice { id: c.id.clone() },
                                            self.admin_tx.clone(),
                                        );
                                    }
                                    let revoke_btn = egui::Button::new(
                                        egui::RichText::new(t(lang, "admin_revoke"))
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(0xC6, 0x28, 0x28));
                                    if ui.add_enabled(!busy, revoke_btn).clicked() {
                                        self.admin_revoke_id = Some(c.id.clone());
                                        self.admin_revoke_name = c.name.clone();
                                    }
                                }
                            });
                        });
                    }
                });
        });

        // ── Add-client form (Admin only — a mutating control) ────────────
        if can_mutate && self.admin_show_add {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(t(lang, "admin_add_client")).strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.admin_add_name)
                    .desired_width(f32::INFINITY)
                    .hint_text(t(lang, "key_name")),
            );
            ui.checkbox(&mut self.admin_add_one_time, t(lang, "admin_one_time"));
            ui.label(t(lang, "admin_expiry_hint"));
            ui.add(
                egui::TextEdit::singleline(&mut self.admin_add_expiry)
                    .desired_width(f32::INFINITY)
                    .hint_text("2026-08-01T00:00:00Z"),
            );
            ui.label(t(lang, "admin_exit_node"));
            Self::draw_exit_node_picker(
                ui,
                lang,
                "admin_add_exit_node_combo",
                &mut self.admin_add_exit_node,
                &mut self.admin_add_exit_custom_mode,
                &admin::exit_node_addresses(&self.admin_pool_nodes),
            );
            if let Some(err) = &self.admin_add_error {
                ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
            }
            ui.horizontal(|ui| {
                let can_save = !self.admin_add_name.trim().is_empty() && !self.admin_add_busy;
                if ui
                    .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                    .clicked()
                {
                    self.admin_add_busy = true;
                    self.admin_add_error = None;
                    let form = admin::NewClientForm {
                        name: self.admin_add_name.trim().to_string(),
                        one_time: self.admin_add_one_time,
                        expires_at: self.admin_add_expiry.trim().to_string(),
                        exit_node: self.admin_add_exit_node.trim().to_string(),
                    };
                    admin::spawn(
                        self.vpn.client_binary.clone(),
                        AdminRequest::AddClient(form),
                        self.admin_tx.clone(),
                    );
                }
                if ui
                    .add_enabled(!self.admin_add_busy, egui::Button::new(t(lang, "cancel")))
                    .clicked()
                {
                    self.admin_show_add = false;
                    self.admin_add_error = None;
                }
            });
        }

        // ── Edit-client form (Admin only). `can_mutate &&` here is
        // defense-in-depth, not the primary gate — `admin_edit_id` can only
        // ever be set via the Edit button above, which is itself hidden
        // for a Viewer (e.g. guards against a role downgrade landing
        // mid-interaction).
        if can_mutate {
            if let Some(id) = self.admin_edit_id.clone() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("{}: {}", t(lang, "edit"), self.admin_edit_name))
                        .strong(),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_edit_name)
                        .desired_width(f32::INFINITY)
                        .hint_text(t(lang, "key_name")),
                );
                ui.checkbox(&mut self.admin_edit_enabled, t(lang, "admin_enabled"));
                ui.label(t(lang, "admin_expiry_hint"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_edit_expiry)
                        .desired_width(f32::INFINITY)
                        .hint_text("2026-08-01T00:00:00Z"),
                );
                ui.label(t(lang, "admin_exit_node"));
                Self::draw_exit_node_picker(
                    ui,
                    lang,
                    "admin_edit_exit_node_combo",
                    &mut self.admin_edit_exit_node,
                    &mut self.admin_edit_exit_custom_mode,
                    &admin::exit_node_addresses(&self.admin_pool_nodes),
                );
                if let Some(err) = &self.admin_edit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                ui.horizontal(|ui| {
                    let can_save = !self.admin_edit_name.trim().is_empty() && !self.admin_edit_busy;
                    if ui
                        .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                        .clicked()
                    {
                        self.admin_edit_busy = true;
                        self.admin_edit_error = None;
                        let form = admin::EditClientForm {
                            id: id.clone(),
                            name: self.admin_edit_name.trim().to_string(),
                            enabled: self.admin_edit_enabled,
                            expires_at: self.admin_edit_expiry.trim().to_string(),
                            exit_node: self.admin_edit_exit_node.trim().to_string(),
                        };
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::EditClient(form),
                            self.admin_tx.clone(),
                        );
                    }
                    if ui
                        .add_enabled(!self.admin_edit_busy, egui::Button::new(t(lang, "cancel")))
                        .clicked()
                    {
                        self.admin_edit_id = None;
                        self.admin_edit_error = None;
                    }
                });
            }
        }

        // ── Server status (read-only) — Viewer + Admin ───────────────────
        // A plain GET (`GET /api/v1/status`), same as the client list
        // above; nothing here mutates, so it's shown to both roles
        // unconditionally (no `can_mutate` check needed).
        egui::CollapsingHeader::new(t(lang, "admin_status_header")).show(ui, |ui| {
            if ui.button(t(lang, "admin_refresh")).clicked() {
                admin::spawn(
                    self.vpn.client_binary.clone(),
                    AdminRequest::Status,
                    self.admin_tx.clone(),
                );
            }
            if let Some(s) = &self.admin_status {
                ui.label(format!(
                    "{}: {}/{}   {}: {}",
                    t(lang, "admin_status_clients"),
                    s.clients_enabled,
                    s.clients_total,
                    t(lang, "admin_status_kernel"),
                    if s.kernel_module { "✓" } else { "✗" }
                ));
            }
        });
    }

    /// G-A2: audit-log panel — hash-chain-verified tail of the server's
    /// append-only admin audit log (`GET /api/v1/audit-log?verify=1`,
    /// `mgmt_service::audit_verify`). Only ever called from
    /// `draw_admin_panel`, itself gated on `admin_role == Some(1)` (Viewer)
    /// or `Some(2)` (Admin) — GET-only in the server's curated allowlist
    /// regardless of role, so unlike `draw_admin_clients_section` there is
    /// no `can_mutate` split here at all: nothing in this panel ever
    /// mutates anything.
    pub(crate) fn draw_audit_panel(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_audit_panel"))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button(t(lang, "admin_refresh")).clicked() {
                        self.refresh_admin_audit();
                    }
                });

                if self.admin_audit_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.admin_audit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }

                // Hash-chain verification badge — `None` (no info, e.g. an
                // older server that ignored `?verify=1`) renders nothing
                // rather than defaulting to either color.
                match self.admin_audit_verified {
                    Some(true) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                            t(lang, "admin_audit_chain_verified"),
                        );
                    }
                    Some(false) => {
                        let idx = self
                            .admin_audit_broken_at
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "?".to_string());
                        ui.colored_label(
                            egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                            format!("{} ({idx})", t(lang, "admin_audit_chain_broken")),
                        );
                    }
                    None => {}
                }

                if self.admin_audit.is_empty() && !self.admin_audit_loading {
                    ui.weak(t(lang, "admin_audit_no_entries"));
                }

                let frame = egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::same(4i8))
                    .corner_radius(egui::CornerRadius::same(4));
                frame.show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .id_salt("admin_audit")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            // Oldest-first from the server; show newest-first
                            // so the most recent action is always visible
                            // without scrolling.
                            for e in self.admin_audit.iter().rev() {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "[{}] {} {} {} — {}",
                                        e.ts, e.actor, e.action, e.target, e.result
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                        });
                });
            });
    }

    /// Pool topology view (B3) — node list + health summary, read-only.
    /// Viewer(1)+Admin(2) both reach this (see `draw_admin_panel`'s doc
    /// comment); it never issues a mutating call, matching the server's
    /// `authorize()` treating `pool/*` as GET-only for every role that can
    /// reach it at all.
    pub(crate) fn draw_admin_pool_section(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_pool_section"))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button(t(lang, "admin_refresh")).clicked() {
                        self.refresh_admin_pool();
                    }
                });

                if self.admin_pool_nodes_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.admin_pool_nodes_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }

                if let Some(h) = &self.admin_pool_health {
                    ui.label(format!(
                        "{}: {}   {}: {}/{}   {}: {}/{}",
                        t(lang, "admin_pool_transport"),
                        h.transport,
                        t(lang, "admin_pool_connected"),
                        h.connected_peers,
                        h.total_nodes,
                        t(lang, "admin_pool_converged"),
                        h.converged_peers,
                        h.total_nodes,
                    ));
                    if h.partition_conflict {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_pool_partition_conflict"),
                        );
                    }
                    if h.subnet_mismatch {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_pool_subnet_mismatch"),
                        );
                    }
                }

                let frame = egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::same(4i8))
                    .corner_radius(egui::CornerRadius::same(4));
                frame.show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .id_salt("admin_pool_nodes")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if self.admin_pool_nodes.is_empty() && !self.admin_pool_nodes_loading {
                                ui.weak(t(lang, "admin_pool_no_nodes"));
                            }
                            for n in &self.admin_pool_nodes {
                                ui.group(|ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        let status_color = if n.connected {
                                            egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                        } else {
                                            egui::Color32::from_rgb(0x78, 0x78, 0x78)
                                        };
                                        ui.colored_label(status_color, "●");
                                        ui.label(egui::RichText::new(&n.node_id).strong());
                                        if n.revoked {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                                                t(lang, "admin_pool_revoked"),
                                            );
                                        } else if n.verified {
                                            ui.label(
                                                egui::RichText::new(t(lang, "admin_pool_verified"))
                                                    .size(10.0)
                                                    .weak(),
                                            );
                                        }
                                    });
                                    if let Some(addr) = &n.address {
                                        ui.label(egui::RichText::new(addr).size(11.0).weak());
                                    }
                                    if let Some(ts) = n.last_seen_unix {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}: {}",
                                                t(lang, "admin_pool_last_seen"),
                                                format_unix_ago(ts)
                                            ))
                                            .size(10.0)
                                            .weak(),
                                        );
                                    }
                                });
                            }
                        });
                });
            });
    }

    /// G-A3: Server Settings — Admin-only apply-with-rollback for the
    /// active mask (per client — see `admin.rs`'s module-doc note on why
    /// there is no server-WIDE default mask here) and the global default
    /// exit node. Only ever called for `is_admin` (see `draw_admin_panel`'s
    /// call site) — unlike every other admin subsection, there is no
    /// Viewer-visible read-only rendering at all.
    pub(crate) fn draw_admin_server_settings_section(
        &mut self,
        ui: &mut eframe::egui::Ui,
        lang: Lang,
    ) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_settings_panel"))
            .default_open(false)
            .show(ui, |ui| {
                // ── Active mask (per client) ─────────────────────────────
                ui.label(egui::RichText::new(t(lang, "admin_settings_mask_section")).strong());
                if self.admin_clients.is_empty() {
                    ui.weak(t(lang, "admin_settings_mask_no_clients"));
                } else {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, "admin_settings_mask_client_label"));
                        let selected_label = self
                            .admin_clients
                            .iter()
                            .find(|c| c.id == self.admin_settings_mask_client)
                            .map(|c| c.name.clone())
                            .unwrap_or_default();
                        egui::ComboBox::from_id_salt("admin_settings_mask_client_combo")
                            .selected_text(selected_label)
                            .show_ui(ui, |ui| {
                                for c in &self.admin_clients {
                                    let is_selected = self.admin_settings_mask_client == c.id;
                                    if ui.selectable_label(is_selected, &c.name).clicked() {
                                        self.admin_settings_mask_client = c.id.clone();
                                    }
                                }
                            });
                    });
                    ui.label(t(lang, "admin_settings_mask_id_label"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.admin_settings_mask_id)
                            .desired_width(f32::INFINITY)
                            .hint_text(t(lang, "admin_settings_mask_id_hint")),
                    );
                    if let Some(err) = &self.admin_settings_mask_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if self.admin_settings_mask_rolled_back {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_settings_rolled_back"),
                        );
                    }
                    if let Some(token) = self.admin_settings_mask_token.clone() {
                        let confirm_clicked = Self::draw_pending_config_banner(
                            ui,
                            lang,
                            self.admin_settings_mask_deadline,
                            self.admin_settings_mask_confirm_busy,
                        );
                        if confirm_clicked {
                            self.admin_settings_mask_confirm_busy = true;
                            admin::spawn(
                                self.vpn.client_binary.clone(),
                                AdminRequest::ConfirmConfig {
                                    setting: admin::ConfigSetting::ActiveMask,
                                    token,
                                },
                                self.admin_tx.clone(),
                            );
                        }
                    } else {
                        let can_apply = !self.admin_settings_mask_client.is_empty()
                            && admin::mask_id_looks_valid(self.admin_settings_mask_id.trim())
                            && !self.admin_settings_mask_busy;
                        if ui
                            .add_enabled(
                                can_apply,
                                egui::Button::new(t(lang, "admin_settings_apply")),
                            )
                            .clicked()
                        {
                            self.admin_settings_mask_busy = true;
                            self.admin_settings_mask_error = None;
                            self.admin_settings_mask_rolled_back = false;
                            admin::spawn(
                                self.vpn.client_binary.clone(),
                                AdminRequest::ApplyActiveMask {
                                    client_id: self.admin_settings_mask_client.clone(),
                                    mask: self.admin_settings_mask_id.trim().to_string(),
                                },
                                self.admin_tx.clone(),
                            );
                        }
                    }
                }

                ui.separator();

                // ── Global default exit node (pool.exit_node) ────────────
                ui.label(egui::RichText::new(t(lang, "admin_settings_exit_section")).strong());
                ui.label(
                    egui::RichText::new(t(lang, "admin_settings_exit_restart_hint"))
                        .size(10.0)
                        .weak(),
                );
                Self::draw_global_exit_node_picker(
                    ui,
                    lang,
                    &mut self.admin_settings_exit_node,
                    &mut self.admin_settings_exit_custom_mode,
                    &admin::exit_node_addresses(&self.admin_pool_nodes),
                );
                if let Some(err) = &self.admin_settings_exit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                if self.admin_settings_exit_rolled_back {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                        t(lang, "admin_settings_rolled_back"),
                    );
                }
                if let Some(token) = self.admin_settings_exit_token.clone() {
                    let confirm_clicked = Self::draw_pending_config_banner(
                        ui,
                        lang,
                        self.admin_settings_exit_deadline,
                        self.admin_settings_exit_confirm_busy,
                    );
                    if confirm_clicked {
                        self.admin_settings_exit_confirm_busy = true;
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::ConfirmConfig {
                                setting: admin::ConfigSetting::ExitNode,
                                token,
                            },
                            self.admin_tx.clone(),
                        );
                    }
                } else if ui
                    .add_enabled(
                        !self.admin_settings_exit_busy,
                        egui::Button::new(t(lang, "admin_settings_apply")),
                    )
                    .clicked()
                {
                    self.admin_settings_exit_busy = true;
                    self.admin_settings_exit_error = None;
                    self.admin_settings_exit_rolled_back = false;
                    let trimmed = self.admin_settings_exit_node.trim();
                    let addr = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                    admin::spawn(
                        self.vpn.client_binary.clone(),
                        AdminRequest::ApplyExitNode { addr },
                        self.admin_tx.clone(),
                    );
                }
            });
    }

    /// G-A3: shared "pending confirmation" banner — the countdown text plus
    /// the Confirm button, used identically by both the active-mask and
    /// exit-node blocks in `draw_admin_server_settings_section`. Returns
    /// `true` if Confirm was clicked this frame; no `&self`/`&mut self`
    /// param (same rationale as `draw_exit_node_picker`) so it can be
    /// called from either block without a disjoint-field-borrow conflict —
    /// the caller does the actual `admin::spawn` since which busy flag to
    /// set and which `ConfigSetting` to send differs per call site.
    pub(crate) fn draw_pending_config_banner(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        deadline: Option<Instant>,
        confirm_busy: bool,
    ) -> bool {
        use eframe::egui;

        // Frame-time based, not a separate timer: `update()` already runs
        // continuously while a session is Connected (egui repaints on
        // every VPN status poll), so this recomputes fresh each draw.
        let secs_left = deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_secs())
            .unwrap_or(0);
        ui.colored_label(
            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
            format!(
                "{} ({secs_left}s)",
                t(lang, "admin_settings_pending_banner")
            ),
        );
        ui.add_enabled(
            !confirm_busy,
            egui::Button::new(t(lang, "admin_settings_confirm")),
        )
        .clicked()
    }

    /// G-A3: exit-node picker for the GLOBAL default (`pool.exit_node`) —
    /// same `ComboBox`-over-known-pool-addresses-plus-custom shape as
    /// `draw_exit_node_picker`, but with its own "no override" label
    /// ("(none)" rather than "(default)" — there IS no higher-level
    /// default to fall back to for this one, clearing it disables global
    /// exit routing entirely) and no live-apply hover hint (the restart
    /// caveat is already shown as a persistent label above the picker in
    /// `draw_admin_server_settings_section`, unlike the per-client picker
    /// which has no equivalent always-visible caption).
    pub(crate) fn draw_global_exit_node_picker(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        value: &mut String,
        custom_mode: &mut bool,
        known_addresses: &[String],
    ) {
        use eframe::egui;

        let choice = if *custom_mode {
            admin::ExitNodeChoice::Custom
        } else {
            admin::classify_exit_node(value, known_addresses)
        };
        let none_label = t(lang, "admin_settings_exit_none");
        let custom_label = t(lang, "admin_exit_node_custom");
        let selected_text = match &choice {
            admin::ExitNodeChoice::Default => none_label.to_string(),
            admin::ExitNodeChoice::Node(addr) => addr.clone(),
            admin::ExitNodeChoice::Custom => custom_label.to_string(),
        };

        egui::ComboBox::from_id_salt("admin_settings_exit_node_combo")
            .selected_text(selected_text)
            .width(230.0)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Default, none_label)
                    .clicked()
                {
                    value.clear();
                    *custom_mode = false;
                }
                for addr in known_addresses {
                    let is_selected =
                        matches!(&choice, admin::ExitNodeChoice::Node(a) if a == addr);
                    if ui.selectable_label(is_selected, addr).clicked() {
                        *value = addr.clone();
                        *custom_mode = false;
                    }
                }
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Custom, custom_label)
                    .clicked()
                {
                    *custom_mode = true;
                }
            });

        if matches!(choice, admin::ExitNodeChoice::Custom) {
            ui.add(
                egui::TextEdit::singleline(value)
                    .desired_width(f32::INFINITY)
                    .hint_text("exit.example.com:51820"),
            );
        }
    }

    /// Connection-key / QR viewer window and the revoke-confirmation modal —
    /// both are separate top-level egui containers, so they're drawn once
    /// per frame from `update()` alongside the existing key add/edit
    /// viewport dialog, rather than nested inside `draw_admin_panel`'s
    /// `CentralPanel` closure.
    pub(crate) fn draw_admin_extras(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        if self.admin_key_id.is_some() {
            let mut open = true;
            let title = format!("{}: {}", t(lang, "admin_key_qr"), self.admin_key_name);
            egui::Window::new(title)
                .id(egui::Id::new("admin_key_window"))
                .collapsible(false)
                .resizable(true)
                .open(&mut open)
                .show(ctx, |ui| {
                    if self.admin_key_loading {
                        ui.weak(t(lang, "admin_loading"));
                    }
                    if let Some(err) = &self.admin_key_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if let Some(key) = self.admin_key_value.clone() {
                        let mut display_key = key.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut display_key)
                                .desired_width(360.0)
                                .desired_rows(3)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false),
                        );
                        ui.horizontal(|ui| {
                            if ui.button(t(lang, "copy")).clicked() {
                                ctx.copy_text(key.clone());
                            }
                            if ui.button(t(lang, "admin_save_key_file")).clicked() {
                                self.save_admin_key_to_file(&key);
                            }
                            if !self.admin_qr_loading && self.admin_qr_png.is_none() {
                                if ui.button(t(lang, "admin_show_qr")).clicked() {
                                    self.admin_qr_loading = true;
                                    self.admin_qr_error = None;
                                    let id = self.admin_key_id.clone().unwrap_or_default();
                                    admin::spawn(
                                        self.vpn.client_binary.clone(),
                                        AdminRequest::Qr {
                                            id,
                                            text: key.clone(),
                                        },
                                        self.admin_tx.clone(),
                                    );
                                }
                            }
                        });
                        if let Some(saved) = &self.admin_key_saved_msg {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}: {saved}",
                                    t(lang, "admin_saved_to")
                                ))
                                .size(11.0)
                                .weak(),
                            );
                        }
                    }
                    if self.admin_qr_loading {
                        ui.weak(t(lang, "admin_loading"));
                    }
                    if let Some(err) = &self.admin_qr_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if let Some(png) = self.admin_qr_png.clone() {
                        let texture = self.admin_qr_texture.get_or_insert_with(|| {
                            let (rgba, w, h) = decode_png_rgba(&png);
                            ctx.load_texture(
                                "admin-qr",
                                egui::ColorImage::from_rgba_unmultiplied(
                                    [w as usize, h as usize],
                                    &rgba,
                                ),
                                egui::TextureOptions::default(),
                            )
                        });
                        ui.image((texture.id(), texture.size_vec2()));
                        if ui.button(t(lang, "admin_save_qr_file")).clicked() {
                            self.save_admin_qr_to_file(&png);
                        }
                        if let Some(saved) = &self.admin_qr_saved_msg {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}: {saved}",
                                    t(lang, "admin_saved_to")
                                ))
                                .size(11.0)
                                .weak(),
                            );
                        }
                    }
                });
            if !open {
                self.admin_key_id = None;
                self.admin_key_value = None;
                self.admin_qr_png = None;
                self.admin_qr_texture = None;
            }
        }

        if let Some(id) = self.admin_revoke_id.clone() {
            let name = self.admin_revoke_name.clone();
            let busy = self.admin_busy_ids.contains(&id);
            let resp = egui::Modal::new(egui::Id::new("admin_revoke_modal")).show(ctx, |ui| {
                ui.set_width(300.0);
                ui.label(egui::RichText::new(t(lang, "admin_revoke_confirm_title")).strong());
                ui.label(format!(
                    "{} \u{201c}{name}\u{201d}?",
                    t(lang, "admin_revoke_confirm_body")
                ));
                ui.label(
                    egui::RichText::new(t(lang, "admin_revoke_confirm_warn"))
                        .size(11.0)
                        .weak(),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new(t(lang, "cancel")))
                        .clicked()
                    {
                        self.admin_revoke_id = None;
                    }
                    let revoke_btn = egui::Button::new(
                        egui::RichText::new(t(lang, "admin_revoke")).color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0xC6, 0x28, 0x28));
                    if ui.add_enabled(!busy, revoke_btn).clicked() {
                        self.admin_busy_ids.insert(id.clone());
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::RevokeClient { id: id.clone() },
                            self.admin_tx.clone(),
                        );
                    }
                });
            });
            if resp.should_close() {
                self.admin_revoke_id = None;
            }
        }
    }

    // ── SSH server-install wizard (C3) — separate top-level window, same
    // rationale as `draw_admin_extras`'s viewport dialogs. ────────────────

    pub(crate) fn draw_ssh_install_window(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        if !self.ssh_wizard_open {
            return;
        }
        let mut open = true;
        egui::Window::new(t(lang, "ssh_wizard_title"))
            .id(egui::Id::new("ssh_install_wizard"))
            .collapsible(false)
            .resizable(true)
            .default_width(440.0)
            .open(&mut open)
            .show(ctx, |ui| match self.ssh_wizard_stage {
                SshWizardStage::Form | SshWizardStage::Confirmed => {
                    self.draw_ssh_wizard_form(ui, lang)
                }
                SshWizardStage::Installing | SshWizardStage::Done => {
                    self.draw_ssh_wizard_progress(ui, lang)
                }
            });
        if !open {
            self.close_ssh_wizard();
        }

        if self.ssh_show_script {
            self.draw_ssh_script_window(ctx, lang);
        }
    }

    pub(crate) fn draw_ssh_wizard_form(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::Grid::new("ssh_wizard_target_grid")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                ui.label(t(lang, "ssh_host"));
                // TOFU: any edit to host/port/user invalidates the probed
                // fingerprint and the trust decision — otherwise a probe of
                // host A could bless an install on host B (the Linux GUI
                // resets these in its *Changed message handlers; here the
                // fields are edited in place, so watch `.changed()`).
                if ui.text_edit_singleline(&mut self.ssh_host).changed() {
                    self.ssh_fingerprint = None;
                    self.ssh_trusted = false;
                }
                ui.end_row();
                ui.label(t(lang, "ssh_port"));
                if ui.text_edit_singleline(&mut self.ssh_port).changed() {
                    self.ssh_fingerprint = None;
                    self.ssh_trusted = false;
                }
                ui.end_row();
                ui.label(t(lang, "ssh_user"));
                if ui.text_edit_singleline(&mut self.ssh_user).changed() {
                    self.ssh_fingerprint = None;
                    self.ssh_trusted = false;
                }
                ui.end_row();
            });

        ui.separator();
        ui.horizontal(|ui| {
            ui.radio_value(
                &mut self.ssh_auth_key_mode,
                false,
                t(lang, "ssh_auth_password"),
            );
            ui.radio_value(&mut self.ssh_auth_key_mode, true, t(lang, "ssh_auth_key"));
        });
        if self.ssh_auth_key_mode {
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_key_path"));
                ui.text_edit_singleline(&mut self.ssh_key_path);
            });
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_key_passphrase"));
                ui.add(egui::TextEdit::singleline(&mut self.ssh_key_passphrase).password(true));
            });
        } else {
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_password"));
                ui.add(egui::TextEdit::singleline(&mut self.ssh_password).password(true));
            });
        }

        // GAP-G3: server binary source — default(GitHub Releases)/URL/local
        // file, mirrors ssh_install_cmd.rs's RunArgs --binary-file/
        // --binary-url flags via install_wizard::BinarySource (see
        // start_ssh_install's mapping).
        ui.separator();
        ui.label(egui::RichText::new(t(lang, "ssh_binary_source_label")).strong());
        ui.horizontal(|ui| {
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::Default,
                t(lang, "ssh_binary_source_default"),
            );
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::Url,
                t(lang, "ssh_binary_source_url"),
            );
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::LocalFile,
                t(lang, "ssh_binary_source_file"),
            );
        });
        match self.ssh_binary_source_choice {
            SshBinarySourceChoice::Default => {}
            SshBinarySourceChoice::Url => {
                ui.horizontal(|ui| {
                    ui.label(t(lang, "ssh_binary_url_label"));
                    ui.text_edit_singleline(&mut self.ssh_binary_url);
                });
            }
            SshBinarySourceChoice::LocalFile => {
                ui.horizontal(|ui| {
                    ui.label(t(lang, "ssh_binary_file_label"));
                    ui.text_edit_singleline(&mut self.ssh_binary_file_path);
                });
            }
        }

        ui.separator();
        ui.checkbox(&mut self.ssh_mode_docker, t(lang, "ssh_mode_docker"));
        ui.horizontal(|ui| {
            ui.label(t(lang, "ssh_server_ip"));
            ui.text_edit_singleline(&mut self.ssh_server_ip);
        });
        ui.horizontal(|ui| {
            ui.label(t(lang, "ssh_server_port"));
            ui.text_edit_singleline(&mut self.ssh_server_port);
        });
        ui.checkbox(&mut self.ssh_bind_device, t(lang, "ssh_bind_device"));

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button(t(lang, "ssh_show_script_btn")).clicked() {
                self.ssh_show_script = true;
                if self.ssh_script_text.is_none() && !self.ssh_script_loading {
                    self.start_fetch_script();
                }
            }
            let probe_enabled = !self.ssh_probe_busy && !self.ssh_host.trim().is_empty();
            if ui
                .add_enabled(probe_enabled, egui::Button::new(t(lang, "ssh_probe_btn")))
                .clicked()
            {
                self.start_ssh_probe();
            }
        });
        if self.ssh_probe_busy {
            ui.weak(t(lang, "admin_loading"));
        }
        if let Some(err) = &self.ssh_probe_error {
            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
        }

        if let Some(fp) = self.ssh_fingerprint.clone() {
            ui.separator();
            ui.label(egui::RichText::new(t(lang, "ssh_fingerprint_label")).strong());
            ui.label(egui::RichText::new(&fp).monospace());
            ui.checkbox(&mut self.ssh_trusted, t(lang, "ssh_trust_checkbox"));

            let auth_ready = if self.ssh_auth_key_mode {
                !self.ssh_key_path.trim().is_empty()
            } else {
                !self.ssh_password.is_empty()
            };
            let install_enabled = self.ssh_trusted && auth_ready;
            if ui
                .add_enabled(
                    install_enabled,
                    egui::Button::new(t(lang, "ssh_install_btn")),
                )
                .clicked()
            {
                self.start_ssh_install();
            }
        }
    }

    pub(crate) fn draw_ssh_wizard_progress(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        if self.ssh_install_running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(t(lang, "ssh_installing"));
            });
        }

        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(4i8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .id_salt("ssh_install_log")
                    .max_height(260.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for line in &self.ssh_install_log {
                            match line {
                                install_wizard::InstallLine::Raw(s) => {
                                    ui.label(egui::RichText::new(s).monospace().size(11.0));
                                }
                                install_wizard::InstallLine::Marker {
                                    step,
                                    status,
                                    code,
                                    msg,
                                    ..
                                } => {
                                    // Internal-only synthetic marker — see
                                    // gui_process_exit_line's doc comment in
                                    // install_wizard.rs; never shown raw.
                                    if step == "gui_process" {
                                        continue;
                                    }
                                    let color = match status.as_str() {
                                        "ok" => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                                        "error" => egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                                        _ => egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                                    };
                                    let mut text = format!("[{step}] {status}");
                                    if let Some(c) = code {
                                        text.push_str(&format!(" ({c})"));
                                    }
                                    if let Some(m) = msg {
                                        text.push_str(&format!(": {m}"));
                                    }
                                    ui.colored_label(color, egui::RichText::new(text).size(11.0));
                                }
                            }
                        }
                    });
            });

        if let Some(ok) = self.ssh_install_done_ok {
            ui.separator();
            if ok {
                ui.colored_label(
                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                    t(lang, "ssh_install_done_ok"),
                );
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                    t(lang, "ssh_install_done_error"),
                );
            }
            // G-C1: the profile is now imported automatically the moment
            // the terminal marker's key arrives (`poll_ssh_install`) —
            // no manual click required. This just confirms it happened
            // and shows the key, mirroring the admin panel's read-only
            // key viewer (`admin_key_value` above). `!ssh_import_done`
            // only remains reachable if the auto-import itself failed
            // (e.g. `KeyStorage::add_key` rejected it) — that path keeps
            // the old manual button as a retry rather than stranding the
            // key with no way to add it.
            if let Some(key) = self.ssh_install_connection_key.clone() {
                ui.separator();
                if self.ssh_import_done {
                    ui.colored_label(
                        egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                        t(lang, "ssh_import_profile_done"),
                    );
                    let mut display_key = key.clone();
                    ui.add(
                        egui::TextEdit::multiline(&mut display_key)
                            .desired_width(360.0)
                            .desired_rows(3)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                    if ui.button(t(lang, "copy")).clicked() {
                        ui.ctx().copy_text(key);
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                        t(lang, "ssh_import_profile_retry_hint"),
                    );
                    if ui.button(t(lang, "ssh_import_profile_btn")).clicked() {
                        self.import_ssh_install_key();
                    }
                }
            }
            if ui.button(t(lang, "ssh_wizard_close_btn")).clicked() {
                self.close_ssh_wizard();
            }
        }
    }

    /// "Show script" review window — text + sha256, independent of the
    /// main wizard window's open/close state so it can stay open while the
    /// form behind it is edited.
    pub(crate) fn draw_ssh_script_window(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        let mut open = true;
        egui::Window::new(t(lang, "ssh_script_title"))
            .id(egui::Id::new("ssh_install_script_window"))
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .default_height(420.0)
            .open(&mut open)
            .show(ctx, |ui| {
                if self.ssh_script_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.ssh_script_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                if let Some(sha256) = &self.ssh_script_sha256 {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(t(lang, "ssh_script_sha256")).strong());
                        ui.label(egui::RichText::new(sha256).monospace());
                        if ui.small_button(t(lang, "copy")).clicked() {
                            ctx.copy_text(sha256.clone());
                        }
                    });
                }
                if let Some(script) = self.ssh_script_text.clone() {
                    let mut display = script;
                    egui::ScrollArea::vertical()
                        .id_salt("ssh_script_text")
                        .max_height(320.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut display)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace)
                                    .interactive(false),
                            );
                        });
                }
            });
        if !open {
            self.ssh_show_script = false;
        }
    }
}
