use crate::assets::{apply_theme_to_ctx, mask_choices_from_catalog};
use crate::localization::{t, Lang};
use crate::platform_win::{find_own_aivpn_hwnd, set_autostart};
use crate::vpn_manager::{format_bytes, ConnectionState, RecordingState, VpnManager};
use crate::APP_VERSION;
use std::time::Instant;

#[cfg(windows)]
impl eframe::App for super::AivpnApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;
        use std::sync::atomic::Ordering::Relaxed;

        self.tick();

        // Sync window_visible from background tray thread (tray_show_flag set by bg thread
        // so window restore works even when SW_HIDE pauses the eframe update loop).
        if self.tray_show_flag.swap(false, Relaxed) {
            self.window_visible = true;
        }

        // Handle tray menu actions signalled from the background thread.
        // MenuEvent is drained in init_tray() bg thread so it works even when window is hidden.
        if self.quit_requested.swap(false, Relaxed) {
            self.tray_thread_shutdown.store(true, Relaxed);
            self.tray = None;
            self.vpn.disconnect();
            self.settings.save();
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.connect_requested.swap(false, Relaxed) {
            self.window_visible = true;
            self.do_connect();
        }

        self.update_tray();

        let lang = self.settings.lang;
        let is_connected = self.vpn.is_connected();
        let is_busy = self.vpn.is_busy();
        let conn_state = self.vpn.state();
        let bytes_rx = self.vpn.stats().bytes_received;
        let bytes_tx = self.vpn.stats().bytes_sent;
        let quality = self.vpn.stats().quality_score;
        // HIGH #2 (client parity): the live, possibly server-re-homed VPN IP
        // from traffic.stats (`ip:` key) takes priority over the connection
        // key's static, one-time-parsed IP — falls back to the latter only
        // before the client's first stats write of the session arrives.
        let vpn_ip_display: Option<String> = self.vpn.stats().vpn_ip.clone().or_else(|| {
            self.keys
                .selected_key()
                .map(|k| k.vpn_ip.clone())
                .filter(|s| !s.is_empty())
        });
        // Uptime comes from the client's session epoch (`since:` in the stats
        // file, wall-clock now − since): on a silent in-child reconnect the
        // epoch changes and the stopwatch resets together with the per-session
        // counters. The GUI-local Instant is only a fallback for old-format
        // clients that don't write `since` (and the pre-first-write window).
        let uptime = self
            .vpn
            .session_since_ms()
            .map(|since_ms| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                now_ms.saturating_sub(since_ms) / 1000
            })
            .or_else(|| self.connected_since.map(|t| t.elapsed().as_secs()))
            .unwrap_or(0);

        let status_text = match conn_state {
            ConnectionState::Disconnected => t(lang, "disconnected").to_string(),
            ConnectionState::Connecting => t(lang, "connecting").to_string(),
            ConnectionState::Connected => {
                let h = uptime / 3600;
                let m = (uptime % 3600) / 60;
                let s = uptime % 60;
                if h > 0 {
                    format!("{} {}:{:02}:{:02}", t(lang, "connected"), h, m, s)
                } else {
                    format!("{} {}:{:02}", t(lang, "connected"), m, s)
                }
            }
            ConnectionState::Disconnecting => t(lang, "disconnecting").to_string(),
        };

        let no_traffic_warn = is_connected && uptime > 30 && bytes_rx == 0 && bytes_tx == 0;
        // last_error (specific cause from stall detection) takes precedence over the generic
        // no_traffic_warn so the user sees "WintunCreateAdapter failed" not "No traffic detected".
        let error_display: Option<String> = if let Some(e) = &self.error_msg {
            Some(e.clone())
        } else if let Some(e) = self.vpn.last_error.clone().filter(|e| !e.is_empty()) {
            Some(e)
        } else if no_traffic_warn {
            Some(t(lang, "no_traffic_warn").to_string())
        } else {
            None
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // ── Header ─────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        let dot_color = match conn_state {
                            ConnectionState::Connected => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                            ConnectionState::Connecting | ConnectionState::Disconnecting => {
                                egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                            }
                            ConnectionState::Disconnected => {
                                egui::Color32::from_rgb(0x78, 0x78, 0x78)
                            }
                        };
                        let (dot_rect, _) =
                            ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(dot_rect.center(), 5.0, dot_color);
                        ui.label(egui::RichText::new("AIVPN").size(17.0).strong());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button(lang.label()).clicked() {
                                self.settings.lang = match self.settings.lang {
                                    Lang::En => Lang::Ru,
                                    Lang::Ru => Lang::En,
                                };
                                self.dirty_at.get_or_insert(Instant::now());
                            }
                            let theme_lbl = if self.settings.dark_mode {
                                "☀"
                            } else {
                                "🌙"
                            };
                            if ui.small_button(theme_lbl).clicked() {
                                self.settings.dark_mode = !self.settings.dark_mode;
                                self.dirty_at.get_or_insert(Instant::now());
                                apply_theme_to_ctx(ctx, self.settings.dark_mode);
                            }
                            ui.label(
                                egui::RichText::new(format!("v{APP_VERSION}"))
                                    .size(11.0)
                                    .weak(),
                            );
                        });
                    });

                    ui.separator();

                    // ── Status + Connect card ─────────────────────────────────────
                    let status_color = match conn_state {
                        ConnectionState::Connected => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                        ConnectionState::Connecting | ConnectionState::Disconnecting => {
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                        }
                        ConnectionState::Disconnected => ui.visuals().text_color(),
                    };
                    let btn_text = if is_connected || is_busy {
                        t(lang, "disconnect")
                    } else {
                        t(lang, "connect")
                    };
                    let btn_color = if is_connected || is_busy {
                        egui::Color32::from_rgb(0xC6, 0x28, 0x28)
                    } else {
                        egui::Color32::from_rgb(0x19, 0x76, 0xD2)
                    };
                    let card_bg = if self.settings.dark_mode {
                        egui::Color32::from_rgb(0x26, 0x26, 0x30)
                    } else {
                        egui::Color32::from_rgb(0xEA, 0xEA, 0xF4)
                    };
                    egui::Frame::new()
                        .fill(card_bg)
                        .corner_radius(egui::CornerRadius::same(10))
                        .inner_margin(egui::Margin::symmetric(12i8, 10i8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&status_text)
                                        .color(status_color)
                                        .size(15.0),
                                );
                                if is_connected {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "↑ {}",
                                                    format_bytes(bytes_tx)
                                                ))
                                                .size(11.0)
                                                .weak(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "↓ {}",
                                                    format_bytes(bytes_rx)
                                                ))
                                                .size(11.0)
                                                .weak(),
                                            );
                                        },
                                    );
                                }
                            });
                            // Show which profile will be connected
                            if let Some(name) = self.keys.selected_key().map(|k| k.name.clone()) {
                                ui.label(
                                    egui::RichText::new(format!("→ {name}")).size(11.0).weak(),
                                );
                            }
                            // HIGH #2 (client parity): show the assigned VPN
                            // IP once connected, live-updated across a pool
                            // re-home (see vpn_ip_display above).
                            if is_connected {
                                if let Some(ip) = &vpn_ip_display {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{}: {ip}",
                                            t(lang, "vpn_ip_label")
                                        ))
                                        .size(11.0)
                                        .weak(),
                                    );
                                }
                            }
                            // 3c: bootstrap-fallback indicator — live value
                            // from traffic.stats `fallback:` key (this GUI's
                            // child stdout is Stdio::null(), so the stats
                            // file is the only channel; see TrafficStats::fallback).
                            if (is_connected || is_busy) && self.vpn.stats().fallback {
                                ui.label(
                                    egui::RichText::new(t(lang, "bootstrap_fallback_label"))
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(0xFF, 0xA7, 0x26)),
                                );
                            }
                            // Warn when disconnected and no key is available/selected
                            if !is_connected && !is_busy {
                                let warn_color = egui::Color32::from_rgb(0xFF, 0xA7, 0x26);
                                if self.keys.keys.is_empty() {
                                    ui.label(
                                        egui::RichText::new(t(lang, "no_keys"))
                                            .color(warn_color)
                                            .size(11.0),
                                    );
                                } else if self.keys.selected_key().is_none() {
                                    ui.label(
                                        egui::RichText::new(t(lang, "no_key_selected"))
                                            .color(warn_color)
                                            .size(11.0),
                                    );
                                }
                            }
                            ui.add_space(4.0);
                            let can_connect = is_connected || self.keys.selected_key().is_some();
                            let btn = egui::Button::new(
                                egui::RichText::new(btn_text)
                                    .color(egui::Color32::WHITE)
                                    .size(15.0)
                                    .strong(),
                            )
                            .fill(btn_color)
                            .min_size(egui::vec2(ui.available_width(), 38.0));
                            if ui.add_enabled(!is_busy && can_connect, btn).clicked() {
                                self.do_connect();
                            }
                        });

                    ui.add_space(4.0);
                    ui.separator();

                    // ── GAP-G2: SSH server-install wizard entry point ────────────────
                    // Always visible on the main screen — no connection and no admin
                    // role required, since installing a brand-new server ("first
                    // server from scratch") is a base scenario, not a management
                    // action on an already-running one (that flow, e.g. client
                    // management, stays gated behind draw_admin_panel/is_admin).
                    ui.horizontal(|ui| {
                        if ui.small_button(t(lang, "ssh_wizard_open_btn")).clicked() {
                            self.ssh_wizard_open = true;
                        }
                    });

                    ui.add_space(4.0);
                    ui.separator();

                    // ── Connection keys ────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(t(lang, "keys")).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("  +  ").clicked() {
                                self.dlg_name.clear();
                                self.dlg_key.clear();
                                self.dlg_full_tunnel = false;
                                self.dlg_proxy = false;
                                self.dlg_proxy_addr.clear();
                                self.dlg_exclude_routes.clear();
                                self.dlg_include_routes.clear();
                                self.dlg_mtls_cert.clear();
                                self.dlg_error = None;
                                self.editing_idx = None;
                                self.show_dialog = true;
                            }
                        });
                    });

                    let frame = egui::Frame::group(ui.style())
                        .inner_margin(egui::Margin::same(4i8))
                        .corner_radius(egui::CornerRadius::same(4));
                    frame.show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        egui::ScrollArea::vertical()
                            .id_salt("keys")
                            .max_height(90.0)
                            .show(ui, |ui: &mut egui::Ui| {
                                ui.set_width(ui.available_width());
                                // Defer deletion until after the loop: calling remove_key mid-loop
                                // shrinks the Vec while `for i in 0..len` keeps the original end,
                                // so a later iteration indexes out of bounds and panics (triggered
                                // by deleting any non-last key via the right-click menu).
                                let mut delete_idx: Option<usize> = None;
                                if self.keys.keys.is_empty() {
                                    ui.weak(t(lang, "no_keys"));
                                } else {
                                    for i in 0..self.keys.keys.len() {
                                        let name = self.keys.keys[i].name.clone();
                                        let selected = self.keys.selected == Some(i);
                                        let resp = ui.selectable_label(selected, &name);
                                        if resp.clicked() {
                                            self.keys.selected = Some(i);
                                        }
                                        resp.context_menu(|ui| {
                                            if ui.button(t(lang, "edit")).clicked() {
                                                let ck = &self.keys.keys[i];
                                                self.dlg_name = ck.name.clone();
                                                self.dlg_key = ck.key.clone();
                                                self.dlg_full_tunnel = ck.full_tunnel;
                                                self.dlg_proxy = ck.proxy_listen.is_some();
                                                self.dlg_proxy_addr =
                                                    ck.proxy_listen.clone().unwrap_or_default();
                                                self.dlg_exclude_routes =
                                                    ck.exclude_routes.join("\n");
                                                self.dlg_include_routes =
                                                    ck.include_routes.join("\n");
                                                self.dlg_mtls_cert =
                                                    ck.mtls_cert_path.clone().unwrap_or_default();
                                                self.dlg_error = None;
                                                self.editing_idx = Some(i);
                                                self.show_dialog = true;
                                                ui.close_menu();
                                            }
                                            ui.add_enabled_ui(!is_connected, |ui| {
                                                if ui.button(t(lang, "delete")).clicked() {
                                                    delete_idx = Some(i);
                                                    ui.close_menu();
                                                }
                                            });
                                        });
                                    }
                                }
                                if let Some(i) = delete_idx {
                                    self.keys.remove_key(i);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        let sel = self.keys.selected;
                        if ui
                            .add_enabled(sel.is_some(), egui::Button::new(t(lang, "edit")))
                            .clicked()
                        {
                            if let Some(idx) = sel {
                                let ck = &self.keys.keys[idx];
                                self.dlg_name = ck.name.clone();
                                self.dlg_key = ck.key.clone();
                                self.dlg_full_tunnel = ck.full_tunnel;
                                self.dlg_proxy = ck.proxy_listen.is_some();
                                self.dlg_proxy_addr = ck.proxy_listen.clone().unwrap_or_default();
                                self.dlg_exclude_routes = ck.exclude_routes.join("\n");
                                self.dlg_include_routes = ck.include_routes.join("\n");
                                self.dlg_mtls_cert = ck.mtls_cert_path.clone().unwrap_or_default();
                                self.dlg_error = None;
                                self.editing_idx = Some(idx);
                                self.show_dialog = true;
                            }
                        }
                        if ui
                            .add_enabled(
                                sel.is_some() && !is_connected,
                                egui::Button::new(t(lang, "delete")),
                            )
                            .clicked()
                        {
                            if let Some(idx) = sel {
                                self.keys.remove_key(idx);
                            }
                        }
                    });

                    ui.separator();

                    // ── Traffic indicators (quality / FEC / uptime) ────────────────
                    ui.horizontal(|ui| {
                        if is_connected && quality > 0 {
                            let qc = if quality >= 70 {
                                egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                            } else if quality >= 40 {
                                egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                            } else {
                                egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                            };
                            ui.label(
                                egui::RichText::new(format!("Q:{quality}%"))
                                    .color(qc)
                                    .size(13.0),
                            );
                        }
                        let sal = self.vpn.stats().server_adaptive_level;
                        if is_connected && (sal >= 2 || self.settings.adaptive_level >= 2) {
                            ui.label(
                                egui::RichText::new("FEC")
                                    .color(egui::Color32::from_rgb(0x42, 0xA5, 0xF5))
                                    .size(13.0)
                                    .strong(),
                            );
                        }
                    });

                    ui.separator();

                    // ── Recording (only when server reports capability) ────────────
                    if is_connected
                        && self.vpn.recording_capability_known
                        && self.vpn.can_record_masks
                    {
                        let is_rec = self.vpn.is_recording();
                        let rec_busy = self.vpn.recording_button_disabled();
                        let rec_status: Option<&'static str> = match &self.vpn.recording_state {
                            RecordingState::Starting(_) => Some(t(lang, "recording_starting")),
                            RecordingState::Recording(_) => Some(t(lang, "recording_active")),
                            RecordingState::Stopping(_) => Some(t(lang, "recording_stopping")),
                            RecordingState::Analyzing(_) => Some(t(lang, "recording_analyzing")),
                            RecordingState::Success(_, _) => Some(t(lang, "recording_success")),
                            RecordingState::Failed(_, _) => Some(t(lang, "recording_failed")),
                            RecordingState::Idle => None,
                        };
                        let rec_result = self.vpn.last_recording_result.clone();
                        ui.horizontal(|ui| {
                            if is_rec {
                                let stop_btn = egui::Button::new(
                                    egui::RichText::new(t(lang, "stop_recording"))
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(0xE5, 0x39, 0x35));
                                if ui.add_enabled(!rec_busy, stop_btn).clicked() {
                                    self.vpn.stop_recording();
                                }
                            } else {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.recording_service)
                                        .desired_width(130.0)
                                        .hint_text(t(lang, "record_service_name")),
                                );
                                let svc = {
                                    let s = self.recording_service.trim().to_string();
                                    if s.is_empty() {
                                        "custom".to_string()
                                    } else {
                                        s
                                    }
                                };
                                if ui
                                    .add_enabled(
                                        !rec_busy,
                                        egui::Button::new(t(lang, "record_new_mask")),
                                    )
                                    .clicked()
                                {
                                    self.vpn.start_recording(&svc);
                                }
                            }
                            if let Some(s) = rec_status {
                                ui.label(egui::RichText::new(s).size(11.0).weak());
                            }
                        });
                        if let Some(result) = rec_result {
                            let color = if result.succeeded {
                                egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                            } else {
                                egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&result.details).color(color).size(11.0),
                                );
                                if ui.small_button(t(lang, "dismiss")).clicked() {
                                    self.vpn.clear_recording_result();
                                }
                            });
                        }

                        // ── Diagnostics / Benchmark ───────────────────────────────
                        ui.horizontal(|ui| {
                            let bench_lbl = if self.bench_running {
                                t(lang, "bench_running")
                            } else {
                                t(lang, "run_benchmark")
                            };
                            if ui
                                .add_enabled(!self.bench_running, egui::Button::new(bench_lbl))
                                .clicked()
                            {
                                let binary = self.vpn.client_binary.clone();
                                let server = self.vpn.server_addr().unwrap_or("").to_string();
                                if server.is_empty() {
                                    self.show_error(
                                        "No server address — reconnect first".to_string(),
                                    );
                                } else {
                                    self.bench_running = true;
                                    self.bench_result = None;
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    self.bench_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let result =
                                            VpnManager::run_bench_blocking(&binary, &server);
                                        let _ = tx.send(result);
                                    });
                                }
                            }
                            if let Some(ref r) = self.bench_result {
                                let qc = if r.quality_score >= 70 {
                                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                } else if r.quality_score >= 40 {
                                    egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                                } else {
                                    egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                                };
                                ui.label(
                                    egui::RichText::new(format!(
                                        "P50: {:.0}ms  Q:{}/100",
                                        r.latency_p50_ms, r.quality_score
                                    ))
                                    .color(qc)
                                    .size(12.0),
                                );
                            }
                        });

                        ui.separator();
                    }

                    // ── Admin panel (P3.4) — Viewer(1) and Admin(2) both get ────────
                    // ── clients/pool/audit (G-A1/G-A2); Viewer read-only ─────────────
                    if is_connected && matches!(self.admin_role, Some(1) | Some(2)) {
                        self.draw_admin_panel(ui, lang);
                        ui.separator();
                    }

                    // ── Settings ───────────────────────────────────────────────────
                    let mut ks = self.settings.kill_switch;
                    if ui
                        .add_enabled(
                            !is_connected && !is_busy,
                            egui::Checkbox::new(&mut ks, t(lang, "kill_switch")),
                        )
                        .changed()
                    {
                        self.settings.kill_switch = ks;
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    // Grid ensures both labels share the same column width → comboboxes align
                    egui::Grid::new("settings_controls")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(t(lang, "adaptive_mode"));
                            const ADM_DESCS: &[&str] = &[
                                "Server picks the best profile automatically",
                                "Basic traffic mimicry. Keepalive every 15 s.",
                                "HTTPS/QUIC mimicry. Keepalive every 8 s.",
                                "Max mimicry. Optimized for high latency (>300 ms).",
                            ];
                            let labels = ["Auto", "Light", "Aggressive", "Satellite"];
                            let mut adp = self.settings.adaptive_level as usize;
                            egui::ComboBox::from_id_salt("adp")
                                .selected_text(labels[adp.min(3)])
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    for (i, lbl) in labels.iter().enumerate() {
                                        if ui
                                            .selectable_value(&mut adp, i, *lbl)
                                            .on_hover_text(ADM_DESCS[i])
                                            .changed()
                                        {
                                            self.settings.adaptive_level = adp as u8;
                                            self.dirty_at.get_or_insert(Instant::now());
                                        }
                                    }
                                });
                            ui.end_row();

                            ui.label(t(lang, "mask_profile"));
                            // Prefer the server-pushed catalog (auto masks marked
                            // "(авто)"); fall back to the built-in presets until a
                            // catalog has been received.
                            let mask_choices: Vec<(String, String)> = mask_choices_from_catalog(
                                self.settings.lang,
                            )
                            .unwrap_or_else(|| {
                                [
                                    "auto",
                                    "webrtc_zoom_v3",
                                    "quic_https_v2",
                                    "webrtc_yandex_telemost_v1",
                                    "webrtc_vk_teams_v1",
                                    "webrtc_sberjazz_v1",
                                ]
                                .iter()
                                .map(|s| (s.to_string(), s.to_string()))
                                .collect()
                            });
                            let cur = self.settings.preferred_mask.clone();
                            let cur_label = mask_choices
                                .iter()
                                .find(|(id, _)| id == &cur)
                                .map(|(_, d)| d.clone())
                                .unwrap_or_else(|| "auto".to_string());
                            egui::ComboBox::from_id_salt("mask_profile")
                                .selected_text(cur_label)
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    for (id, display) in &mask_choices {
                                        if ui
                                            .selectable_value(
                                                &mut self.settings.preferred_mask,
                                                id.clone(),
                                                display,
                                            )
                                            .changed()
                                        {
                                            if self.settings.preferred_mask == "auto" {
                                                // "Auto" has no concrete base mask to
                                                // polymorph from — leaving the toggle
                                                // checked would be inert (disabled in
                                                // the UI, but the stored value stays
                                                // true and could still be persisted).
                                                self.settings.polymorphic_mask = false;
                                            }
                                            self.dirty_at.get_or_insert(Instant::now());
                                        }
                                    }
                                });
                            ui.end_row();
                        });

                    let cur_mask_is_preset = self.settings.preferred_mask != "auto"
                        && !self.settings.preferred_mask.is_empty();
                    let mut polymorphic = self.settings.polymorphic_mask;
                    if ui
                        .add_enabled(
                            cur_mask_is_preset,
                            egui::Checkbox::new(&mut polymorphic, t(lang, "polymorphic_mask")),
                        )
                        .on_hover_text(t(lang, "polymorphic_mask_hint"))
                        .changed()
                    {
                        self.settings.polymorphic_mask = polymorphic;
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    ui.label(t(lang, "dns_proxy"));
                    let dns_r = ui.add(
                        egui::TextEdit::singleline(&mut self.settings.dns_proxy)
                            .desired_width(f32::INFINITY)
                            .hint_text("127.0.0.1:5353"),
                    );
                    if dns_r.changed() {
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    egui::CollapsingHeader::new(t(lang, "mask_feedback_section")).show(ui, |ui| {
                        ui.label(t(lang, "mask_feedback_hint"));

                        let mut share_fb = self.settings.share_mask_feedback;
                        if ui
                            .checkbox(&mut share_fb, t(lang, "share_mask_feedback"))
                            .changed()
                        {
                            self.settings.share_mask_feedback = share_fb;
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        let mut receive_hints = self.settings.receive_mask_hints;
                        if ui
                            .checkbox(&mut receive_hints, t(lang, "receive_mask_hints"))
                            .changed()
                        {
                            self.settings.receive_mask_hints = receive_hints;
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "country_code"));
                        let cc_r = ui.add(
                            egui::TextEdit::singleline(&mut self.settings.country_code)
                                .desired_width(60.0)
                                .char_limit(2)
                                .hint_text("DE"),
                        );
                        if cc_r.changed() {
                            // Filter to ASCII letters only (drop digits/punctuation), matching
                            // the Linux/macOS/iOS country-code inputs.
                            self.settings.country_code = self
                                .settings
                                .country_code
                                .chars()
                                .filter(|c| c.is_ascii_alphabetic())
                                .take(2)
                                .collect::<String>()
                                .to_uppercase();
                            self.dirty_at.get_or_insert(Instant::now());
                        }
                    });

                    egui::CollapsingHeader::new(t(lang, "bootstrap_section")).show(ui, |ui| {
                        ui.label(t(lang, "bootstrap_hint"));

                        ui.label(t(lang, "bootstrap_cdn_url"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.bootstrap_cdn_url)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_telegram_token"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(
                                    &mut self.settings.bootstrap_telegram_token,
                                )
                                .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_telegram_chat"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(
                                    &mut self.settings.bootstrap_telegram_chat,
                                )
                                .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_github"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.bootstrap_github)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "server_signing_key"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.server_signing_key)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }
                    });

                    let mut startup = self.settings.connect_on_startup;
                    if ui
                        .checkbox(&mut startup, t(lang, "connect_on_startup"))
                        .changed()
                    {
                        self.settings.connect_on_startup = startup;
                        set_autostart(startup);
                        // Save immediately — registry and settings.json must stay in sync
                        self.settings.save();
                        self.dirty_at = None;
                    }
                    // ── Error / warning ────────────────────────────────────────────
                    if let Some(err) = &error_display {
                        ui.separator();
                        let err_color = if no_traffic_warn {
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                        } else {
                            egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                        };
                        let is_persistent_vpn_err = self.error_msg.is_none()
                            && self
                                .vpn
                                .last_error
                                .as_deref()
                                .is_some_and(|e| !e.is_empty());
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(err).color(err_color).size(12.0),
                                )
                                .wrap(),
                            );
                            if is_persistent_vpn_err {
                                if ui.small_button("✕").clicked() {
                                    self.vpn.last_error = None;
                                }
                            }
                        });
                    }
                });
        });

        // P3.4: connection-key/QR viewer window + revoke-confirmation modal —
        // separate top-level containers, drawn once per frame regardless of
        // whether draw_admin_panel() ran this frame (admin_key_id/
        // admin_revoke_id can still be Some right after the panel itself
        // stops being drawn, e.g. a disconnect mid-dialog — reset_admin_state()
        // clears both, but only on the NEXT tick(), not synchronously here).
        self.draw_admin_extras(ctx, lang);

        // C3: SSH install wizard window — same "always drawn, independent
        // of draw_admin_panel this frame" rationale as draw_admin_extras
        // above (its own `ssh_wizard_open` flag gates visibility). GAP-G1:
        // the migration wizard (export/import via the tunnel mgmt bridge)
        // was removed — migration is a web-panel-only feature.
        self.draw_ssh_install_window(ctx, lang);

        // ── Add / Edit dialog — separate OS window (can go outside main window) ──
        if self.show_dialog {
            let title = if self.editing_idx.is_some() {
                t(lang, "edit")
            } else {
                t(lang, "add_key")
            };
            // Split-borrow individual fields so the FnMut closure can mutate them
            // while `ctx` (a separate parameter, not part of self) drives the call.
            let show_dialog = &mut self.show_dialog;
            let editing_idx = &mut self.editing_idx;
            let dlg_name = &mut self.dlg_name;
            let dlg_key = &mut self.dlg_key;
            let dlg_full_tunnel = &mut self.dlg_full_tunnel;
            let dlg_proxy = &mut self.dlg_proxy;
            let dlg_proxy_addr = &mut self.dlg_proxy_addr;
            let dlg_exclude_routes = &mut self.dlg_exclude_routes;
            let dlg_include_routes = &mut self.dlg_include_routes;
            let dlg_mtls_cert = &mut self.dlg_mtls_cert;
            let dlg_error = &mut self.dlg_error;
            let keys = &mut self.keys;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("key_dialog"),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([370.0, 470.0])
                    .with_resizable(true),
                |ctx, _| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        *show_dialog = false;
                        *dlg_error = None;
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.label(t(lang, "key_name"));
                        ui.add(egui::TextEdit::singleline(dlg_name).desired_width(f32::INFINITY));
                        ui.add_space(4.0);
                        ui.label(t(lang, "key_value"));
                        ui.add(
                            egui::TextEdit::singleline(dlg_key)
                                .desired_width(f32::INFINITY)
                                .hint_text("aivpn://…")
                                // LOW/MEDIUM: this field carries the PSK-bearing
                                // aivpn:// connection key — mask it like a password
                                // field so it isn't rendered in clear text on screen
                                // (shoulder-surf / screenshot exposure). Verified
                                // against the vendored egui 0.31.1 source
                                // (widgets/text_edit/builder.rs): `password(bool)` is
                                // a real TextEdit builder method in this version.
                                .password(true),
                        );
                        ui.add_space(4.0);
                        ui.checkbox(dlg_full_tunnel, t(lang, "full_tunnel"));
                        ui.checkbox(dlg_proxy, t(lang, "proxy_mode"));
                        if *dlg_proxy {
                            ui.add(
                                egui::TextEdit::singleline(dlg_proxy_addr)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("127.0.0.1:1080"),
                            );
                        }
                        ui.add_space(4.0);
                        ui.label(t(lang, "exclude_routes"));
                        ui.add(
                            egui::TextEdit::multiline(dlg_exclude_routes)
                                .desired_width(f32::INFINITY)
                                .desired_rows(3)
                                .hint_text(t(lang, "exclude_routes_hint")),
                        );
                        ui.add_space(4.0);
                        ui.label(t(lang, "include_routes"));
                        ui.add(
                            egui::TextEdit::multiline(dlg_include_routes)
                                .desired_width(f32::INFINITY)
                                .desired_rows(3)
                                .hint_text(t(lang, "include_routes_hint")),
                        );
                        ui.add_space(4.0);
                        ui.label(t(lang, "mtls_cert_path"));
                        ui.add(
                            egui::TextEdit::singleline(dlg_mtls_cert)
                                .desired_width(f32::INFINITY)
                                .hint_text(t(lang, "mtls_cert_hint")),
                        );
                        if let Some(e) = dlg_error.as_deref() {
                            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), e);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let can_save =
                                !dlg_name.trim().is_empty() && !dlg_key.trim().is_empty();
                            if ui
                                .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                                .clicked()
                            {
                                let proxy = if *dlg_proxy && !dlg_proxy_addr.is_empty() {
                                    Some(dlg_proxy_addr.clone())
                                } else {
                                    None
                                };
                                let exclude_routes: Vec<String> = dlg_exclude_routes
                                    .lines()
                                    .map(|l| l.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                let include_routes: Vec<String> = dlg_include_routes
                                    .lines()
                                    .map(|l| l.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                let mtls = if dlg_mtls_cert.trim().is_empty() {
                                    None
                                } else {
                                    Some(dlg_mtls_cert.trim().to_string())
                                };
                                let result = if let Some(idx) = *editing_idx {
                                    keys.update_key(
                                        idx,
                                        dlg_name,
                                        dlg_key,
                                        *dlg_full_tunnel,
                                        proxy,
                                        mtls,
                                        exclude_routes,
                                        include_routes,
                                    )
                                } else {
                                    keys.add_key(
                                        dlg_name,
                                        dlg_key,
                                        *dlg_full_tunnel,
                                        proxy,
                                        mtls,
                                        exclude_routes,
                                        include_routes,
                                    )
                                };
                                match result {
                                    Ok(()) => {
                                        *show_dialog = false;
                                        *dlg_error = None;
                                    }
                                    Err(e) => *dlg_error = Some(e),
                                }
                            }
                            if ui.button(t(lang, "cancel")).clicked() {
                                *show_dialog = false;
                                *dlg_error = None;
                            }
                        });
                    });
                },
            );
        }

        // Minimize → hide to tray (fix: minimize was going to taskbar, not tray)
        if ctx.input(|i| i.viewport().minimized.unwrap_or(false)) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            #[cfg(windows)]
            unsafe {
                use winapi::um::winuser::{ShowWindow, SW_HIDE};
                let hwnd = find_own_aivpn_hwnd();
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            self.window_visible = false;
        }

        // Close button → hide to tray instead of quitting (skip when quit was requested)
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            #[cfg(windows)]
            unsafe {
                use winapi::um::winuser::{ShowWindow, SW_HIDE};
                let hwnd = find_own_aivpn_hwnd();
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            self.window_visible = false;
        }

        // Repaint every second for live uptime/traffic display
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if !self.quitting {
            self.vpn.disconnect();
            let _ = self.settings.save();
        }
    }
}
