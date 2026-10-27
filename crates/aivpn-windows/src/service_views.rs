use crate::localization::{t, Lang};
use crate::vpn_manager::{RecordingState, VpnManager};
use eframe::egui;

impl crate::AivpnApp {
    pub(crate) fn draw_service_tools(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let is_connected = self.vpn.is_connected();
        // Запись доступна после подтверждения сервером.
        if is_connected && self.vpn.recording_capability_known && self.vpn.can_record_masks {
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
            ui.horizontal_wrapped(|ui| {
                if is_rec {
                    let stop_btn = egui::Button::new(
                        egui::RichText::new(t(lang, "stop_recording")).color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0xC4, 0x2B, 0x1C));
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
                        .add_enabled(!rec_busy, egui::Button::new(t(lang, "record_new_mask")))
                        .clicked()
                    {
                        self.vpn.start_recording(&svc);
                    }
                }
                if let Some(s) = rec_status {
                    ui.label(egui::RichText::new(s).size(12.0).weak());
                }
            });
            if let Some(result) = rec_result {
                let color = if result.succeeded {
                    crate::assets::fluent_colors(ui.visuals().dark_mode).success
                } else {
                    ui.visuals().error_fg_color
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(&result.details).color(color).size(12.0));
                    if ui.small_button(t(lang, "dismiss")).clicked() {
                        self.vpn.clear_recording_result();
                    }
                });
            }
        }

        if is_connected {
            // Проверка качества текущего соединения.
            ui.horizontal_wrapped(|ui| {
                            let bench_lbl = if self.bench_running {
                                t(lang, "bench_running")
                            } else {
                                t(lang, "run_benchmark")
                            };
                            if ui
                                .add_enabled(!self.bench_running, egui::Button::new(bench_lbl))
                                .clicked()
                            {
                                let token = crate::admin::read_admin_token();
                                let server = self.vpn.server_addr().unwrap_or("").to_string();
                                if server.is_empty() {
                                    self.show_error(
                                        crate::appearance::text(lang,"Адрес сервера неизвестен. Подключитесь повторно.","Server address is unknown. Reconnect first.").to_string(),
                                    );
                                } else {
                                    self.bench_running = true;
                                    self.bench_result = None;
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    self.bench_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let result =
                                            VpnManager::run_bench_blocking(token);
                                        let _ = tx.send(result);
                                    });
                                }
                            }
                            if let Some(ref r) = self.bench_result {
                                let qc = if r.quality_score >= 70 {
                                    crate::assets::fluent_colors(ui.visuals().dark_mode).success
                                } else if r.quality_score >= 40 {
                                    ui.visuals().warn_fg_color
                                } else {
                                    ui.visuals().error_fg_color
                                };
                                ui.label(
                                    egui::RichText::new(format!(
                                        "P50/P95/P99: {:.0}/{:.0}/{:.0}ms  Loss: {:.1}%  Q:{}/100  ↑ {:.0} ↓ {:.0} kbps",
                                        r.latency_p50_ms,
                                        r.latency_p95_ms,
                                        r.latency_p99_ms,
                                        r.packet_loss_pct,
                                        r.quality_score,
                                        r.throughput_up_kbps,
                                        r.throughput_down_kbps
                                    ))
                                    .color(qc)
                                    .size(12.0),
                                );
                            }
                        });

            ui.separator();
        }

        // Наблюдатель читает списки, изменения доступны администратору.
        if is_connected && matches!(self.admin_role, Some(1) | Some(2)) {
            self.draw_admin_panel(ui, lang);
            ui.separator();
        }
    }
}
