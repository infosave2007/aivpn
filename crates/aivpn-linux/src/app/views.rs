//! `view`/`view_*` rendering methods for the iced `App`. Moved verbatim out
//! of `app/mod.rs` (pure move, no behavior change).

use super::*;
use iced::widget::{column, row};

impl super::App {
    pub fn view(&self) -> Element<'_, Message> {
        if self.dialog != DialogMode::None {
            return self.view_dialog();
        }
        self.view_main()
    }

    fn view_main(&self) -> Element<'_, Message> {
        let is_dark = self.settings.dark_mode;
        let lang = self.settings.lang.as_str();

        // Adaptive palette — grey tones that contrast in both light and dark themes
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        // Card surface must visibly stand out from the window background.
        // iced Theme::Dark background ≈ rgb(0.20, 0.20, 0.20); card at 0.27 gives clear delta.
        let card_bg = if is_dark {
            Color::from_rgb(0.26, 0.27, 0.35)
        } else {
            Color::from_rgb(0.92, 0.93, 0.97)
        };
        let card_border_color = if is_dark {
            Color::from_rgba(1.0, 1.0, 1.0, 0.09)
        } else {
            Color::from_rgba(0.0, 0.0, 0.0, 0.07)
        };

        // ── Status colours ────────────────────────────────────────────────────
        let (dot_color, status_str, status_color) = match &self.status {
            VpnStatus::Disconnected => (
                muted,
                t(lang, "Disconnected").to_string(),
                if is_dark {
                    Color::from_rgb(0.82, 0.84, 0.90)
                } else {
                    Color::from_rgb(0.33, 0.35, 0.42)
                },
            ),
            VpnStatus::Connecting => (
                Color::from_rgb(1.0, 0.70, 0.15),
                t(lang, "Connecting...").to_string(),
                Color::from_rgb(1.0, 0.70, 0.15),
            ),
            VpnStatus::Connected { vpn_ip } => {
                // MEDIUM-HIGH #3 (client parity): elapsed connection time,
                // derived the same way Windows (vpn_manager.rs
                // session_since_ms) and macOS (VPNManager) do — wall-clock
                // now minus the client's session epoch — instead of never
                // showing uptime at all. `connected_since` is already parsed
                // by `read_traffic_stats()`/`parse_traffic_stats()` from the
                // stats file's `since:` key; previously only consulted here
                // to detect a silent in-process reconnect, never displayed.
                let uptime_str = self.stats.connected_since.map(|since_ms| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(since_ms);
                    let secs = now_ms.saturating_sub(since_ms) / 1000;
                    let h = secs / 3600;
                    let m = (secs % 3600) / 60;
                    let s = secs % 60;
                    if h > 0 {
                        format!("{h}:{m:02}:{s:02}")
                    } else {
                        format!("{m}:{s:02}")
                    }
                });
                let label = if lang == "ru" {
                    "Подключено"
                } else {
                    "Connected"
                };
                let status_str = match &uptime_str {
                    Some(u) => format!("{label}  {vpn_ip}  {u}"),
                    None => format!("{label}  {vpn_ip}"),
                };
                (
                    Color::from_rgb(0.25, 0.84, 0.36),
                    status_str,
                    Color::from_rgb(0.25, 0.84, 0.36),
                )
            }
            VpnStatus::Error(e) => (
                Color::from_rgb(0.95, 0.28, 0.18),
                format!(
                    "{}: {e}",
                    if lang == "ru" {
                        "Ошибка"
                    } else {
                        "Error"
                    }
                ),
                Color::from_rgb(0.95, 0.28, 0.18),
            ),
        };

        // ── Header ────────────────────────────────────────────────────────────
        // Container-dot avoids Unicode glyph rendering issues on systems with
        // limited fonts — renders as a 10×10 colored circle regardless.
        let dot = container(Space::with_width(0))
            .width(10)
            .height(10)
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(dot_color)),
                border: Border {
                    radius: 5.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            });
        let theme_btn = button(if self.settings.dark_mode {
            "Light"
        } else {
            "Dark"
        })
        .on_press(Message::ToggleTheme)
        .style(button::text);
        let lang_btn = button(if lang == "ru" { "EN" } else { "RU" })
            .on_press(Message::ToggleLang)
            .style(button::text);
        let version_label = text(concat!("v", env!("CARGO_PKG_VERSION")))
            .size(11)
            .color(muted);
        let header = row![
            dot,
            Space::with_width(6),
            text("AIVPN").size(17),
            Space::with_width(Length::Fill),
            version_label,
            Space::with_width(4),
            lang_btn,
            Space::with_width(2),
            theme_btn,
        ]
        .align_y(Alignment::Center);

        // ── Status card ───────────────────────────────────────────────────────
        let busy = matches!(
            self.status,
            VpnStatus::Connected { .. } | VpnStatus::Connecting
        );
        let is_connected = matches!(self.status, VpnStatus::Connected { .. });
        let has_profile = self.storage.selected_key().is_some();

        let profile_hint: Element<Message> = if let Some(k) = self.storage.selected_key() {
            text(format!("-> {}", k.name)).size(11).color(muted).into()
        } else if self.storage.keys.is_empty() {
            text(t(lang, "No profiles - add one below"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        } else {
            text(t(lang, "Select a profile below"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        };

        let conn_btn: Element<Message> = if busy {
            button(text(t(lang, "Disconnect")).size(13))
                .on_press(Message::Disconnect)
                .style(button::danger)
                .padding([6, 14])
                .into()
        } else {
            let b = button(text(t(lang, "Connect")).size(13))
                .style(button::primary)
                .padding([6, 14]);
            if has_profile {
                b.on_press(Message::Connect).into()
            } else {
                b.into()
            }
        };

        let traffic_row: Element<Message> = if is_connected {
            let mut r = row![
                text(format!("RX {}", format_bytes(self.stats.bytes_received)))
                    .size(11)
                    .color(muted),
                Space::with_width(6),
                text(format!("TX {}", format_bytes(self.stats.bytes_sent)))
                    .size(11)
                    .color(muted),
            ];
            // Live link quality from the client's quality.json (0 = not
            // reported yet / old client).
            if self.stats.quality_score > 0 {
                r = r.push(Space::with_width(6)).push(
                    text(format!("Q {}%", self.stats.quality_score))
                        .size(11)
                        .color(muted),
                );
            }
            r.align_y(Alignment::Center).into()
        } else {
            profile_hint
        };

        let status_card = container(
            row![
                text(status_str).color(status_color).size(14),
                Space::with_width(8),
                traffic_row,
                Space::with_width(Length::Fill),
                conn_btn,
            ]
            .align_y(Alignment::Center),
        )
        .style(move |_theme: &Theme| container::Style {
            background: Some(Background::Color(card_bg)),
            border: Border {
                radius: 8.0.into(),
                width: 1.0,
                color: card_border_color,
            },
            ..Default::default()
        })
        .padding([10, 12])
        .width(Length::Fill);

        // 3c: brief indicator shown while this session is running on the
        // built-in default mask (bootstrap-fallback) rather than a normal
        // bootstrap-derived one — only meaningful while a connection is
        // active/being attempted, and cleared on every new Connect/Disconnect
        // (see Message::Connect / Message::Disconnect / BootstrapFallbackDetected).
        let fallback_badge: Element<Message> = if self.bootstrap_fallback && busy {
            text(t(lang, "Using built-in mask (fallback)"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        } else {
            Space::with_height(0).into()
        };

        // ── Profiles ──────────────────────────────────────────────────────────
        let profiles_header = row![
            text(t(lang, "Profiles")).size(14),
            Space::with_width(Length::Fill),
            button(t(lang, "+ Add"))
                .on_press(Message::ShowAddDialog)
                .style(button::text),
        ]
        .align_y(Alignment::Center);

        let profile_rows: Vec<Element<Message>> = self
            .storage
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let is_selected = self.storage.selected == Some(i);
                let name_text = text(&k.name).size(13);
                let addr_text = text(if k.server_addr.is_empty() {
                    "-"
                } else {
                    &k.server_addr
                })
                .size(11)
                .color(muted);
                let profile_col = column![name_text, addr_text].spacing(1);

                let edit_btn = button(t(lang, "Edit"))
                    .on_press(Message::ShowEditDialog(i))
                    .style(button::text);
                let del_btn = button("x")
                    .on_press(Message::RemoveProfile(i))
                    .style(button::text);

                let row_content: Element<Message> = row![
                    profile_col,
                    Space::with_width(Length::Fill),
                    edit_btn,
                    del_btn,
                ]
                .spacing(4)
                .align_y(Alignment::Center)
                .into();

                if is_selected {
                    container(row_content)
                        .padding([6, 8])
                        .width(Length::Fill)
                        .style(|theme: &Theme| {
                            let palette = theme.extended_palette();
                            container::Style {
                                background: Some(Background::Color(palette.primary.weak.color)),
                                border: Border {
                                    radius: 6.0.into(),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        })
                        .into()
                } else {
                    button(row_content)
                        .on_press(Message::SelectProfile(i))
                        .width(Length::Fill)
                        .style(button::text)
                        .padding([6, 8])
                        .into()
                }
            })
            .collect();

        let profile_list_h = ((self.storage.keys.len() * 46) + 8).max(46).min(180) as u16;
        let profiles_list = container(
            scrollable(
                container(column(profile_rows).spacing(2))
                    .width(Length::Fill)
                    .padding(4),
            )
            .height(profile_list_h),
        )
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style {
                border: Border {
                    radius: 6.0.into(),
                    width: 1.0,
                    color: palette.background.weak.color,
                },
                ..Default::default()
            }
        })
        .width(Length::Fill);
        // ── Recording (visible when connected) ────────────────────────────────
        let recording_section: Element<Message> =
            if matches!(self.status, VpnStatus::Connected { .. }) {
                match &self.recording_state {
                    RecordingState::Done { succeeded, details } => {
                        let color = if *succeeded {
                            Color::from_rgb(0.2, 0.75, 0.3)
                        } else {
                            Color::from_rgb(0.9, 0.2, 0.1)
                        };
                        column![
                            text(t(lang, "Record New Mask")).size(13),
                            row![
                                text(details).color(color).size(12),
                                Space::with_width(Length::Fill),
                                button(t(lang, "Dismiss"))
                                    .on_press(Message::DismissRecordingResult)
                                    .style(button::text),
                            ]
                            .align_y(Alignment::Center),
                        ]
                        .spacing(4)
                        .into()
                    }
                    RecordingState::Active(svc) => row![
                        text(format!("{} {svc}", t(lang, "Recording:")))
                            .color(Color::from_rgb(0.9, 0.2, 0.1))
                            .size(13),
                        Space::with_width(Length::Fill),
                        button(t(lang, "Stop"))
                            .on_press(Message::StopRecording)
                            .style(button::danger),
                    ]
                    .align_y(Alignment::Center)
                    .into(),
                    RecordingState::Stopping => row![text(t(lang, "Stopping recording..."))
                        .color(Color::from_rgb(0.9, 0.6, 0.1))
                        .size(13),]
                    .into(),
                    RecordingState::Idle => column![
                        text(t(lang, "Record New Mask")).size(13),
                        row![
                            text_input("Service name", &self.recording_service)
                                .on_input(Message::RecordServiceChanged)
                                .width(180),
                            Space::with_width(8),
                            button(t(lang, "Start Recording")).on_press(Message::StartRecording),
                        ]
                        .align_y(Alignment::Center),
                    ]
                    .spacing(4)
                    .into(),
                }
            } else {
                Space::with_height(0).into()
            };

        // Only frame the recording area with its own trailing separator when
        // there is something to show (connected). Disconnected, the section is
        // empty, so a single separator sits between SOCKS5 and Bootstrap rather
        // than two with a blank gap between them.
        let recording_block: Element<Message> =
            if matches!(self.status, VpnStatus::Connected { .. }) {
                column![
                    Space::with_height(6),
                    recording_section,
                    Space::with_height(6),
                    horizontal_rule(1),
                ]
                .into()
            } else {
                Space::with_height(0).into()
            };

        // ── Diagnostics / Bench ───────────────────────────────────────────────
        let bench_label: Element<Message> = if self.bench_running {
            text(t(lang, "Running diagnostics..."))
                .color(muted)
                .size(12)
                .into()
        } else if let Some(r) = &self.bench_result {
            text(r).size(12).into()
        } else {
            Space::with_height(0).into()
        };
        let diag_btn = {
            let b = button(t(lang, "Diagnostics")).style(button::secondary);
            if !self.bench_running {
                b.on_press(Message::RunDiagnostics)
            } else {
                b
            }
        };

        let adaptive_opt = AdaptiveOption::from_level(self.settings.adaptive_level);
        // The FEC badge reflects the LIVE level the server actually runs the
        // session at (quality.json) when connected — not merely the requested
        // preference, which the adaptive controller may have overridden.
        let live_level = if is_connected && self.stats.server_adaptive_level > 0 {
            self.stats.server_adaptive_level
        } else {
            self.settings.adaptive_level
        };
        let fec_text = if live_level >= 2 { " [FEC]" } else { "" };
        let fec_badge = text(fec_text)
            .color(Color::from_rgb(0.3, 0.8, 0.5))
            .size(11);
        let adaptive_row = row![
            text(t(lang, "Adaptive mode")).size(13).width(130),
            pick_list(
                AdaptiveOption::all(),
                Some(adaptive_opt.clone()),
                Message::AdaptiveLevelChanged,
            )
            .width(200),
            fec_badge,
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let adaptive_desc = text(adaptive_opt.desc(lang)).size(11).color(muted);

        let mask_opt = MaskOption::from_str(&self.settings.preferred_mask);
        // Dynamic picker: prefer the server-pushed catalog (which marks
        // auto-generated masks "(авто)"); fall back to the built-in presets
        // until a catalog has been received.
        let mask_choices: Vec<MaskChoice> = mask_choices_from_catalog(lang).unwrap_or_else(|| {
            MaskOption::all()
                .iter()
                .map(|m| MaskChoice {
                    id: m.as_str().to_string(),
                    display: m.label().to_string(),
                })
                .collect()
        });
        let selected_choice = mask_choices
            .iter()
            .find(|c| c.id == self.settings.preferred_mask)
            .cloned()
            .or_else(|| mask_choices.first().cloned());
        let mask_row = row![
            text(t(lang, "Mask profile")).size(13).width(130),
            pick_list(mask_choices, selected_choice, |c: MaskChoice| {
                Message::MaskOptionChanged(c.id)
            })
            .width(200),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let mask_desc = text(mask_opt.desc(lang)).size(11).color(muted);

        // Polymorphic masks only make sense with a concrete (non-"auto") base mask —
        // mirrors the Windows/macOS/iOS GUIs, which all disable this control on "auto".
        let mask_is_preset =
            self.settings.preferred_mask != "auto" && !self.settings.preferred_mask.is_empty();
        let polymorphic_row = checkbox(
            t(lang, "Polymorphic (per-session unique shape)"),
            self.settings.polymorphic_mask,
        )
        .on_toggle_maybe(mask_is_preset.then_some(Message::TogglePolymorphicMask));
        let polymorphic_desc = text(t(
            lang,
            "Each session gets a unique variant of the selected mask. Not used with \"Auto\".",
        ))
        .size(11)
        .color(muted);

        // Stack the two toggles vertically: side by side they overflowed a
        // narrow window and wrapped to one letter per line ("плывёт").
        let feedback_row = column![
            checkbox(
                t(lang, "Share blocked-mask feedback"),
                self.settings.share_mask_feedback
            )
            .on_toggle(Message::ToggleShareMaskFeedback),
            checkbox(
                t(lang, "Receive mask hints for my region"),
                self.settings.receive_mask_hints
            )
            .on_toggle(Message::ToggleReceiveMaskHints),
        ]
        .spacing(6);

        let country_code_row = row![
            text(t(lang, "Country code")).size(13).width(130),
            text_input("DE", &self.settings.country_code)
                .on_input(Message::CountryCodeChanged)
                .width(80),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let kill_switch_row = checkbox(t(lang, "Kill switch"), self.settings.kill_switch)
            .on_toggle(Message::ToggleKillSwitch);
        let autostart_row = checkbox(t(lang, "Start on login"), self.settings.autostart)
            .on_toggle(Message::ToggleAutostart);

        let dns_row = row![
            text(t(lang, "DNS proxy")).size(13).width(130),
            text_input("127.0.0.1:5300", &self.settings.dns_proxy)
                .on_input(Message::DnsProxyChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let routes_row = row![
            text(t(lang, "Exclude routes")).size(13).width(130),
            text_input("10.0.0.0/8, 192.168.0.0/16", &self.settings.exclude_routes)
                .on_input(Message::ExcludeRoutesChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let include_routes_row = row![
            text(t(lang, "Include routes only")).size(13).width(130),
            text_input("10.0.0.0/8", &self.settings.include_routes)
                .on_input(Message::IncludeRoutesChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let socks5_addr_input: Element<Message> = if self.settings.socks5_enabled {
            text_input("127.0.0.1:1080", &self.settings.socks5_addr)
                .on_input(Message::Socks5AddrChanged)
                .width(Length::Fill)
                .into()
        } else {
            Space::with_width(Length::Fill).into()
        };
        let socks5_row = row![
            checkbox(t(lang, "SOCKS5 proxy"), self.settings.socks5_enabled)
                .on_toggle(Message::ToggleSocks5),
            Space::with_width(8),
            socks5_addr_input,
        ]
        .align_y(Alignment::Center);

        let bootstrap_toggle_label = if self.bootstrap_open {
            format!("[-] {}", t(lang, "Bootstrap (advanced)"))
        } else {
            format!("[+] {}", t(lang, "Bootstrap (advanced)"))
        };
        let bootstrap_header = row![
            button(text(bootstrap_toggle_label))
                .on_press(Message::ToggleBootstrapPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center);
        let bootstrap_desc_text = text(bootstrap_desc(lang)).size(11).color(muted);

        let bootstrap_box: Element<Message> = if self.bootstrap_open {
            let cdn_row = row![
                text(t(lang, "Bootstrap CDN URL")).size(13).width(130),
                text_input(
                    "https://cdn.example.com/bootstrap.json",
                    &self.settings.bootstrap_cdn_url
                )
                .on_input(Message::BootstrapCdnUrlChanged)
                .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let telegram_token_row = row![
                text(t(lang, "Bootstrap Telegram token"))
                    .size(13)
                    .width(130),
                text_input("123456:ABC-DEF...", &self.settings.bootstrap_telegram_token)
                    .on_input(Message::BootstrapTelegramTokenChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let telegram_chat_row = row![
                text(t(lang, "Bootstrap Telegram chat")).size(13).width(130),
                text_input("@aivpn_channel", &self.settings.bootstrap_telegram_chat)
                    .on_input(Message::BootstrapTelegramChatChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let github_row = row![
                text(t(lang, "Bootstrap GitHub repo")).size(13).width(130),
                text_input("owner/repo", &self.settings.bootstrap_github)
                    .on_input(Message::BootstrapGithubChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let signing_key_row = row![
                text(t(lang, "Server signing key")).size(13).width(130),
                text_input("base64 ed25519 pubkey", &self.settings.server_signing_key)
                    .on_input(Message::ServerSigningKeyChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            column![
                bootstrap_desc_text,
                Space::with_height(4),
                cdn_row,
                telegram_token_row,
                telegram_chat_row,
                github_row,
                signing_key_row,
            ]
            .spacing(4)
            .into()
        } else {
            Space::with_height(0).into()
        };

        let log_toggle_label = if self.logs_open {
            if lang == "ru" {
                "[-] Лог"
            } else {
                "[-] Log"
            }
        } else {
            if lang == "ru" {
                "[+] Лог"
            } else {
                "[+] Log"
            }
        };
        let log_header = row![
            button(log_toggle_label)
                .on_press(Message::ToggleLogPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            button(t(lang, "Clear"))
                .on_press(Message::ClearLog)
                .style(button::text),
            button(if lang == "ru" {
                "Сохранить"
            } else {
                "Save log"
            })
            .on_press(Message::SaveLog)
            .style(button::text),
        ]
        .align_y(Alignment::Center);

        let log_box: Element<Message> = if self.logs_open {
            let log_items: Vec<Element<Message>> = if self.log_lines.is_empty() {
                vec![text(t(lang, "No output yet")).color(muted).into()]
            } else {
                self.log_lines
                    .iter()
                    .map(|l| text(l).size(11).into())
                    .collect()
            };
            scrollable(
                container(column(log_items).spacing(1))
                    .padding(8)
                    .width(Length::Fill),
            )
            .height(160)
            .into()
        } else {
            Space::with_height(0).into()
        };

        // Admin client-management panel: gated on the panel being connected
        // in the first place (a stale role from a just-ended session can
        // never show a panel that would immediately fail every call) AND a
        // confirmed role of Viewer (1) or Admin (2), fetched fresh on every
        // Connected transition (see Message::StatusReceived).
        //
        // G-A1: Viewer gets the SAME panel as Admin, not a separate
        // read-only rendering — `view_admin_section` takes `can_mutate`
        // (true only for Admin) and hides every mutating control
        // (add/edit/enable-disable/reset-device/revoke) itself, leaving
        // just the client list + "Key"/"Show QR" reads, both plain GETs the
        // server's `authorize()` already permits a Viewer. A User (role 0,
        // or no role loaded yet) still sees nothing at all.
        let admin_is_connected = matches!(self.status, VpnStatus::Connected { .. });
        let admin_can_view = admin_is_connected && self.admin_role.is_some_and(|r| r >= 1);
        let admin_can_mutate = admin_is_connected && self.admin_role == Some(2);
        let admin_section: Element<Message> = if admin_can_view {
            self.view_admin_section(admin_can_mutate)
        } else {
            Space::with_height(0).into()
        };
        // Pool topology panel (B3): same connected+Viewer-or-Admin gate as
        // the client-management panel above — pool node/health data is a
        // read like the client list, and this panel has no mutating
        // controls of its own (Refresh is a GET reload).
        let pool_section: Element<Message> = if admin_can_view {
            self.view_pool_section()
        } else {
            Space::with_height(0).into()
        };
        // G-A2: audit-log panel — same Viewer-or-Admin gate; the server's
        // `audit-log` route is GET-only in the curated allowlist regardless
        // of role, so there is nothing to mutate-gate here at all.
        let audit_section: Element<Message> = if admin_can_view {
            self.view_audit_section()
        } else {
            Space::with_height(0).into()
        };
        // G-A3: Server Settings panel — Admin-only (`admin_can_mutate`, NOT
        // `admin_can_view`), unlike the three sections above: every control
        // in this panel mutates server state (apply-with-rollback), so
        // there is no Viewer-visible read-only rendering to fall back to.
        let server_settings_section: Element<Message> = if admin_can_mutate {
            self.view_server_settings_section()
        } else {
            Space::with_height(0).into()
        };

        // C3: SSH server install wizard. Deliberately NOT gated behind
        // `admin_is_connected` like the panels above — this installs a
        // server the GUI isn't (yet) connected to at all (the base "first
        // server from scratch" scenario), so it must be reachable before
        // any VPN session or admin role exists. The one real call it makes
        // (ssh-install, run as a subprocess) surfaces its own "not
        // connected"/error state if attempted at the wrong time.
        let install_wizard_section = self.view_install_wizard_section();

        // Wrap everything in a scrollable so settings + log are reachable
        // in windows smaller than the full content height.
        container(
            scrollable(
                column![
                    header,
                    Space::with_height(4),
                    horizontal_rule(1),
                    Space::with_height(6),
                    status_card,
                    fallback_badge,
                    Space::with_height(8),
                    horizontal_rule(1),
                    Space::with_height(6),
                    profiles_header,
                    Space::with_height(4),
                    profiles_list,
                    Space::with_height(6),
                    row![diag_btn, Space::with_width(8), bench_label].align_y(Alignment::Center),
                    Space::with_height(4),
                    horizontal_rule(1),
                    Space::with_height(6),
                    adaptive_row,
                    adaptive_desc,
                    Space::with_height(2),
                    mask_row,
                    mask_desc,
                    Space::with_height(2),
                    polymorphic_row,
                    polymorphic_desc,
                    Space::with_height(2),
                    feedback_row,
                    country_code_row,
                    Space::with_height(2),
                    row![kill_switch_row, Space::with_width(16), autostart_row]
                        .align_y(Alignment::Center),
                    dns_row,
                    routes_row,
                    include_routes_row,
                    socks5_row,
                    // Single separator after SOCKS5; the recording block adds its
                    // own trailing separator only when connected (see recording_block).
                    Space::with_height(6),
                    horizontal_rule(1),
                    recording_block,
                    Space::with_height(6),
                    admin_section,
                    Space::with_height(6),
                    pool_section,
                    Space::with_height(6),
                    audit_section,
                    Space::with_height(6),
                    server_settings_section,
                    Space::with_height(6),
                    install_wizard_section,
                    Space::with_height(6),
                    bootstrap_header,
                    bootstrap_box,
                    Space::with_height(4),
                    horizontal_rule(1),
                    log_header,
                    log_box,
                    Space::with_height(4),
                ]
                .padding(16)
                .spacing(4),
            )
            .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    /// Admin client-management panel body. Only ever called from
    /// `view_main` behind the `is_connected && admin_role >= 1` (Viewer or
    /// Admin) gate — this method itself does not re-check whether the role
    /// qualifies for entry at all, since it has no meaningful "not
    /// authorized" rendering of its own (the caller simply never invokes
    /// it for a User/no-role session).
    ///
    /// G-A1: `can_mutate` (`true` only for a confirmed Admin, `false` for
    /// Viewer) gates every mutating control inside — the add-client form
    /// and each client's Edit/Enable-Disable/Reset-device/Revoke buttons.
    /// "Key"/"Show QR" stay available to both roles: both are plain GETs
    /// the server's `authorize()` already permits a Viewer
    /// (`connection-key` is a curated GET route; QR generation never goes
    /// through the mgmt API at all — it's the client daemon's own admin
    /// socket, unrelated to the server-assigned role).
    fn view_admin_section(&self, can_mutate: bool) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);

        let toggle_label = if self.admin_open {
            format!("[-] {}", t(lang, "Admin — Client Management"))
        } else {
            format!("[+] {}", t(lang, "Admin — Client Management"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleAdminPanel)
                .style(button::text),
            if !can_mutate {
                text(t(lang, "View only")).size(11).color(muted).into()
            } else {
                Element::from(Space::with_width(0))
            },
            Space::with_width(Length::Fill),
            if self.admin_open {
                button(t(lang, "Refresh"))
                    .on_press(Message::AdminRefreshClients)
                    .style(button::text)
                    .into()
            } else {
                Element::from(Space::with_width(0))
            },
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        if !self.admin_open {
            return column![header].into();
        }

        let mut body = column![].spacing(6);

        if let Some(err) = &self.admin_error {
            body = body.push(text(err).size(12).color(danger));
        }

        // G-B1: exit-node picker option list — "(default)" + every
        // `GET /api/v1/pool/nodes` address + "Custom..." — shared by the
        // add-client and per-client-edit forms below. Sourced from
        // `self.pool_nodes`, fetched on `ToggleAdminPanel`/`AdminRoleLoaded`
        // (same field the Pool Topology panel uses, loaded at most once).
        let exit_choices = exit_node_choices(lang, &self.pool_nodes);
        // Caption shared by both forms' exit-node control — per-client
        // overrides are applied by the running daemon live (no reconnect);
        // clearing back to "(default)" only takes effect for the pool's
        // *global* default on the daemon's next restart.
        let exit_node_hint = || {
            text(format!(
                "{}: {} / {}",
                t(lang, "Exit node"),
                t(lang, "applies live, no reconnect"),
                t(lang, "global default applies on restart"),
            ))
            .size(10)
            .color(muted)
        };

        // ── Add-client form (Admin only — a mutating control) ────────────
        if can_mutate {
            let adding = self.admin_busy_id.as_deref() == Some("");
            let selected = exit_node_selected(&self.admin_new_exit_node, &exit_choices);
            let add_row = row![
                text_input(t(lang, "Name"), &self.admin_new_name)
                    .on_input(Message::AdminNewNameChanged)
                    .width(Length::FillPortion(2)),
                checkbox(t(lang, "One-time"), self.admin_new_one_time)
                    .on_toggle(Message::AdminNewOneTimeToggled),
                text_input("expires (RFC3339, optional)", &self.admin_new_expires)
                    .on_input(Message::AdminNewExpiresChanged)
                    .width(Length::FillPortion(2)),
                pick_list(
                    exit_choices.clone(),
                    selected,
                    Message::AdminNewExitNodePicked,
                )
                .width(120),
                text_input(t(lang, "Exit node (optional)"), &self.admin_new_exit_node)
                    .on_input(Message::AdminNewExitNodeChanged)
                    .width(Length::FillPortion(2)),
                button(text(if adding {
                    t(lang, "Adding...")
                } else {
                    t(lang, "+ Add")
                }))
                .on_press_maybe(
                    (!adding && !self.admin_new_name.trim().is_empty())
                        .then_some(Message::AdminAddClient)
                ),
            ]
            .spacing(6)
            .align_y(Alignment::Center);
            body = body.push(add_row);
            body = body.push(exit_node_hint());
        }

        // ── Client list ──────────────────────────────────────────────────
        if self.admin_clients_loading {
            body = body.push(text(t(lang, "Loading...")).size(12).color(muted));
        } else if self.admin_clients.is_empty() {
            body = body.push(text(t(lang, "No clients")).size(12).color(muted));
        }

        for c in &self.admin_clients {
            let busy = self.admin_busy_id.as_deref() == Some(c.id.as_str());
            let title_row = row![
                text(format!("{}", c.name)).size(13),
                text(format!("[{}]", c.role_label())).size(11).color(muted),
                text(if c.enabled {
                    t(lang, "enabled")
                } else {
                    t(lang, "disabled")
                })
                .size(11)
                .color(if c.enabled { muted } else { danger }),
                if c.one_time {
                    text(t(lang, "one-time")).size(11).color(muted)
                } else {
                    text("").size(11)
                },
                if let Some(exit) = &c.exit_node {
                    text(format!("{}: {}", t(lang, "Exit"), exit))
                        .size(11)
                        .color(muted)
                } else {
                    text("").size(11)
                },
            ]
            .spacing(8)
            .align_y(Alignment::Center);

            let mut card = column![title_row].spacing(4);

            // G-A1: `pending_revoke`/`edit_id` can only ever be set via the
            // Revoke/Edit buttons in the `can_mutate` branch below, so a
            // Viewer session can never actually be sitting in either of
            // these two states — the `can_mutate &&` here is defense in
            // depth (e.g. a role downgrade landing mid-interaction), not
            // the primary gate.
            if can_mutate && self.admin_pending_revoke.as_deref() == Some(c.id.as_str()) {
                card = card.push(
                    row![
                        text(t(lang, "Confirm revoke?")).size(12).color(danger),
                        button(t(lang, "Yes"))
                            .on_press(Message::AdminRevokeConfirm(c.id.clone()))
                            .style(button::danger),
                        button(t(lang, "No"))
                            .on_press(Message::AdminRevokeCancel)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            } else if can_mutate && self.admin_edit_id.as_deref() == Some(c.id.as_str()) {
                let edit_selected = exit_node_selected(&self.admin_edit_exit_node, &exit_choices);
                card = card.push(
                    row![
                        text_input(t(lang, "Name"), &self.admin_edit_name)
                            .on_input(Message::AdminEditNameChanged)
                            .width(Length::FillPortion(2)),
                        text_input("expires (RFC3339)", &self.admin_edit_expires)
                            .on_input(Message::AdminEditExpiresChanged)
                            .width(Length::FillPortion(2)),
                        pick_list(
                            exit_choices.clone(),
                            edit_selected,
                            Message::AdminEditExitNodePicked,
                        )
                        .width(120),
                        text_input("host:port", &self.admin_edit_exit_node)
                            .on_input(Message::AdminEditExitNodeChanged)
                            .width(Length::FillPortion(2)),
                        button(t(lang, "Save"))
                            .on_press_maybe((!busy).then_some(Message::AdminEditSave)),
                        button(t(lang, "Cancel"))
                            .on_press(Message::AdminEditCancel)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
                card = card.push(exit_node_hint());
            } else if can_mutate {
                card = card.push(
                    row![
                        button(t(lang, "Key"))
                            .on_press_maybe((!busy).then_some(Message::AdminShowKey(c.id.clone()))),
                        button(t(lang, "Edit")).on_press_maybe(
                            (!busy).then_some(Message::AdminStartEdit(c.id.clone()))
                        ),
                        button(text(if c.enabled {
                            t(lang, "Disable")
                        } else {
                            t(lang, "Enable")
                        }))
                        .on_press_maybe(
                            (!busy)
                                .then_some(Message::AdminToggleEnabled(c.id.clone(), !c.enabled))
                        ),
                        button(t(lang, "Reset device")).on_press_maybe(
                            (!busy).then_some(Message::AdminResetDevice(c.id.clone()))
                        ),
                        button(t(lang, "Revoke"))
                            .on_press_maybe(
                                (!busy).then_some(Message::AdminRevokeRequest(c.id.clone()))
                            )
                            .style(button::danger),
                    ]
                    .spacing(4)
                    .align_y(Alignment::Center),
                );
            } else {
                // Viewer: only the read-only "Key" affordance (a plain GET
                // the server allows a Viewer) — every mutating control is
                // omitted entirely rather than disabled.
                card = card.push(
                    row![button(t(lang, "Key"))
                        .on_press_maybe((!busy).then_some(Message::AdminShowKey(c.id.clone())))]
                    .spacing(4)
                    .align_y(Alignment::Center),
                );
            }

            if let Some((kid, key)) = &self.admin_key_view {
                if kid == &c.id {
                    card = card.push(
                        scrollable(text(key).size(11))
                            .width(Length::Fill)
                            .height(50),
                    );
                    card = card.push(
                        row![
                            button(t(lang, "Copy")).on_press(Message::AdminCopyKey(key.clone())),
                            button(t(lang, "Save")).on_press(Message::AdminSaveKeyToFile),
                            button(t(lang, "Show QR")).on_press_maybe(
                                (self.admin_qr_loading.is_none())
                                    .then_some(Message::AdminRequestQr(c.id.clone()))
                            ),
                            button(t(lang, "Close"))
                                .on_press(Message::AdminCloseKeyView)
                                .style(button::secondary),
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center),
                    );
                    if self.admin_qr_loading.as_deref() == Some(c.id.as_str()) {
                        card = card.push(text(t(lang, "Generating QR...")).size(11).color(muted));
                    }
                    if let Some((qid, handle)) = &self.admin_qr {
                        if qid == &c.id {
                            card = card.push(
                                column![
                                    image(handle.clone()).width(180).height(180),
                                    button(t(lang, "Save QR"))
                                        .on_press(Message::AdminSaveQrToFile)
                                        .style(button::text),
                                ]
                                .spacing(4),
                            );
                        }
                    }
                }
            }

            body = body.push(container(card).padding(8).width(Length::Fill).style(
                move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgb(0.24, 0.25, 0.30)
                    } else {
                        Color::from_rgb(0.95, 0.95, 0.97)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: if is_dark {
                            Color::from_rgba(1.0, 1.0, 1.0, 0.08)
                        } else {
                            Color::from_rgba(0.0, 0.0, 0.0, 0.06)
                        },
                    },
                    ..Default::default()
                },
            ));
        }

        column![header, body].spacing(6).into()
    }

    /// Pool topology panel body (Wave B3): node list + health summary.
    /// Same gating discipline as `view_admin_section` — only ever called
    /// from `view_main` behind `is_connected && admin_role == Some(2)`.
    fn view_pool_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);
        let good = Color::from_rgb(0.20, 0.70, 0.35);

        let toggle_label = if self.pool_open {
            format!("[-] {}", t(lang, "Pool Topology"))
        } else {
            format!("[+] {}", t(lang, "Pool Topology"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::TogglePoolPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            if self.pool_open {
                button(t(lang, "Refresh"))
                    .on_press(Message::PoolRefresh)
                    .style(button::text)
                    .into()
            } else {
                Element::from(Space::with_width(0))
            },
        ]
        .align_y(Alignment::Center);

        if !self.pool_open {
            return column![header].into();
        }

        let mut body = column![].spacing(6);

        if let Some(err) = &self.pool_error {
            body = body.push(text(err).size(12).color(danger));
        }

        if let Some(h) = &self.pool_health {
            let health_row = row![
                text(format!("{}: {}", t(lang, "Transport"), h.transport)).size(12),
                text(format!(
                    "{}: {}/{}",
                    t(lang, "Connected"),
                    h.connected_peers,
                    h.total_nodes
                ))
                .size(12),
                text(format!("{}: {}", t(lang, "Converged"), h.converged_peers)).size(12),
            ]
            .spacing(12);
            body = body.push(health_row);

            if h.partition_conflict || h.subnet_mismatch {
                let mut warn = String::new();
                if h.partition_conflict {
                    warn.push_str(t(lang, "Partition conflict detected"));
                }
                if h.subnet_mismatch {
                    if !warn.is_empty() {
                        warn.push_str(" \u{b7} ");
                    }
                    warn.push_str(t(lang, "Subnet mismatch detected"));
                }
                body = body.push(text(warn).size(12).color(danger));
            } else if h.diverged {
                body = body.push(text(t(lang, "Some peers diverged")).size(12).color(muted));
            }
        }

        if self.pool_loading {
            body = body.push(text(t(lang, "Loading...")).size(12).color(muted));
        } else if self.pool_nodes.is_empty() {
            body = body.push(text(t(lang, "No pool nodes")).size(12).color(muted));
        }

        for n in &self.pool_nodes {
            let last_seen = n
                .last_seen_unix
                .map(|ts| ts.to_string())
                .unwrap_or_else(|| t(lang, "never").to_string());
            let node_row = row![
                text(n.node_id.clone())
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(n.address.clone().unwrap_or_else(|| "-".to_string()))
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(if n.verified {
                    t(lang, "verified")
                } else {
                    t(lang, "unverified")
                })
                .size(11)
                .color(if n.verified { good } else { muted }),
                text(if n.connected {
                    t(lang, "connected")
                } else {
                    t(lang, "offline")
                })
                .size(11)
                .color(if n.connected { good } else { muted }),
                if n.revoked {
                    text(t(lang, "revoked")).size(11).color(danger)
                } else {
                    text("").size(11)
                },
                text(format!("{}: {}", t(lang, "Last seen"), last_seen))
                    .size(11)
                    .color(muted),
            ]
            .spacing(8)
            .align_y(Alignment::Center);

            body = body.push(container(node_row).padding(6).width(Length::Fill).style(
                move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgb(0.24, 0.25, 0.30)
                    } else {
                        Color::from_rgb(0.95, 0.95, 0.97)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: if is_dark {
                            Color::from_rgba(1.0, 1.0, 1.0, 0.08)
                        } else {
                            Color::from_rgba(0.0, 0.0, 0.0, 0.06)
                        },
                    },
                    ..Default::default()
                },
            ));
        }

        column![header, body].spacing(6).into()
    }

    /// G-A3: "Server Settings" panel body — Admin-only apply-with-rollback
    /// for the two `HeavySetting`s `POST /api/v1/config/apply` supports
    /// (`mgmt_service.rs::HeavySetting`): a per-client active-mask override
    /// (applies live) and the pool's global default exit node (applies only
    /// after a server restart). Only ever called from `view_main` behind
    /// `is_connected && admin_role == Some(2)` — unlike
    /// `view_admin_section`/`view_pool_section`/`view_audit_section` there
    /// is no Viewer-visible read-only rendering here at all, since every
    /// control in this panel mutates server state.
    ///
    /// NOTE on scope: the original brief for this panel assumed a "global
    /// active mask" setting and a `GET /api/v1/masks` catalog endpoint
    /// reachable over the admin tunnel. Neither exists: `classify_route`
    /// (`mgmt_service.rs`) has no masks route at all (the tunnel
    /// deliberately never exposes several `management_api.rs` REST routes,
    /// masks among them), and `HeavySetting::ActiveMask` rejects an empty
    /// `client` with `400` — it is a per-client override, not a global
    /// default, verified directly against `resolve_heavy_setting`. So the
    /// mask picker below targets one client (from `self.admin_clients`,
    /// already fetched for the client-management panel) and its choices
    /// come from the local server-pushed mask catalog
    /// (`admin_mask_choices`/`mask_choices_from_catalog`) rather than a
    /// network call.
    fn view_server_settings_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);

        let toggle_label = if self.server_settings_open {
            format!("[-] {}", t(lang, "Server Settings"))
        } else {
            format!("[+] {}", t(lang, "Server Settings"))
        };
        let header = row![button(text(toggle_label))
            .on_press(Message::ToggleServerSettingsPanel)
            .style(button::text)];

        if !self.server_settings_open {
            return column![header].into();
        }

        let mut body = column![].spacing(8);

        if let Some(err) = &self.server_settings_error {
            body = body.push(text(err).size(12).color(danger));
        }
        if self.server_settings_rolled_back {
            body = body.push(
                text(t(
                    lang,
                    "Change was not confirmed in time and was rolled back",
                ))
                .size(12)
                .color(danger),
            );
        }

        // ── Pending apply / confirm banner — shared by both settings
        // below, since only one apply is tracked client-side at a time.
        if let Some((_, kind)) = &self.server_settings_pending {
            let scope_hint = match kind {
                ServerSettingsPendingKind::ActiveMask => t(lang, "applies live, no reconnect"),
                ServerSettingsPendingKind::ExitNode => t(lang, "global default applies on restart"),
            };
            body = body.push(
                container(
                    column![
                        text(format!(
                            "{} ({})",
                            t(
                                lang,
                                "Change applied - confirm within ~120s or it will be rolled back"
                            ),
                            scope_hint,
                        ))
                        .size(12),
                        row![
                            text(format!(
                                "{}: {}s",
                                t(lang, "Time left"),
                                self.server_settings_countdown
                            ))
                            .size(12)
                            .color(muted),
                            button(t(lang, "Confirm")).on_press_maybe(
                                (!self.server_settings_busy)
                                    .then_some(Message::ServerSettingsConfirm)
                            ),
                        ]
                        .spacing(10)
                        .align_y(Alignment::Center),
                    ]
                    .spacing(4),
                )
                .padding(8)
                .width(Length::Fill)
                .style(move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgba(0.85, 0.65, 0.10, 0.15)
                    } else {
                        Color::from_rgba(0.95, 0.75, 0.10, 0.20)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: Color::from_rgba(0.85, 0.65, 0.10, 0.5),
                    },
                    ..Default::default()
                }),
            );
        }

        let pending_active = self.server_settings_pending.is_some();

        // ── Active mask override (per-client, live) ─────────────────────
        body = body.push(horizontal_rule(1));
        body = body.push(text(t(lang, "Active mask override")).size(13));
        let client_choices = admin_client_choices(&self.admin_clients);
        let selected_client = self
            .server_settings_mask_client
            .as_ref()
            .and_then(|id| client_choices.iter().find(|c| &c.id == id).cloned());
        let mask_choices = admin_mask_choices(lang);
        let selected_mask = self
            .server_settings_mask_id
            .as_ref()
            .and_then(|id| mask_choices.iter().find(|m| &m.id == id).cloned());
        body = body.push(
            row![
                pick_list(
                    client_choices.clone(),
                    selected_client,
                    Message::ServerSettingsMaskClientPicked,
                )
                .placeholder(t(lang, "Select client..."))
                .width(Length::FillPortion(2)),
                pick_list(
                    mask_choices.clone(),
                    selected_mask,
                    Message::ServerSettingsMaskPicked,
                )
                .placeholder(t(lang, "Select mask..."))
                .width(Length::FillPortion(2)),
                button(t(lang, "Apply")).on_press_maybe(
                    (!self.server_settings_busy
                        && !pending_active
                        && self.server_settings_mask_client.is_some()
                        && self.server_settings_mask_id.is_some())
                    .then_some(Message::ServerSettingsApplyMask)
                ),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );
        if client_choices.is_empty() {
            body = body.push(text(t(lang, "No clients loaded yet")).size(11).color(muted));
        }
        if mask_choices.is_empty() {
            body = body.push(
                text(t(lang, "No mask catalog received yet (connect once first)"))
                    .size(11)
                    .color(muted),
            );
        }

        // ── Global exit node (pool default, restart required) ───────────
        body = body.push(horizontal_rule(1));
        body = body.push(text(t(lang, "Global exit node (pool default)")).size(13));
        let exit_choices = exit_node_choices(lang, &self.pool_nodes);
        let exit_selected = exit_node_selected(&self.server_settings_exit_node, &exit_choices);
        body = body.push(
            row![
                pick_list(
                    exit_choices.clone(),
                    exit_selected,
                    Message::ServerSettingsExitNodePicked,
                )
                .width(140),
                text_input("host:port", &self.server_settings_exit_node)
                    .on_input(Message::ServerSettingsExitNodeChanged)
                    .width(Length::FillPortion(2)),
                button(t(lang, "Apply")).on_press_maybe(
                    (!self.server_settings_busy && !pending_active)
                        .then_some(Message::ServerSettingsApplyExitNode)
                ),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );
        body = body.push(
            text(t(
                lang,
                "Takes effect only after the server process restarts",
            ))
            .size(10)
            .color(muted),
        );

        column![header, body].spacing(6).into()
    }

    /// G-A2: audit-log panel body — hash-chain-verified tail of the
    /// server's append-only admin audit log (`GET /api/v1/audit-log?verify=1`).
    /// Same gating discipline as `view_pool_section`: only ever called from
    /// `view_main` behind `is_connected && admin_role >= 1` (Viewer or
    /// Admin) — GET-only in the server's curated allowlist regardless of
    /// role, so unlike `view_admin_section` there is no `can_mutate` split
    /// here at all, nothing in this panel ever mutates anything.
    fn view_audit_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);
        let good = Color::from_rgb(0.20, 0.70, 0.35);

        let toggle_label = if self.audit_open {
            format!("[-] {}", t(lang, "Audit Log"))
        } else {
            format!("[+] {}", t(lang, "Audit Log"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleAuditPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            if self.audit_open {
                button(t(lang, "Refresh"))
                    .on_press(Message::AuditRefresh)
                    .style(button::text)
                    .into()
            } else {
                Element::from(Space::with_width(0))
            },
        ]
        .align_y(Alignment::Center);

        if !self.audit_open {
            return column![header].into();
        }

        let mut body = column![].spacing(6);

        if let Some(err) = &self.audit_error {
            body = body.push(text(err).size(12).color(danger));
        }

        if let Some(verified) = self.audit_verified {
            let chain_badge = if verified {
                text(t(lang, "chain verified")).size(12).color(good)
            } else {
                text(format!(
                    "{} ({})",
                    t(lang, "chain BROKEN"),
                    self.audit_broken_at
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "?".to_string())
                ))
                .size(12)
                .color(danger)
            };
            body = body.push(chain_badge);
        }

        if self.audit_loading {
            body = body.push(text(t(lang, "Loading...")).size(12).color(muted));
        } else if self.audit_entries.is_empty() {
            body = body.push(text(t(lang, "No audit entries")).size(12).color(muted));
        }

        // Oldest-first from the server; show newest-first so the most
        // recent action is always the first row without scrolling.
        for e in self.audit_entries.iter().rev() {
            let entry_row = row![
                text(e.ts.clone())
                    .size(11)
                    .color(muted)
                    .width(Length::FillPortion(2)),
                text(format!("[{}]", e.actor)).size(11).color(muted),
                text(e.action.clone())
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(e.target.clone())
                    .size(11)
                    .color(muted)
                    .width(Length::FillPortion(2)),
                text(e.result.clone())
                    .size(11)
                    .color(if e.result == "ok" { good } else { danger }),
            ]
            .spacing(8)
            .align_y(Alignment::Center);

            body = body.push(container(entry_row).padding(6).width(Length::Fill).style(
                move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgb(0.24, 0.25, 0.30)
                    } else {
                        Color::from_rgb(0.95, 0.95, 0.97)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: if is_dark {
                            Color::from_rgba(1.0, 1.0, 1.0, 0.08)
                        } else {
                            Color::from_rgba(0.0, 0.0, 0.0, 0.06)
                        },
                    },
                    ..Default::default()
                },
            ));
        }

        column![header, body].spacing(6).into()
    }

    /// C3: "Install server via SSH" wizard body — Target → TOFU → Installing
    /// steps, computed from state rather than an explicit step enum (each
    /// step's fields double as the "am I on this step" flags: no
    /// fingerprint yet => Target/probe step; fingerprint but not trusted =>
    /// TOFU confirm step; trusted => ready to start; running/exit_code set
    /// => streaming/result step).
    fn view_install_wizard_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);
        let ok_color = if is_dark {
            Color::from_rgb(0.40, 0.85, 0.40)
        } else {
            Color::from_rgb(0.15, 0.55, 0.15)
        };

        let toggle_label = if self.install_wizard_open {
            format!("[-] {}", t(lang, "Install Server via SSH"))
        } else {
            format!("[+] {}", t(lang, "Install Server via SSH"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleInstallWizard)
                .style(button::text),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center);

        if !self.install_wizard_open {
            return column![header].into();
        }

        let mut body = column![].spacing(8);

        if let Some(err) = &self.install_error {
            body = body.push(text(err).size(12).color(danger));
        }

        // ── Installing / result step ────────────────────────────────────
        if self.install_running || self.install_exit_code.is_some() {
            let log_items: Vec<Element<Message>> = self
                .install_log
                .iter()
                .map(|l| text(l).size(11).into())
                .collect();
            body = body.push(
                scrollable(
                    container(column(log_items).spacing(1))
                        .padding(8)
                        .width(Length::Fill),
                )
                .height(200),
            );
            if let Some(code) = self.install_exit_code {
                let status_text = if code == 0 {
                    text(t(lang, "Install finished successfully")).color(ok_color)
                } else {
                    text(format!("{} (exit {code})", t(lang, "Install failed"))).color(danger)
                };
                body = body.push(status_text);
                let mut actions = row![button(t(lang, "Start over"))
                    .on_press(Message::InstallReset)
                    .style(button::secondary)]
                .spacing(6);
                // G-C1: auto-import already ran the instant the marker with
                // `connection_key` arrived (see `import_installed_key`), so
                // this button is only ever shown as a retry when that failed
                // (`install_error` set, `install_profile_imported` still
                // `None`) — the happy path needs no manual click at all.
                if self.install_connection_key.is_some() && self.install_profile_imported.is_none()
                {
                    actions = actions.push(
                        button(t(lang, "Import profile")).on_press(Message::InstallImportProfile),
                    );
                }
                body = body.push(actions);
                if let Some(name) = &self.install_profile_imported {
                    body = body.push(
                        text(format!(
                            "{} \"{}\" — {}",
                            t(lang, "Imported profile"),
                            name,
                            t(lang, "ready to connect (admin access)")
                        ))
                        .size(12)
                        .color(ok_color),
                    );
                    if let Some(key) = &self.install_connection_key {
                        body = body.push(
                            scrollable(text(key).size(11))
                                .width(Length::Fill)
                                .height(50),
                        );
                        body = body.push(
                            row![button(t(lang, "Copy"))
                                .on_press(Message::AdminCopyKey(key.clone()))]
                            .spacing(6),
                        );
                    }
                }
            } else {
                body = body.push(text(t(lang, "Installing...")).size(12).color(muted));
            }
            return column![header, body].spacing(6).into();
        }

        // ── Target step ─────────────────────────────────────────────────
        body = body.push(
            row![
                text_input("host or IP", &self.install_host)
                    .on_input(Message::InstallHostChanged)
                    .width(Length::FillPortion(3)),
                text_input("22", &self.install_port)
                    .on_input(Message::InstallPortChanged)
                    .width(Length::FillPortion(1)),
                text_input("root", &self.install_user)
                    .on_input(Message::InstallUserChanged)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(6),
        );

        body = body.push(
            checkbox(
                t(lang, "Use SSH key instead of password"),
                self.install_auth_is_key,
            )
            .on_toggle(Message::InstallAuthModeToggled),
        );

        if self.install_auth_is_key {
            body = body.push(
                text_input(t(lang, "Private key path"), &self.install_key_file)
                    .on_input(Message::InstallKeyFileChanged),
            );
            body = body.push(
                text_input(
                    t(lang, "Key passphrase (optional)"),
                    &self.install_key_passphrase,
                )
                .secure(true)
                .on_input(Message::InstallKeyPassphraseChanged),
            );
        } else {
            body = body.push(
                text_input(t(lang, "SSH password"), &self.install_password)
                    .secure(true)
                    .on_input(Message::InstallPasswordChanged),
            );
        }

        body = body.push(text(t(lang, "Binary source")).size(12).color(muted));
        body = body.push(pick_list(
            InstallBinarySourceKind::all(),
            Some(self.install_binary_source_kind),
            Message::InstallBinarySourceChanged,
        ));
        match self.install_binary_source_kind {
            InstallBinarySourceKind::Default => {}
            InstallBinarySourceKind::Url => {
                body = body.push(
                    text_input(t(lang, "Binary URL"), &self.install_binary_url)
                        .on_input(Message::InstallBinaryUrlChanged),
                );
            }
            InstallBinarySourceKind::LocalFile => {
                body = body.push(
                    row![
                        text_input(t(lang, "Binary file path"), &self.install_binary_file)
                            .on_input(Message::InstallBinaryFileChanged)
                            .width(Length::Fill),
                        button(t(lang, "Browse..."))
                            .on_press(Message::InstallBinaryFileBrowse)
                            .style(button::secondary),
                    ]
                    .spacing(6),
                );
            }
        }

        body = body.push(
            row![
                text_input(t(lang, "Server IP (optional)"), &self.install_server_ip)
                    .on_input(Message::InstallServerIpChanged),
                text_input(t(lang, "Server port (optional)"), &self.install_server_port)
                    .on_input(Message::InstallServerPortChanged),
            ]
            .spacing(6),
        );

        body = body.push(
            row![
                checkbox("docker", self.install_mode_docker).on_toggle(Message::InstallModeToggled),
                checkbox(
                    t(lang, "Bind this device (admin access)"),
                    self.install_bind_device
                )
                .on_toggle(Message::InstallBindDeviceToggled),
            ]
            .spacing(12),
        );

        body = body.push(
            button(t(lang, "Show script"))
                .on_press(Message::InstallShowScript)
                .style(button::text),
        );

        if self.install_script_open {
            if let Some((sha, script)) = &self.install_script {
                body = body.push(text(format!("SHA256: {sha}")).size(11).color(muted));
                body = body.push(scrollable(text(script.clone()).size(10)).height(140));
            } else {
                body = body.push(text(t(lang, "Loading...")).size(11).color(muted));
            }
            body = body.push(
                button(t(lang, "Close"))
                    .on_press(Message::InstallHideScript)
                    .style(button::text),
            );
        }

        // ── TOFU step ────────────────────────────────────────────────────
        if let Some(fp) = &self.install_fingerprint {
            body = body.push(text(format!("{}: {fp}", t(lang, "Host key fingerprint"))).size(12));
            if self.install_trusted {
                let auth_ok = if self.install_auth_is_key {
                    !self.install_key_file.trim().is_empty()
                } else {
                    !self.install_password.is_empty()
                };
                let binary_ok = match self.install_binary_source_kind {
                    InstallBinarySourceKind::Default => true,
                    InstallBinarySourceKind::Url => !self.install_binary_url.trim().is_empty(),
                    InstallBinarySourceKind::LocalFile => {
                        !self.install_binary_file.trim().is_empty()
                    }
                };
                let can_start = auth_ok && binary_ok;
                body = body.push(
                    row![
                        button(t(lang, "Install"))
                            .on_press_maybe(can_start.then_some(Message::InstallStart)),
                        button(t(lang, "Don't trust"))
                            .on_press(Message::InstallDistrust)
                            .style(button::danger),
                    ]
                    .spacing(6),
                );
            } else {
                body = body.push(
                    row![
                        text(t(lang, "Confirm this is the correct server's key"))
                            .size(12)
                            .color(muted),
                        button(t(lang, "I trust this key"))
                            .on_press(Message::InstallTrustFingerprint),
                        button(t(lang, "Cancel"))
                            .on_press(Message::InstallDistrust)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            }
        } else {
            let can_probe = !self.install_probing && !self.install_host.trim().is_empty();
            body = body.push(
                button(text(if self.install_probing {
                    t(lang, "Connecting...")
                } else {
                    t(lang, "Connect & verify host key")
                }))
                .on_press_maybe(can_probe.then_some(Message::InstallProbe)),
            );
        }

        column![header, body].spacing(6).into()
    }

    fn view_dialog(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let title = match self.dialog {
            DialogMode::Add => t(lang, "Add Profile"),
            DialogMode::Edit(_) => t(lang, "Edit Profile"),
            DialogMode::None => "",
        };

        let name_input =
            text_input("Profile name", &self.dlg_name).on_input(Message::DlgNameChanged);
        let key_input =
            text_input("aivpn:// connection key", &self.dlg_key).on_input(Message::DlgKeyChanged);
        let mtls_input = text_input("mTLS cert path (optional)", &self.dlg_mtls_cert)
            .on_input(Message::DlgMtlsCertChanged);

        let error_row: Element<Message> = if let Some(e) = &self.dlg_error {
            text(e)
                .color(Color::from_rgb(0.9, 0.2, 0.1))
                .size(12)
                .into()
        } else {
            Space::with_height(0).into()
        };

        let buttons: Element<Message> = row![
            button(t(lang, "Save"))
                .on_press(Message::DlgSave)
                .style(button::primary),
            Space::with_width(8),
            button(t(lang, "Cancel")).on_press(Message::DlgCancel),
        ]
        .into();

        let dialog_content = container(
            column![
                text(title).size(16),
                Space::with_height(12),
                text(t(lang, "Name")).size(12),
                name_input,
                Space::with_height(8),
                text(t(lang, "Connection key")).size(12),
                key_input,
                Space::with_height(8),
                text(t(lang, "mTLS cert path (optional)")).size(12),
                mtls_input,
                Space::with_height(6),
                checkbox(
                    if lang == "ru" {
                        "Full tunnel (весь трафик через VPN)"
                    } else {
                        "Full tunnel (route all traffic through VPN)"
                    },
                    self.dlg_full_tunnel,
                )
                .on_toggle(Message::DlgFullTunnelToggled),
                Space::with_height(2),
                error_row,
                Space::with_height(12),
                buttons,
            ]
            .spacing(4)
            .padding(24),
        )
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style {
                background: Some(Background::Color(palette.background.strong.color)),
                border: Border {
                    radius: 8.0.into(),
                    width: 1.0,
                    color: palette.background.weak.color,
                },
                ..Default::default()
            }
        })
        .width(420);

        container(dialog_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .align_y(iced::alignment::Vertical::Center)
            .into()
    }
}
