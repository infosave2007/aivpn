use crate::platform_win::find_own_aivpn_hwnd;

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
            if let Err(error) = self.settings.save() {
                self.show_error(error);
            }
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.connect_requested.swap(false, Relaxed) {
            self.window_visible = true;
            self.do_connect();
        }

        self.update_tray();

        self.sync_appearance(ctx);
        self.handle_shortcuts(ctx);
        self.draw_shell(ctx);
        let lang = self.settings.lang;

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

        self.draw_profile_dialog(ctx);
        self.draw_delete_dialog(ctx);

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
            if let Err(error) = self.settings.save() {
                crate::vpn_manager::gui_log(&error);
            }
        }
    }
}
