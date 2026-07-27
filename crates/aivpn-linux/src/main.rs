mod admin;
mod app;
mod install_wizard;
mod key_storage;
mod settings;
mod tray;
mod vpn_manager;

use app::App;
use iced::{Settings, Size};

fn main() -> iced::Result {
    // Single-instance guard: a second GUI (e.g. relaunched after a crash
    // while the first is still alive) would spawn a second aivpn-client over
    // the same TUN/routes. The lock is held for the whole process lifetime.
    let _instance_lock = match app::acquire_single_instance_lock() {
        Ok(guard) => guard,
        Err(()) => {
            eprintln!("aivpn-linux: another instance is already running; exiting");
            return Ok(());
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aivpn_linux=debug".parse().unwrap()),
        )
        .init();

    iced::application("AIVPN", App::update, App::view)
        .subscription(App::subscription)
        .theme(App::theme)
        .window(iced::window::Settings {
            size: Size::new(480.0, 420.0),
            min_size: Some(Size::new(480.0, 420.0)),
            ..Default::default()
        })
        .settings(Settings {
            antialiasing: true,
            ..Default::default()
        })
        .run_with(App::new)
}
