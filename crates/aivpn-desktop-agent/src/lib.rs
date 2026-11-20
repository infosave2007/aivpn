//! Локальный канал между desktop-клиентами и привилегированной службой маршрутизации.

// Политика ограничена 128 КиБ, управление допускает 512 КиБ с base64 и JSON оберткой.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_DESCRIPTORS: usize = 2;

pub mod administration;
#[cfg(all(feature = "cli", any(target_os = "linux", target_os = "windows")))]
pub mod app_control;
pub mod protocol;
pub use aivpn_desktop_policy as policy;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod client;
pub mod connection;

#[cfg(target_os = "linux")]
pub mod unix;

pub mod state;

pub mod bindings;
pub mod control;
#[cfg(any(
    all(target_os = "linux", feature = "linux-kernel"),
    target_os = "windows"
))]
pub mod dns;
#[cfg(any(
    all(target_os = "linux", feature = "linux-kernel"),
    target_os = "windows"
))]
pub mod maintenance;
pub mod slots;
pub mod worker_protocol;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Ограниченный журнал уже открытого файла работника.
pub mod worker_log;
