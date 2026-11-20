pub const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum StateFile {
    Committed,
    Pending,
    DnsJournal,
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::StateDirectory;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub(crate) use windows::image::TrustedImage;
#[cfg(all(target_os = "windows", feature = "windows-kernel"))]
pub(crate) use windows::retirement::{RemovalEvidence, StateRetirement};
#[cfg(target_os = "windows")]
pub use windows::StateDirectory;
