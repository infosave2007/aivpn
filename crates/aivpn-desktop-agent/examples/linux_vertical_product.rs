//! Изолированная сборка настоящего Control, backend и координатора.
#[cfg(target_os = "linux")]
#[path = "linux_vertical_product/support.rs"]
mod support;
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    support::run(|_, _| Ok(()))
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
