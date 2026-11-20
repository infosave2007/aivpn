//! Ограниченный SYSTEM harness настоящего Control и отдельного packet worker.
#[cfg(target_os = "windows")]
#[path = "windows_vertical_service/main.rs"]
mod windows;
fn main() {
    #[cfg(target_os = "windows")]
    if let Err(error) = windows::run() {
        eprintln!("Ошибка vertical path: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "windows"))]
    std::process::exit(1);
}
