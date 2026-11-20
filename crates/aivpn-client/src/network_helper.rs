//! Встроенные сетевые операции с фиксированными режимами и ограниченным вводом.
mod batch;
mod owned;
mod session;

pub fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> std::process::ExitCode {
    let arguments: Vec<_> = arguments.into_iter().collect();
    if arguments == [std::ffi::OsString::from("--tun-session")] {
        return match session::serve() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Сетевой помощник: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    eprintln!("Сетевой помощник принимает только --tun-session");
    std::process::ExitCode::from(64)
}

pub(crate) fn clear_owned_routes() -> std::io::Result<()> {
    owned::clear_stale()
}

pub(crate) fn acquire_firewall(uid: Option<u32>) -> std::io::Result<std::fs::File> {
    session::acquire_firewall(uid)
}
