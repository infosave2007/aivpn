fn main() -> std::process::ExitCode {
    aivpn_client::entry::dispatch(aivpn_client::entry::DefaultMode::Cli)
        .unwrap_or(std::process::ExitCode::FAILURE)
}
