//! Сквозная проверка прежнего DNS через Control и настоящий VPN-сеанс в guest.
#[cfg(target_os = "linux")]
#[path = "../../aivpn-desktop-agent/examples/linux_vertical_product/support.rs"]
mod support;
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    let mut relay = None;
    support::run(|coordinator, event| {
        if relay.is_none() {
            relay = Some(aivpn_client::service_dns::LinuxDnsRelay::bind_for_system(
                "198.18.0.53:53".parse().unwrap(),
                coordinator,
            )?);
        }
        relay.as_mut().unwrap().progress(coordinator, event)
    })
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
