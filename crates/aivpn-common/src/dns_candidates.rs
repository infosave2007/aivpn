//! Выбор адреса сервера между повторными попытками подключения.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

const MAX_HOSTS: usize = 64;

struct Previous {
    endpoint: String,
    address: SocketAddr,
    confirmed: bool,
}

#[derive(Default)]
struct Candidates(VecDeque<Previous>);

impl Candidates {
    fn select(&mut self, endpoint: &str, addresses: &[SocketAddr]) -> Option<SocketAddr> {
        let first = *addresses.first()?;
        let endpoint = endpoint.to_ascii_lowercase();
        let previous = self
            .0
            .iter()
            .position(|item| item.endpoint == endpoint)
            .and_then(|index| self.0.remove(index));
        let address = match previous {
            Some(previous) => match addresses.iter().position(|item| *item == previous.address) {
                Some(index) if previous.confirmed => addresses[index],
                Some(index) => addresses[(index + 1) % addresses.len()],
                None => first,
            },
            None if self.0.len() >= MAX_HOSTS => {
                // При большом числе узлов вытеснение не должно каждый раз
                // возвращать попытку на тот же первый недоступный адрес.
                addresses[rand::random::<usize>() % addresses.len()]
            }
            None => first,
        };
        if self.0.len() == MAX_HOSTS {
            self.0.pop_front();
        }
        self.0.push_back(Previous {
            endpoint,
            address,
            confirmed: false,
        });
        Some(address)
    }

    fn confirm(&mut self, endpoint: &str, address: SocketAddr) {
        if let Some(previous) = self
            .0
            .iter_mut()
            .find(|item| item.endpoint.eq_ignore_ascii_case(endpoint) && item.address == address)
        {
            previous.confirmed = true;
        }
    }
}

fn candidates() -> &'static Mutex<Candidates> {
    static CANDIDATES: OnceLock<Mutex<Candidates>> = OnceLock::new();
    CANDIDATES.get_or_init(|| Mutex::new(Candidates::default()))
}

/// Следующий адрес после неудачной попытки, подтвержденный адрес после успешной.
pub fn select(
    endpoint: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    let mut unique = Vec::new();
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    candidates()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .select(endpoint, &unique)
}

/// Запоминает успех только после проверки ServerHello и установки ключей PFS.
pub fn confirm(endpoint: &str, address: SocketAddr) {
    candidates()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .confirm(endpoint, address);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_dns_answer_can_replace_the_confirmed_address() {
        let addresses = [
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];
        let mut state = Candidates::default();
        assert_eq!(state.select("vpn:443", &addresses), Some(addresses[0]));
        state.confirm("vpn:443", addresses[0]);
        assert_eq!(state.select("vpn:443", &addresses[1..]), Some(addresses[1]));
        state.confirm("vpn:443", addresses[1]);
        assert_eq!(state.select("vpn:443", &addresses), Some(addresses[1]));
        assert_eq!(state.select("vpn:443", &addresses), Some(addresses[0]));
    }

    #[test]
    fn failures_rotate_addresses_and_success_is_retried_before_fallback() {
        let addresses = [
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
        ];
        let mut state = Candidates::default();
        assert_eq!(
            state.select("vpn.example:443", &addresses),
            Some(addresses[0])
        );
        assert_eq!(
            state.select("vpn.example:443", &addresses),
            Some(addresses[1])
        );
        state.confirm("VPN.EXAMPLE:443", addresses[1]);
        assert_eq!(
            state.select("vpn.example:443", &addresses),
            Some(addresses[1])
        );
        assert_eq!(
            state.select("vpn.example:443", &addresses),
            Some(addresses[0])
        );
        // Поздний ответ от другой параллельной попытки не подтверждает текущую.
        state.confirm("vpn.example:443", addresses[1]);
        assert_eq!(
            state.select("vpn.example:443", &addresses),
            Some(addresses[1])
        );
    }

    #[test]
    fn hosts_are_independent_dns_changes_are_used_and_history_is_bounded() {
        let addresses = [
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];
        let mut state = Candidates::default();
        assert_eq!(state.select("a:443", &addresses), Some(addresses[0]));
        assert_eq!(state.select("b:443", &addresses), Some(addresses[0]));
        assert_eq!(state.select("a:443", &addresses), Some(addresses[1]));
        assert!(state.select("a:443", &[]).is_none());
        let changed = [
            "192.0.2.3:443".parse().unwrap(),
            "192.0.2.4:443".parse().unwrap(),
        ];
        assert_eq!(state.select("a:443", &changed), Some(changed[0]));
        for index in 0..MAX_HOSTS * 2 {
            state.select(&format!("server{index}:443"), &addresses);
        }
        assert_eq!(state.0.len(), MAX_HOSTS);
    }
}
