//! Ограниченные счетчики частоты для отдельных классов UDP-трафика.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct SourceRates {
    entries: HashMap<IpAddr, (u64, Instant)>,
    last_sweep: Option<Instant>,
}

impl SourceRates {
    pub(crate) fn allow(&mut self, ip: IpAddr, now: Instant, capacity: usize, limit: u64) -> bool {
        if self.entries.len() >= capacity && !self.entries.contains_key(&ip) {
            if self
                .last_sweep
                .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(1))
            {
                self.entries.retain(|_, (_, since)| {
                    now.saturating_duration_since(*since) < Duration::from_secs(1)
                });
                self.last_sweep = Some(now);
            }
            if self.entries.len() >= capacity {
                return false;
            }
        }
        let (count, since) = self.entries.entry(ip).or_insert((0, now));
        if now.saturating_duration_since(*since) >= Duration::from_secs(1) {
            *count = 0;
            *since = now;
        }
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    }
}

#[derive(Default)]
pub(crate) struct UdpIngressRates {
    untrusted: SourceRates,
    authenticated: SourceRates,
}

impl UdpIngressRates {
    pub(crate) fn allow(
        &mut self,
        ip: IpAddr,
        now: Instant,
        capacity: usize,
        limits: [u64; 2],
        authenticated: bool,
    ) -> bool {
        let (rates, limit) = if authenticated {
            (&mut self.authenticated, limits[1])
        } else {
            (&mut self.untrusted, limits[0])
        };
        rates.allow(ip, now, capacity, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CAPACITY: usize = 4096;
    const LIMIT: u32 = 100;

    #[test]
    fn authenticated_ingress_has_an_independent_finite_ceiling() {
        let mut rates = UdpIngressRates::default();
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        for _ in 0..5000 {
            assert!(rates.allow(ip, now, 16, [5000, 100_000], false));
        }
        assert!(!rates.allow(ip, now, 16, [5000, 100_000], false));
        for _ in 0..100_000 {
            assert!(rates.allow(ip, now, 16, [5000, 100_000], true));
        }
        assert!(!rates.allow(ip, now, 16, [5000, 100_000], true));
        assert!(!rates.allow(ip, now, 16, [5000, 100_000], false));
        assert!(rates.allow(ip, now + Duration::from_secs(1), 16, [5000, 100_000], true));
    }

    #[test]
    fn ingress_maps_are_separately_bounded_and_flood_cannot_reset_either_quota() {
        let mut rates = UdpIngressRates::default();
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        for authenticated in [false, true] {
            assert!(rates.allow(ip, now, 4, [1, 2], authenticated));
            if authenticated {
                assert!(rates.allow(ip, now, 4, [1, 2], true));
            }
            assert!(!rates.allow(ip, now, 4, [1, 2], authenticated));
            for address in 2..=4 {
                assert!(rates.allow(
                    std::net::Ipv4Addr::from(address).into(),
                    now,
                    4,
                    [1, 2],
                    authenticated
                ));
            }
            for address in 5..1000 {
                assert!(!rates.allow(
                    std::net::Ipv4Addr::from(address).into(),
                    now,
                    4,
                    [1, 2],
                    authenticated
                ));
            }
        }
        assert_eq!(rates.untrusted.entries.len(), 4);
        assert_eq!(rates.authenticated.entries.len(), 4);
        for authenticated in [false, true] {
            assert!(!rates.allow(ip, now, 4, [1, 2], authenticated));
            assert!(rates.allow(ip, now + Duration::from_secs(1), 4, [1, 2], authenticated));
        }
    }
    #[test]
    fn source_flood_is_bounded_without_resetting_an_existing_rate_limit() {
        fn allow(rates: &mut SourceRates, ip: IpAddr, now: Instant) -> bool {
            rates.allow(ip, now, CAPACITY, LIMIT.into())
        }
        let mut rates = SourceRates::default();
        let now = Instant::now();
        let first = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..LIMIT {
            assert!(allow(&mut rates, first, now));
        }
        assert!(!allow(&mut rates, first, now));
        for value in 2..=CAPACITY as u32 {
            assert!(allow(
                &mut rates,
                std::net::Ipv4Addr::from(value).into(),
                now
            ));
        }
        assert_eq!(rates.entries.len(), CAPACITY);
        for value in 0..1000 {
            assert!(!allow(
                &mut rates,
                std::net::Ipv4Addr::from(100_000 + value).into(),
                now
            ));
        }
        assert!(!allow(&mut rates, first, now));
        assert!(allow(&mut rates, first, now + Duration::from_secs(1)));
        assert!(allow(
            &mut rates,
            "192.0.2.1".parse().unwrap(),
            now + Duration::from_secs(1)
        ));
        assert!(rates.entries.len() < CAPACITY);
    }
}
