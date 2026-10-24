//! Ограничение числа источников и частоты запросов до проверки клиента.

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

#[cfg(test)]
mod tests {
    use super::*;
    const CAPACITY: usize = 4096;
    const LIMIT: u32 = 100;
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
