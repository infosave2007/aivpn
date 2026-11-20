//! Кеш DNS на время UDP ASSOCIATE. Запросы всегда идут через туннель.
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const CAPACITY: usize = 256;
const MAX_AGE: Duration = Duration::from_secs(60);
type Key = (String, u16);

#[derive(Default)]
pub(super) struct UdpDnsCache(HashMap<Key, (SocketAddr, Instant)>);
impl UdpDnsCache {
    pub fn get(&mut self, key: &Key, now: Instant) -> Option<SocketAddr> {
        let &(address, expires) = self.0.get(key)?;
        if expires <= now {
            self.0.remove(key);
            return None;
        }
        Some(address)
    }
    pub fn insert(&mut self, key: Key, value: SocketAddr, now: Instant) {
        self.0.retain(|_, (_, expires)| *expires > now);
        if self.0.len() >= CAPACITY && !self.0.contains_key(&key) {
            if let Some(oldest) = self
                .0
                .iter()
                .min_by_key(|(_, (_, expires))| *expires)
                .map(|(key, _)| key.clone())
            {
                self.0.remove(&oldest);
            }
        }
        self.0.insert(key, (value, now + MAX_AGE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_answers_expire_even_when_frequently_used() {
        let mut cache = UdpDnsCache::default();
        let now = Instant::now();
        let key = ("example.test".to_string(), 443);
        let address = "192.0.2.1:443".parse().unwrap();
        cache.insert(key.clone(), address, now);
        assert_eq!(cache.get(&key, now + MAX_AGE / 2), Some(address));
        assert_eq!(cache.get(&key, now + MAX_AGE), None);
    }
    #[test]
    fn unique_destinations_evict_oldest_answer() {
        let mut cache = UdpDnsCache::default();
        let now = Instant::now();
        let address = "192.0.2.1:443".parse().unwrap();
        for index in 0..=CAPACITY {
            cache.insert(
                (format!("{index}.example.test"), 443),
                address,
                now + Duration::from_millis(index as u64),
            );
        }
        assert_eq!(
            cache.get(
                &("0.example.test".to_string(), 443),
                now + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(
            cache.get(
                &(format!("{CAPACITY}.example.test"), 443),
                now + Duration::from_secs(1)
            ),
            Some(address)
        );
    }
}
