//! Ограниченная выборка внешних кадров после проверки транспортного AEAD.

use std::collections::VecDeque;

const LIMIT: usize = 64;
const STRIDE: u64 = 16;

#[derive(Default)]
pub(crate) struct VerifiedWire {
    enabled: bool,
    counter: u64,
    packets: VecDeque<Vec<u8>>,
}

impl VerifiedWire {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn enable(&mut self) {
        self.enabled = true;
        self.counter = 0;
        self.packets.clear();
    }

    pub fn record(&mut self, packet: &[u8]) {
        if !self.enabled || packet.is_empty() || packet.len() > 1380 {
            return;
        }
        let sample = self.counter.is_multiple_of(STRIDE);
        self.counter = self.counter.wrapping_add(1);
        if sample {
            if self.packets.len() == LIMIT {
                self.packets.pop_front();
            }
            self.packets.push_back(packet.to_vec());
        }
    }

    pub fn take(&mut self) -> Vec<Vec<u8>> {
        self.packets.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_is_explicit_sampled_bounded_and_drained() {
        let mut observation = VerifiedWire::default();
        observation.record(&[1]);
        assert!(observation.take().is_empty());
        observation.enable();
        for index in 0..(LIMIT + 3) * STRIDE as usize {
            observation.record(&(index as u64).to_le_bytes());
        }
        let packets = observation.take();
        assert_eq!(packets.len(), LIMIT);
        assert_eq!(packets[0], (3 * STRIDE).to_le_bytes());
        assert!(observation.take().is_empty());
    }
}
