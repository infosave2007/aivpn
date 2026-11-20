//! Измерение соответствия модели отдельно от качества доставки пакетов.

use crate::{
    error::{Error, Result},
    mask::MaskProfile,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const FEATURE: u32 = 1 << 28;
pub const MAX_AGE: Duration = Duration::from_secs(30);

pub fn identity(mask: &MaskProfile) -> [u8; 32] {
    let mut normalized = mask.clone();
    normalized.signature = [0; 64];
    *blake3::hash(&rmp_serde::to_vec(&normalized).expect("Сериализация профиля маски")).as_bytes()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskAssessment {
    pub generation: u64,
    pub mask_digest: [u8; 32],
    pub model_id: [u8; 32],
    /// 0 - резервная проекция; 1 - обученная модель.
    pub model_kind: u8,
    /// 1 - uplink после снятия внешней транспортной оболочки.
    pub direction: u8,
    pub window: u64,
    pub samples: u16,
    pub span_ms: u32,
    pub age_ms: u32,
    pub mse: f32,
    pub warning: f32,
    pub compromised: f32,
}

impl MaskAssessment {
    pub fn validate(&self) -> Result<()> {
        if self.model_kind > 1
            || self.direction != 1
            || !(32..=256).contains(&self.samples)
            || self.window < u64::from(self.samples)
            || self.span_ms == 0
            || self.age_ms >= MAX_AGE.as_millis() as u32
            || !self.mse.is_finite()
            || self.mse < 0.0
            || !self.warning.is_finite()
            || self.warning <= 0.0
            || !self.compromised.is_finite()
            || self.compromised <= self.warning
        {
            return Err(Error::InvalidPacket("Недостоверное измерение модели маски"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = vec![crate::protocol::ControlSubtype::MaskAssessment as u8];
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.mask_digest);
        out.extend_from_slice(&self.model_id);
        out.extend_from_slice(&[self.model_kind, self.direction]);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.extend_from_slice(&self.samples.to_le_bytes());
        for value in [
            self.span_ms,
            self.age_ms,
            self.mse.to_bits(),
            self.warning.to_bits(),
            self.compromised.to_bits(),
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 105 || bytes[0] != crate::protocol::ControlSubtype::MaskAssessment as u8 {
            return Err(Error::InvalidPacket("Неверная длина измерения модели"));
        }
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let value = Self {
            generation: u64::from_le_bytes(bytes[1..9].try_into().unwrap()),
            mask_digest: bytes[9..41].try_into().unwrap(),
            model_id: bytes[41..73].try_into().unwrap(),
            model_kind: bytes[73],
            direction: bytes[74],
            window: u64::from_le_bytes(bytes[75..83].try_into().unwrap()),
            samples: u16::from_le_bytes(bytes[83..85].try_into().unwrap()),
            span_ms: u32_at(85),
            age_ms: u32_at(89),
            mse: f32::from_bits(u32_at(93)),
            warning: f32::from_bits(u32_at(97)),
            compromised: f32::from_bits(u32_at(101)),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssessmentTracker {
    value: Option<(MaskAssessment, Instant)>,
}

impl AssessmentTracker {
    pub fn reset(&mut self) {
        self.value = None;
    }

    pub fn record(
        &mut self,
        value: MaskAssessment,
        mask: [u8; 32],
        generation: u64,
        now: Instant,
    ) -> bool {
        if value.validate().is_err()
            || value.mask_digest != mask
            || value.generation != generation
            || self
                .value
                .as_ref()
                .is_some_and(|(previous, _)| previous.window >= value.window)
        {
            return false;
        }
        let remaining = MAX_AGE - Duration::from_millis(u64::from(value.age_ms));
        self.value = Some((value, now + remaining));
        true
    }

    pub fn current(&self, now: Instant) -> Option<&MaskAssessment> {
        self.value
            .as_ref()
            .filter(|(_, expires)| now < *expires)
            .map(|(value, _)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assessment_unknown_stale_reordered_and_wrong_mask_are_not_good_scores() {
        let mut tracker = AssessmentTracker::default();
        let now = Instant::now();
        assert!(tracker.current(now).is_none());
        let value = MaskAssessment {
            generation: 1,
            mask_digest: [2; 32],
            model_id: [3; 32],
            model_kind: 1,
            direction: 1,
            window: 256,
            samples: 128,
            span_ms: 1200,
            age_ms: 200,
            mse: 0.2,
            warning: 0.3,
            compromised: 0.4,
        };
        assert_eq!(
            MaskAssessment::decode(&value.encode().unwrap()).unwrap(),
            value
        );
        assert!(!tracker.record(value.clone(), [9; 32], 1, now));
        assert!(!tracker.record(value.clone(), [2; 32], 2, now));
        assert!(tracker.record(value.clone(), [2; 32], 1, now));
        assert!(!tracker.record(value.clone(), [2; 32], 1, now));
        assert!(tracker.current(now + MAX_AGE).is_none());
        assert!(!tracker.record(value.clone(), [2; 32], 1, now + MAX_AGE));
        tracker.reset();
        let mut malformed = value;
        malformed.mse = f32::NAN;
        assert!(malformed.encode().is_err());
        assert!(tracker.current(now).is_none());
    }
}
