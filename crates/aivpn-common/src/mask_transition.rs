//! Подтверждение конкретного поколения маски внутри защищенной сессии.

use crate::protocol::ControlPayload;

pub const FEATURE: u32 = 1 << 29;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskReceipt {
    pub generation: u64,
    pub digest: [u8; 32],
}

impl MaskReceipt {
    pub fn for_payload(generation: u64, payload: &[u8]) -> Self {
        Self {
            generation,
            digest: *blake3::hash(payload).as_bytes(),
        }
    }

    pub fn control(self) -> ControlPayload {
        ControlPayload::MaskApplied {
            generation: self.generation,
            digest: self.digest,
        }
    }
}

/// Один принятый профиль и один повторяемый receipt, без очереди поколений.
#[derive(Debug, Default)]
pub struct MaskReceiver {
    current: Option<MaskReceipt>,
    waiting: bool,
}

impl MaskReceiver {
    pub fn accepts(&self, proposed: MaskReceipt) -> bool {
        proposed.generation != 0
            && self
                .current
                .is_none_or(|current| proposed.generation > current.generation)
    }

    /// Вызывать только после проверки подписи, артефакта и установки профиля.
    pub fn applied(&mut self, receipt: MaskReceipt) {
        self.current = Some(receipt);
        self.waiting = true;
    }

    pub fn duplicate(&self, proposed: MaskReceipt) -> bool {
        self.current == Some(proposed)
    }

    pub fn pending(&self) -> Option<MaskReceipt> {
        self.current.filter(|_| self.waiting)
    }

    pub fn confirm(&mut self, receipt: MaskReceipt) {
        if self.current == Some(receipt) {
            self.waiting = false;
        }
    }

    pub fn current(&self) -> Option<MaskReceipt> {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_ack_duplicate_and_reordered_generation_do_not_reapply_profile() {
        let mut receiver = MaskReceiver::default();
        let first = MaskReceipt::for_payload(1, b"first");
        let second = MaskReceipt::for_payload(2, b"second");
        assert!(!receiver.accepts(MaskReceipt::for_payload(0, b"bad")));
        assert!(receiver.accepts(first));
        receiver.applied(first);
        for _ in 0..10 {
            assert_eq!(receiver.pending(), Some(first));
            assert!(!receiver.accepts(first));
            assert!(receiver.duplicate(first));
        }
        receiver.confirm(MaskReceipt::for_payload(1, b"different"));
        assert_eq!(receiver.pending(), Some(first));
        receiver.confirm(first);
        assert_eq!(receiver.pending(), None);
        assert!(receiver.duplicate(first));
        assert!(receiver.accepts(second));
        receiver.applied(second);
        receiver.confirm(first);
        assert_eq!(receiver.pending(), Some(second));
        assert!(!receiver.accepts(first));
        receiver.confirm(second);
        assert_eq!(receiver.pending(), None);
    }
}
