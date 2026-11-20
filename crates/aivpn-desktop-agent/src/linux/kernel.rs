//! Программы ядра для привилегированной службы маршрутизации.
//!
//! Возможность сборки не подтверждает поддержку работающим ядром. Служба должна
//! проверить загрузку, установку защиты и принадлежащие ей сетевые ресурсы.

// Статическая libbpf не требует отдельного runtime-пакета у обычного клиента.
use libbpf_sys as _;

mod image;
pub use image::{KernelImage, LoadedKernel};
mod hooks;
pub use hooks::UnpublishedKernel;
mod pins;
pub use pins::PinnedKernel;
mod objects;
mod recovery;
pub use recovery::RecoveredKernel;
mod installation;
pub use installation::{CorePhaseProof, FinalAttachmentReceipt, InitializingKernel};
mod writer;
pub use writer::{
    BindingRecovery, BindingTxnId, FileGroupId, LinuxBindingRequest, SealedBindingManifest,
    SelectorId, VerifiedAlias, VerifiedBindingSet, VerifiedGroup, VerifiedMembership,
};
pub(crate) use writer::{CacheSweep, ProfilePath, PROFILE_MARK_MASK};
pub use writer::{FrozenBindingSnapshot, KernelWriter, PinnedRetention, PreparedExecutable};
mod capabilities;
pub(crate) mod retirement;

/// Служба уже остановлена, DNS восстановлен, durable состояние запрещает новые политики.
pub fn remove_owned_routing(
    proof: &crate::maintenance::DecommissionProof<'_>,
    runtime: crate::state::StateDirectory,
) -> std::io::Result<()> {
    retirement::remove(proof, runtime)
}

/// Встроенный объект CO-RE. Обычным клиентам и мобильным сборкам clang не нужен.
pub fn embedded_programs() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/routing.bpf.o"))
}

fn invalid_object() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Объекты ядра не соответствуют службе маршрутизации",
    )
}

/// Режим выбирается до load/hooks и не меняется у живого экземпляра.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingMode {
    Legacy,
    Snapshot,
}
impl BindingMode {
    fn image(self) -> &'static [u8] {
        match self {
            Self::Legacy => embedded_programs(),
            Self::Snapshot => embedded_snapshot_programs(),
        }
    }
    fn code(self) -> u32 {
        match self {
            Self::Legacy => 0,
            Self::Snapshot => 1,
        }
    }
}
/// Образ подготовки snapshot. Наличие образа не подтверждает активацию политик.
pub fn embedded_snapshot_programs() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/routing-snapshot.bpf.o"))
}
