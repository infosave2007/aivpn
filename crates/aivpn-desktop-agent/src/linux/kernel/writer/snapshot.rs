//! Подготовка фиксированного снимка без публикации или activation receipt.
use super::{KernelWriter, LinuxBindingRequest, SealedBindingManifest, VerifiedBindingSet};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
pub(super) mod compile;
pub(in crate::linux::kernel::writer) mod schema;
pub(in crate::linux::kernel::writer) mod storage;

/// Полностью прочитанный и frozen bundle. FD не подтверждает видимость в root.
/// Удержание bindings и retentions до снятия всех readers остается обязанностью владельца.
pub struct FrozenBindingSnapshot {
    fd: OwnedFd,
    manifest_digest: [u8; 32],
    bundle_digest: [u8; 32],
    record_count: usize,
}
impl AsFd for FrozenBindingSnapshot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl FrozenBindingSnapshot {
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    pub fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
    pub fn record_count(&self) -> usize {
        self.record_count
    }
}
impl KernelWriter {
    /// Повторно проверяет held files, exact desired и instance до создания и freeze.
    /// Не устанавливает root, не активирует backend и не выдает activation epoch.
    pub fn prepare_binding_snapshot(
        &mut self,
        request: &LinuxBindingRequest,
        set: &VerifiedBindingSet,
    ) -> io::Result<FrozenBindingSnapshot> {
        let sealed = self.checked_snapshot_source(request, set)?;
        let bundle = compile::Bundle::compile(&sealed)?;
        let fd = storage::prepare(&bundle.records)?;
        self.checked_snapshot_source(request, set)?;
        // Ни одна пользовательская операция не выполняется между проверкой и freeze.
        storage::freeze(&fd, &bundle.records)?;
        Ok(FrozenBindingSnapshot {
            fd,
            manifest_digest: bundle.manifest_digest,
            bundle_digest: bundle.bundle_digest,
            record_count: bundle.records.len(),
        })
    }
    fn checked_snapshot_source(
        &mut self,
        request: &LinuxBindingRequest,
        set: &VerifiedBindingSet,
    ) -> io::Result<SealedBindingManifest> {
        self.check_owner()?;
        if self.kernel.mode() != super::super::BindingMode::Snapshot {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let sealed = self.seal_for_publication(set, request.desired_digest())?;
        self.validate_sealed_bindings(&sealed, request)?;
        Ok(sealed)
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Некорректный снимок привязок Linux",
    )
}

pub(in crate::linux::kernel) fn verify_active_root(root: &OwnedFd) -> io::Result<()> {
    let fd = storage::active(root)?;
    let records = storage::read_records(&fd)?;
    let meta = records
        .get(&schema::key(schema::META, 0, [0; 3]))
        .ok_or_else(invalid)?;
    let identity = records
        .get(&schema::key(schema::IDENTITY, 0, [0; 3]))
        .ok_or_else(invalid)?;
    if u32::from_ne_bytes(meta[..4].try_into().unwrap()) != 2
        || u64::from_ne_bytes(meta[8..16].try_into().unwrap()) == 0
        || identity[..32] == [0; 32]
    {
        return Err(invalid());
    }
    Ok(())
}
