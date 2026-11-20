use crate::{
    maintenance::DecommissionProof,
    state::{StateDirectory, StateFile},
};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    namespace: [u8; 16],
    serial: u64,
    state: [u8; 32],
    complete: bool,
}

/// Запускается SCM от LocalSystem после остановки службы и восстановления DNS.
pub fn remove_owned_routing(
    proof: &DecommissionProof<'_>,
    mut store: StateDirectory,
) -> io::Result<()> {
    super::security::service_authority()?;
    proof.confirm()?;
    if store.load(StateFile::Pending)?.is_some() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let mut receipt = match store.load(StateFile::Committed)? {
        Some(bytes) => serde_json::from_slice::<Receipt>(&bytes)?,
        None => {
            let receipt = Receipt {
                version: 1,
                namespace: proof.namespace(),
                serial: proof.serial(),
                state: proof.digest(),
                complete: false,
            };
            let bytes = serde_json::to_vec(&receipt)?;
            store.replace(StateFile::Committed, &bytes)?;
            confirm(&store, &bytes)?;
            receipt
        }
    };
    if receipt.version != 1
        || receipt.namespace != proof.namespace()
        || receipt.serial != proof.serial()
        || receipt.state != proof.digest()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    super::filters::remove_owned(proof, receipt.complete)?;
    proof.confirm()?;
    receipt.complete = true;
    let bytes = serde_json::to_vec(&receipt)?;
    store.replace(StateFile::Committed, &bytes)?;
    confirm(&store, &bytes)
}

fn confirm(store: &StateDirectory, bytes: &[u8]) -> io::Result<()> {
    if store.load(StateFile::Committed)?.as_deref() != Some(bytes) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    Ok(())
}

/// Соседний журнал позволяет продолжить удаление после исчезновения control/state.json.
pub fn purge_owned_routing(requested: &std::path::Path) -> io::Result<()> {
    use crate::state::StateRetirement;
    super::security::service_authority()?;
    let name = requested
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .ok_or(io::ErrorKind::InvalidInput)?;
    let parent = requested.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let mut journal = StateDirectory::open(&parent.join(format!("{name}Removal")))?;
    let mut plan = match StateRetirement::load(&journal, requested)? {
        Some(plan) => plan,
        None => {
            let evidence: crate::state::RemovalEvidence = {
                let root = StateDirectory::open(requested)?;
                let namespace: [u8; 16] = root
                    .load(StateFile::Committed)?
                    .ok_or(io::ErrorKind::NotFound)?
                    .try_into()
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                let control = root.child(c"control")?;
                let proof =
                    DecommissionProof::open(crate::policy::Platform::Windows, namespace, &control)?;
                remove_owned_routing(&proof, root.child(c"retirement")?)?;
                root.removal_evidence(&proof)?
            };
            StateRetirement::capture(requested, evidence, &mut journal)?
        }
    };
    plan.apply(requested, &mut journal)
}
