//! Журнал и crash recovery многофайлового restore.
//!
//! Политика: до фазы `prepared` recovery возвращает старое поколение.
//! С `prepared` включительно recovery ставит новое поколение.
//! Смешанный набор dest сервер не читает: gate на lock и sidecar
//! завершает или откатывает операцию до разбора config/DB/masks.
//!
//! Staging и backup лежат рядом с каждым dest, поэтому rename dest
//! не пересекает ФС. Общая атомарность набора через разные ФС не
//! обещается: согласованность дает журнал и идемпотентный recovery.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::ImportOptions;
use aivpn_common::error::{Error, Result};

const JOURNAL_VERSION: u32 = 1;
const MAX_RECOVERY_FILE: u64 = 64 * 1024 * 1024;
const JOURNAL_SUFFIX: &str = ".aivpn-restore.journal";
const LOCK_SUFFIX: &str = ".aivpn-restore.lock";
const STAGING_MARK: &str = ".aivpn-restore-staging-";
const BACKUP_MARK: &str = ".aivpn-restore-bak-";
const MASK_JOURNAL_NAME: &str = ".aivpn-restore.journal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    Preparing,
    Prepared,
    Committing,
    Committed,
    Cleaning,
}

impl RestorePhase {
    fn rank(self) -> u8 {
        match self {
            Self::Preparing => 0,
            Self::Prepared => 1,
            Self::Committing => 2,
            Self::Committed => 3,
            Self::Cleaning => 4,
        }
    }

    fn completes(self) -> bool {
        self.rank() >= RestorePhase::Prepared.rank()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestoreJournal {
    version: u32,
    op_id: String,
    phase: RestorePhase,
    config_path: String,
    clients_db: String,
    mask_dir: String,
    files: Vec<RestoreFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestoreFile {
    role: String,
    dest: String,
    staging: String,
    backup: Option<String>,
    new_hash: String,
    old_hash: Option<String>,
    created: bool,
}

#[derive(Clone)]
struct Fault {
    step: String,
    kill: bool,
}

thread_local! {
    static THREAD_FAULT: RefCell<Option<Fault>> = RefCell::new(None);
}

/// Точка отказа для тестов. `kill` поднимает SIGKILL без Drop.
pub fn with_restore_fault<T>(step: &str, kill: bool, f: impl FnOnce() -> T) -> T {
    THREAD_FAULT.with(|slot| {
        *slot.borrow_mut() = Some(Fault {
            step: step.to_string(),
            kill,
        });
    });
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            THREAD_FAULT.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    f()
}

fn current_fault() -> Option<Fault> {
    THREAD_FAULT
        .with(|slot| slot.borrow().clone())
        .or_else(env_fault)
}

fn interrupt(step: &str) -> Result<()> {
    let fault = current_fault();
    let Some(fault) = fault else {
        return Ok(());
    };
    if fault.step != step {
        return Ok(());
    }
    if fault.kill {
        crash_now(step);
    }
    Err(Error::Session(format!(
        "восстановление прервано точкой {step}"
    )))
}

fn crash_only(step: &str) {
    if current_fault().is_some_and(|fault| fault.kill && fault.step == step) {
        crash_now(step);
    }
}

fn crash_now(step: &str) {
    let _ = step;
    #[cfg(unix)]
    unsafe {
        libc::raise(libc::SIGKILL);
    }
}

fn env_fault() -> Option<Fault> {
    if !cfg!(debug_assertions) {
        return None;
    }
    if let Ok(step) = std::env::var("AIVPN_RESTORE_CRASH") {
        if !step.is_empty() {
            return Some(Fault { step, kill: true });
        }
    }
    if let Ok(step) = std::env::var("AIVPN_RESTORE_FAIL") {
        if !step.is_empty() {
            return Some(Fault { step, kill: false });
        }
    }
    None
}

pub(crate) fn config_journal_path(config_path: &Path) -> PathBuf {
    sidecar(config_path, JOURNAL_SUFFIX)
}

pub(crate) fn clients_journal_path(clients_db: &Path) -> PathBuf {
    sidecar(clients_db, JOURNAL_SUFFIX)
}

pub(crate) fn has_clients_journal(clients_db: &Path) -> Result<bool> {
    Ok(read_journal(&clients_journal_path(clients_db))?.is_some())
}

/// Recovery до чтения server.json. Журнал рядом с config, dest внутри него.
///
/// Lock-файл config не удаляется: flock привязан к inode, unlink отпускает
/// ожидающий процесс на уже стертом файле и пускает второй захват.
pub fn recover_config_sidecar(config_path: &Path) -> Result<()> {
    let journal_path = config_journal_path(config_path);
    let Some(peeked) = read_journal(&journal_path)? else {
        return Ok(());
    };
    if Path::new(&peeked.config_path) != abs(config_path) {
        return Err(Error::Session(
            "журнал восстановления не принадлежит этому config".into(),
        ));
    }
    let opts = ImportOptions {
        config_path: PathBuf::from(&peeked.config_path),
        clients_db: PathBuf::from(&peeked.clients_db),
        mask_dir: PathBuf::from(&peeked.mask_dir),
    };
    // Порядок: exclusive DB, затем config, затем mask. Повторный flock
    // тех же файлов в этом потоке не берется.
    let _clients = crate::client_db::OfflineRestoreGuard::try_acquire(Path::new(&opts.clients_db))?;
    let _locks = exclusive_component_locks(&opts)?;
    let Some(current) = read_journal(&journal_path)? else {
        return Ok(());
    };
    if current.op_id != peeked.op_id
        || current.clients_db != peeked.clients_db
        || current.mask_dir != peeked.mask_dir
    {
        return Err(Error::Session(
            "журнал восстановления сменился до захвата блокировок".into(),
        ));
    }
    recover_locked(&opts)
}

/// Recovery при уже известном наборе dest.
/// Сам берет config и mask lock. Вызывающий, который уже держит DB lock,
/// не должен держать эти же component lock.
pub fn recover_pending_restore(opts: &ImportOptions) -> Result<()> {
    let _locks = exclusive_component_locks(opts)?;
    recover_locked(opts)
}

pub(crate) fn recover_clients_sidecar(clients_db: &Path) -> Result<()> {
    let journal_path = clients_journal_path(clients_db);
    let Some(journal) = read_journal(&journal_path)? else {
        return Ok(());
    };
    if Path::new(&journal.clients_db) != abs(clients_db) {
        return Err(Error::Session(
            "журнал восстановления не принадлежит этой базе".into(),
        ));
    }
    let opts = ImportOptions {
        config_path: PathBuf::from(&journal.config_path),
        clients_db: PathBuf::from(&journal.clients_db),
        mask_dir: PathBuf::from(&journal.mask_dir),
    };
    // DB exclusive уже у вызывающего. Дальше только config, затем mask.
    let _locks = exclusive_component_locks(&opts)?;
    let Some(current) = read_journal(&journal_path)? else {
        return Ok(());
    };
    if current.op_id != journal.op_id {
        return Err(Error::Session(
            "журнал восстановления сменился до захвата блокировок".into(),
        ));
    }
    recover_locked(&opts)
}

pub(super) fn install_restored_files(
    opts: &ImportOptions,
    staged: &[(String, Vec<u8>)],
) -> Result<()> {
    if staged.is_empty() {
        return Ok(());
    }
    // DB exclusive уже взят import. Component lock держим непрерывно
    // от recovery чужого журнала до commit, иначе второй DB успеет
    // прочитать или заменить общий журнал config/mask.
    let locks = exclusive_component_locks(opts)?;
    recover_locked(opts)?;
    let mut txn = RestoreTxn::begin(opts, staged, locks)?;
    match txn.prepare_and_commit() {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = txn.rollback_if_unprepared();
            Err(error)
        }
    }
}

fn recover_locked(opts: &ImportOptions) -> Result<()> {
    let Some(journal) = load_best_journal(&[
        config_journal_path(&opts.config_path),
        clients_journal_path(&opts.clients_db),
        opts.mask_dir.join(MASK_JOURNAL_NAME),
    ])?
    else {
        return Ok(());
    };
    if Path::new(&journal.config_path) != abs(&opts.config_path)
        || Path::new(&journal.clients_db) != abs(&opts.clients_db)
        || Path::new(&journal.mask_dir) != abs(&opts.mask_dir)
    {
        return Err(Error::Session(
            "незавершенное восстановление относится к другому набору файлов".into(),
        ));
    }
    apply_journal(&journal)
}

fn load_best_journal(paths: &[PathBuf]) -> Result<Option<RestoreJournal>> {
    let mut best: Option<RestoreJournal> = None;
    for path in paths {
        if path.as_os_str().is_empty() {
            continue;
        }
        match read_journal(path) {
            Ok(None) => {}
            Ok(Some(journal)) => {
                if let Some(current) = &best {
                    if current.op_id == journal.op_id && journal.phase.rank() > current.phase.rank()
                    {
                        best = Some(journal);
                    } else if current.op_id != journal.op_id {
                        return Err(Error::Session(
                            "журналы восстановления относятся к разным операциям".into(),
                        ));
                    }
                } else {
                    best = Some(journal);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(best)
}

fn apply_journal(journal: &RestoreJournal) -> Result<()> {
    validate_journal(journal)?;
    interrupt("recover")?;
    if journal.phase == RestorePhase::Cleaning {
        cleanup_artifacts(journal)?;
    } else if journal.phase.completes() {
        complete_journal(journal)?;
    } else {
        rollback_journal(journal)?;
    }
    Ok(())
}

fn validate_journal(journal: &RestoreJournal) -> Result<()> {
    if journal.version != JOURNAL_VERSION {
        return Err(Error::Session(format!(
            "журнал восстановления версии {} не поддерживается",
            journal.version
        )));
    }
    if journal.op_id.is_empty() || !journal.op_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Session(
            "журнал восстановления содержит некорректный идентификатор".into(),
        ));
    }
    let config = Path::new(&journal.config_path);
    let clients = Path::new(&journal.clients_db);
    let masks = Path::new(&journal.mask_dir);
    if journal.files.is_empty() {
        return Err(Error::Session(
            "журнал восстановления не содержит файлов".into(),
        ));
    }
    let prepared = journal.phase.completes();
    for file in &journal.files {
        let dest = Path::new(&file.dest);
        refuse_forbidden_dest(dest)?;
        match file.role.as_str() {
            "config" => {
                if dest != config {
                    return Err(Error::Session(
                        "журнал восстановления подменил путь config".into(),
                    ));
                }
            }
            "clients" => {
                if dest != clients || dest.extension().and_then(|e| e.to_str()) != Some("json") {
                    return Err(Error::Session(
                        "журнал восстановления подменил путь clients".into(),
                    ));
                }
            }
            "mask" => {
                let name = dest.file_name().map(|n| n.to_string_lossy());
                if dest.parent() != Some(masks)
                    || dest.extension().and_then(|e| e.to_str()) != Some("json")
                    || name
                        .as_deref()
                        .is_some_and(|name| name.contains('/') || name.contains('\\'))
                {
                    return Err(Error::Session(
                        "журнал восстановления подменил путь маски".into(),
                    ));
                }
            }
            other => {
                return Err(Error::Session(format!(
                    "журнал восстановления содержит неизвестную роль {other}"
                )));
            }
        }
        let staging = Path::new(&file.staging);
        if !is_own_sibling(dest, staging, STAGING_MARK, &journal.op_id) {
            return Err(Error::Session(
                "журнал восстановления указывает чужой staging".into(),
            ));
        }
        if let Some(backup) = &file.backup {
            if !is_own_sibling(dest, Path::new(backup), BACKUP_MARK, &journal.op_id) {
                return Err(Error::Session(
                    "журнал восстановления указывает чужой backup".into(),
                ));
            }
        } else if prepared && !file.created {
            return Err(Error::Session(
                "журнал восстановления без backup для существующего dest".into(),
            ));
        }
    }
    Ok(())
}

fn refuse_forbidden_dest(dest: &Path) -> Result<()> {
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name == "server.key" || name == "backup_integrity.key" {
        return Err(Error::Session(
            "журнал восстановления не может менять ключ сервера".into(),
        ));
    }
    if dest
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Session(
            "журнал восстановления содержит относительный выход из каталога".into(),
        ));
    }
    Ok(())
}

fn is_own_sibling(dest: &Path, candidate: &Path, mark: &str, op_id: &str) -> bool {
    if candidate.parent() != dest.parent() {
        return false;
    }
    let Some(dest_name) = dest.file_name() else {
        return false;
    };
    let Some(name) = candidate.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let expected = format!(".{}{mark}{op_id}", dest_name.to_string_lossy());
    name == expected
}

fn complete_journal(journal: &RestoreJournal) -> Result<()> {
    interrupt("recover-complete")?;
    for (index, file) in journal.files.iter().enumerate() {
        install_one(file)?;
        interrupt(&format!("recover-commit-{index}"))?;
    }
    verify_new_generation(journal)?;
    let mut committed = journal.clone();
    committed.phase = RestorePhase::Committed;
    write_journal_copies(&committed)?;
    crash_only("committed");
    finish_cleanup(&committed)
}

fn write_journal_copies(journal: &RestoreJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|e| Error::Session(format!("журнал восстановления: {e}")))?;
    write_journal_atomically(
        &config_journal_path(Path::new(&journal.config_path)),
        &bytes,
    )?;
    if journal.phase == RestorePhase::Prepared {
        interrupt("journal-prepared-config")?;
    }
    write_journal_atomically(
        &clients_journal_path(Path::new(&journal.clients_db)),
        &bytes,
    )?;
    let mask_dir = Path::new(&journal.mask_dir);
    if journal.files.iter().any(|file| file.role == "mask") || mask_dir.is_dir() {
        if journal.files.iter().any(|file| file.role == "mask") {
            std::fs::create_dir_all(mask_dir).map_err(|e| map_io(e, "mkdir mask_dir"))?;
        }
        write_journal_atomically(&mask_dir.join(MASK_JOURNAL_NAME), &bytes)?;
    }
    Ok(())
}

fn rollback_journal(journal: &RestoreJournal) -> Result<()> {
    interrupt("recover-rollback")?;
    for file in &journal.files {
        revert_one(file, journal.phase.completes())?;
    }
    verify_old_generation(journal)?;
    finish_cleanup(journal)
}

fn install_one(file: &RestoreFile) -> Result<()> {
    let dest = Path::new(&file.dest);
    if hash_if_regular(dest)?.as_deref() == Some(file.new_hash.as_str()) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let existing = open_nofollow_read(dest).map_err(|e| map_io(e, "открытие dest"))?;
            existing
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| map_io(e, "chmod dest"))?;
            existing.sync_all().map_err(|e| map_io(e, "fsync dest"))?;
        }
        let _ = remove_if_exists(Path::new(&file.staging));
        return Ok(());
    }
    let staging = Path::new(&file.staging);
    match hash_if_regular(staging)? {
        Some(hash) if hash == file.new_hash => {}
        Some(_) => {
            return Err(Error::Session(format!(
                "staging {} поврежден, восстановление не продолжается",
                staging.display()
            )));
        }
        None => {
            return Err(Error::Session(format!(
                "нет staging для {}, смешанный набор не принимается",
                dest.display()
            )));
        }
    }
    refuse_symlink(dest)?;
    std::fs::rename(staging, dest).map_err(|e| map_io(e, "установка restored файла"))?;
    fsync_parent(dest).map_err(|e| map_io(e, "fsync каталога dest"))?;
    Ok(())
}

fn revert_one(file: &RestoreFile, prepared: bool) -> Result<()> {
    let dest = Path::new(&file.dest);
    let dest_hash = hash_if_regular(dest)?;
    if dest_hash
        .as_deref()
        .is_some_and(|hash| Some(hash) == file.old_hash.as_deref())
    {
        return Ok(());
    }
    if dest_hash.as_deref() == Some(file.new_hash.as_str()) {
        if file.created {
            let _ = remove_if_exists(dest);
        } else if let Some(backup) = &file.backup {
            restore_backup(dest, Path::new(backup), file.old_hash.as_deref())?;
        } else if prepared {
            return Err(Error::Session(format!(
                "нет backup для отката {}",
                dest.display()
            )));
        }
    }
    Ok(())
}

fn restore_backup(dest: &Path, backup: &Path, old_hash: Option<&str>) -> Result<()> {
    match hash_if_regular(backup)? {
        Some(hash) if Some(hash.as_str()) == old_hash => {}
        _ => {
            return Err(Error::Session(format!(
                "backup {} поврежден, откат невозможен",
                backup.display()
            )));
        }
    }
    refuse_symlink(dest)?;
    std::fs::rename(backup, dest).map_err(|e| map_io(e, "откат dest"))?;
    fsync_parent(dest).map_err(|e| map_io(e, "fsync каталога после отката"))
}

fn verify_new_generation(journal: &RestoreJournal) -> Result<()> {
    for file in &journal.files {
        match hash_if_regular(Path::new(&file.dest))? {
            Some(hash) if hash == file.new_hash => {}
            _ => {
                return Err(Error::Session(format!(
                    "dest {} не совпал с новым поколением",
                    file.dest
                )));
            }
        }
    }
    Ok(())
}

fn verify_old_generation(journal: &RestoreJournal) -> Result<()> {
    for file in &journal.files {
        let dest = Path::new(&file.dest);
        if file.old_hash.is_none() {
            if file.created && hash_if_regular(dest)?.as_deref() == Some(file.new_hash.as_str()) {
                return Err(Error::Session(format!(
                    "после отката остался созданный {}",
                    dest.display()
                )));
            }
            continue;
        }
        if file.created {
            if dest.exists() {
                return Err(Error::Session(format!(
                    "после отката остался созданный {}",
                    dest.display()
                )));
            }
            continue;
        }
        match hash_if_regular(dest)? {
            Some(hash) if Some(hash.as_str()) == file.old_hash.as_deref() => {}
            _ => {
                return Err(Error::Session(format!(
                    "dest {} не совпал со старым поколением",
                    dest.display()
                )));
            }
        }
    }
    Ok(())
}

fn finish_cleanup(journal: &RestoreJournal) -> Result<()> {
    // После проверки выбранного поколения recovery только удаляет служебные
    // файлы. Оно больше не сверяет и не переписывает рабочие данные.
    let mut cleaning = journal.clone();
    cleaning.phase = RestorePhase::Cleaning;
    write_journal_copies(&cleaning)?;
    cleanup_artifacts(&cleaning)
}

fn cleanup_artifacts(journal: &RestoreJournal) -> Result<()> {
    for (index, file) in journal.files.iter().enumerate() {
        remove_if_exists(Path::new(&file.staging))?;
        if let Some(backup) = &file.backup {
            remove_if_exists(Path::new(backup))?;
        }
        fsync_parent(Path::new(&file.dest)).map_err(|e| map_io(e, "fsync очистки файлов"))?;
        interrupt(&format!("cleanup-file-{index}"))?;
    }
    for (index, path) in [
        config_journal_path(Path::new(&journal.config_path)),
        clients_journal_path(Path::new(&journal.clients_db)),
        Path::new(&journal.mask_dir).join(MASK_JOURNAL_NAME),
    ]
    .into_iter()
    .enumerate()
    {
        if path.parent().is_some_and(Path::exists) {
            remove_if_exists(&path)?;
            fsync_parent(&path).map_err(|e| map_io(e, "fsync удаления журнала"))?;
            interrupt(&format!("cleanup-journal-{index}"))?;
        }
    }
    Ok(())
}

struct RestoreTxn {
    journal: RestoreJournal,
    contents: Vec<Vec<u8>>,
    prepared: bool,
    _locks: ComponentLocks,
}

impl RestoreTxn {
    fn begin(
        opts: &ImportOptions,
        staged: &[(String, Vec<u8>)],
        locks: ComponentLocks,
    ) -> Result<Self> {
        // locks уже держат config и mask. plan_files читает dest только здесь.
        let op_id = new_op_id();
        let planned = plan_files(opts, staged, &op_id)?;
        let contents = planned.iter().map(|p| p.bytes.clone()).collect();
        let mut files = Vec::with_capacity(planned.len());
        for p in planned {
            files.push(RestoreFile {
                role: p.role,
                dest: path_str(&p.dest)?,
                staging: path_str(&p.staging)?,
                backup: match p.backup.as_ref() {
                    Some(path) => Some(path_str(path)?),
                    None => None,
                },
                new_hash: p.new_hash,
                old_hash: p.old_hash,
                created: p.created,
            });
        }
        let journal = RestoreJournal {
            version: JOURNAL_VERSION,
            op_id,
            phase: RestorePhase::Preparing,
            config_path: path_str(&abs(&opts.config_path))?,
            clients_db: path_str(&abs(&opts.clients_db))?,
            mask_dir: path_str(&abs(&opts.mask_dir))?,
            files,
        };
        validate_journal(&journal)?;
        interrupt("lock")?;
        Ok(Self {
            journal,
            contents,
            prepared: false,
            _locks: locks,
        })
    }

    fn prepare_and_commit(&mut self) -> Result<()> {
        self.write_journals()?;
        interrupt("journal-preparing")?;
        for i in 0..self.journal.files.len() {
            self.write_backup(i)?;
            interrupt(&format!("backup-{i}"))?;
            self.write_staging(i)?;
            interrupt(&format!("stage-{i}"))?;
        }
        self.journal.phase = RestorePhase::Prepared;
        // Даже первая копия prepared запрещает удалять staging при ошибке.
        self.prepared = true;
        self.write_journals()?;
        interrupt("prepared")?;
        self.journal.phase = RestorePhase::Committing;
        self.write_journals()?;
        interrupt("committing")?;
        for i in 0..self.journal.files.len() {
            install_one(&self.journal.files[i])?;
            interrupt(&format!("commit-{i}"))?;
        }
        verify_new_generation(&self.journal)?;
        self.journal.phase = RestorePhase::Committed;
        self.write_journals()?;
        // Ошибка очистки оставляет отдельную возобновляемую фазу.
        crash_only("committed");
        finish_cleanup(&self.journal)
    }

    fn rollback_if_unprepared(&mut self) -> Result<()> {
        if self.prepared {
            return Ok(());
        }
        rollback_journal(&self.journal)
    }

    fn write_journals(&self) -> Result<()> {
        write_journal_copies(&self.journal)
    }

    fn write_backup(&mut self, index: usize) -> Result<()> {
        let file = &mut self.journal.files[index];
        let dest = Path::new(&file.dest);
        match inspect_regular(dest)? {
            None => {
                file.created = true;
                file.backup = None;
                file.old_hash = None;
            }
            Some(_) => {
                let bytes = read_regular(dest)?;
                let hash = blake3::hash(&bytes).to_hex().to_string();
                let backup = sibling(dest, BACKUP_MARK, &self.journal.op_id);
                write_private(&backup, &bytes)?;
                file.created = false;
                file.old_hash = Some(hash);
                file.backup = Some(path_str(&backup)?);
            }
        }
        Ok(())
    }

    fn write_staging(&self, index: usize) -> Result<()> {
        let file = &self.journal.files[index];
        let dest = Path::new(&file.dest);
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| map_io(e, "mkdir dest"))?;
            }
        }
        let staging = Path::new(&file.staging);
        write_private(staging, &self.contents[index])?;
        let actual = blake3::hash(&self.contents[index]).to_hex().to_string();
        if actual != file.new_hash {
            return Err(Error::Session(
                "хеш staging не совпал с подготовленным содержимым".into(),
            ));
        }
        Ok(())
    }
}

struct PlannedFile {
    role: String,
    dest: PathBuf,
    staging: PathBuf,
    backup: Option<PathBuf>,
    new_hash: String,
    old_hash: Option<String>,
    created: bool,
    bytes: Vec<u8>,
}

fn plan_files(
    opts: &ImportOptions,
    staged: &[(String, Vec<u8>)],
    op_id: &str,
) -> Result<Vec<PlannedFile>> {
    let mut ordered = Vec::new();
    let mut masks = Vec::new();
    for (rel, bytes) in staged {
        if !super::is_allowed_import_path(Path::new(rel)) {
            return Err(Error::Session("недопустимый файл восстановления".into()));
        }
        match rel.as_str() {
            "server.json" => ordered.push(("config", abs(&opts.config_path), bytes.clone())),
            "clients.json" => ordered.push(("clients", abs(&opts.clients_db), bytes.clone())),
            other => {
                if let Some(name) = other.strip_prefix("masks/") {
                    if Path::new(name).components().count() != 1 {
                        return Err(Error::Session(format!(
                            "некорректный путь маски в архиве: {other}"
                        )));
                    }
                    masks.push((name.to_string(), bytes.clone()));
                }
            }
        }
    }
    masks.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, bytes) in masks {
        ordered.push(("mask", abs(&opts.mask_dir.join(name)), bytes));
    }
    let mut files = Vec::with_capacity(ordered.len());
    let mut destinations = std::collections::HashSet::new();
    for (role, dest, bytes) in ordered {
        if !destinations.insert(dest.clone()) {
            return Err(Error::Session(
                "файлы восстановления указывают в один путь".into(),
            ));
        }
        refuse_forbidden_dest(&dest)?;
        refuse_symlink(&dest)?;
        let created = inspect_regular(&dest)?.is_none();
        files.push(PlannedFile {
            role: role.to_string(),
            staging: sibling(&dest, STAGING_MARK, op_id),
            backup: if created {
                None
            } else {
                Some(sibling(&dest, BACKUP_MARK, op_id))
            },
            new_hash: blake3::hash(&bytes).to_hex().to_string(),
            old_hash: hash_if_regular(&dest)?,
            created,
            dest,
            bytes,
        });
    }
    Ok(files)
}

fn new_op_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

fn sibling(dest: &Path, mark: &str, op_id: &str) -> PathBuf {
    let name = dest
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("file"));
    let mut out = std::ffi::OsString::from(".");
    out.push(name);
    out.push(mark);
    out.push(op_id);
    parent_dir(dest).join(out)
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn abs(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn path_str(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| Error::Session("путь восстановления должен быть UTF-8".into()))
}

fn inspect_regular(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::Session(format!(
            "отказ читать symlink {}",
            path.display()
        ))),
        Ok(meta) if meta.file_type().is_file() => Ok(Some(meta)),
        Ok(_) => Err(Error::Session(format!(
            "{} должен быть обычным файлом",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(map_io(e, "stat dest")),
    }
}

fn refuse_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io(e, "lstat")),
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::Session(format!(
            "отказ следовать symlink {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
    }
}

fn hash_if_regular(path: &Path) -> Result<Option<String>> {
    match inspect_regular(path)? {
        None => Ok(None),
        Some(_) => Ok(Some(
            blake3::hash(&read_regular(path)?).to_hex().to_string(),
        )),
    }
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let file = open_nofollow_read(path).map_err(|e| map_io(e, "чтение dest"))?;
    let meta = file
        .metadata()
        .map_err(|e| map_io(e, "stat открытого dest"))?;
    if !meta.is_file() || meta.len() > MAX_RECOVERY_FILE {
        return Err(Error::Session(
            "файл восстановления имеет недопустимый тип или размер".into(),
        ));
    }
    let mut buf = Vec::new();
    file.take(MAX_RECOVERY_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| map_io(e, "чтение dest"))?;
    if buf.len() as u64 > MAX_RECOVERY_FILE {
        return Err(Error::Session(
            "файл восстановления превысил предел размера".into(),
        ));
    }
    Ok(buf)
}

fn read_journal(path: &Path) -> Result<Option<RestoreJournal>> {
    match inspect_regular(path)? {
        None => Ok(None),
        Some(_) => {
            let bytes = read_regular(path)?;
            let journal: RestoreJournal = serde_json::from_slice(&bytes).map_err(|_| {
                Error::Session(format!(
                    "журнал восстановления поврежден: {}",
                    path.display()
                ))
            })?;
            Ok(Some(journal))
        }
    }
}

fn write_journal_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| map_io(e, "mkdir journal"))?;
        }
    }
    let tmp = path.with_extension("journal.tmp");
    write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        map_io(e, "rename journal")
    })?;
    fsync_parent(path).map_err(|e| map_io(e, "fsync каталога journal"))?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    refuse_symlink(path)?;
    let _ = std::fs::remove_file(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .map_err(|e| map_io(e, "create private"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| map_io(e, "chmod 0600"))?;
    }
    file.write_all(bytes)
        .map_err(|e| map_io(e, "запись файла"))?;
    file.sync_all().map_err(|e| map_io(e, "fsync файла"))?;
    fsync_parent(path).map_err(|e| map_io(e, "fsync каталога"))?;
    Ok(())
}

fn open_nofollow_read(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

fn fsync_parent(path: &Path) -> std::io::Result<()> {
    File::open(parent_dir(path))?.sync_all()
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io(e, "удаление sidecar")),
    }
}

fn map_io(err: std::io::Error, what: &str) -> Error {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ENOSPC) {
        return Error::Session(format!(
            "восстановление прервано: нет места на диске ({what})"
        ));
    }
    if err.kind() == std::io::ErrorKind::StorageFull {
        return Error::Session(format!(
            "восстановление прервано: нет места на диске ({what})"
        ));
    }
    Error::Session(format!("восстановление прервано: {what}: {err}"))
}

struct RestoreLock {
    file: File,
}

impl RestoreLock {
    /// `create_parent` только у exclusive restore: reader не создает каталоги
    /// на чужом пути. Родителя-symlink не открываем.
    fn acquire(path: &Path, exclusive: bool, create_parent: bool) -> Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                match std::fs::symlink_metadata(parent) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if !create_parent {
                            return Ok(None);
                        }
                        std::fs::create_dir_all(parent)
                            .map_err(|e| map_io(e, "mkdir restore lock"))?;
                    }
                    Err(error) => return Err(map_io(error, "lstat restore lock")),
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(Error::Session(format!(
                            "отказ следовать symlink {}",
                            parent.display()
                        )));
                    }
                    Ok(_) => {}
                }
            }
        }
        refuse_symlink(path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            // На read-only ФС восстановление тоже не может заменить файлы.
            // Ошибки прав доступа сюда не относятся: существующая блокировка
            // другого владельца остается обязательной.
            Err(error) if !exclusive && error.raw_os_error() == Some(libc::EROFS) => {
                return Ok(None);
            }
            Err(error) => return Err(map_io(error, "open restore lock")),
        };
        if !file
            .metadata()
            .map_err(|e| map_io(e, "stat restore lock"))?
            .is_file()
        {
            return Err(Error::Session(
                "блокировка восстановления должна быть обычным файлом".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(map_io(
                    std::io::Error::last_os_error(),
                    "chmod restore lock",
                ));
            }
            let operation = if exclusive {
                libc::LOCK_EX | libc::LOCK_NB
            } else {
                libc::LOCK_SH
            };
            if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
                return Err(map_io(
                    std::io::Error::last_os_error(),
                    "flock restore lock",
                ));
            }
        }
        Ok(Some(Self { file }))
    }
}

impl Drop for RestoreLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Общие для нескольких DB компоненты: config, затем каталог масок.
/// Вызывающий уже держит live-lock своей DB либо еще не брал его.
/// Этот тип сам DB lock не берет и не удаляет lock-файл.
struct ComponentLocks {
    _locks: Vec<RestoreLock>,
}

fn exclusive_component_locks(opts: &ImportOptions) -> Result<ComponentLocks> {
    refuse_symlink(&opts.mask_dir)?;
    Ok(ComponentLocks {
        _locks: acquire_component_locks(Some(&opts.config_path), Some(&opts.mask_dir), true)?,
    })
}

fn acquire_component_locks(
    config: Option<&Path>,
    mask_dir: Option<&Path>,
    exclusive: bool,
) -> Result<Vec<RestoreLock>> {
    let mut locks = Vec::new();
    for path in component_lock_paths(config, mask_dir) {
        if let Some(lock) = RestoreLock::acquire(&path, exclusive, exclusive)? {
            locks.push(lock);
        }
    }
    Ok(locks)
}

fn component_lock_paths(config: Option<&Path>, mask_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(config) = config {
        // /proc/PID/fd/N и другие алиасы чтения используют блокировку
        // исходного файла, а не невозможный соседний путь в procfs.
        let target = std::fs::canonicalize(config).unwrap_or_else(|_| abs(config));
        paths.push(sidecar(&target, LOCK_SUFFIX));
    }
    if let Some(mask_dir) = mask_dir {
        let target = std::fs::canonicalize(mask_dir).unwrap_or_else(|_| abs(mask_dir));
        let path = sidecar(&target, LOCK_SUFFIX);
        if !paths.iter().any(|have| have == &path) {
            paths.push(path);
        }
    }
    paths
}

/// Shared flock config и mask на время одного снимка.
/// Снимается сразу после чтения: долгий shared не пускает restore.
pub struct SharedRestoreLock {
    _locks: Vec<RestoreLock>,
    config: Option<PathBuf>,
    mask_dir: Option<PathBuf>,
}

pub fn lock_shared_restore(
    config: Option<&Path>,
    mask_dir: Option<&Path>,
) -> Result<SharedRestoreLock> {
    Ok(SharedRestoreLock {
        _locks: acquire_component_locks(config, mask_dir, false)?,
        config: config.map(abs),
        mask_dir: mask_dir.map(abs),
    })
}

impl SharedRestoreLock {
    /// Ошибка чтения журнала не маскируется под «журнала нет».
    pub fn journal_pending(&self) -> Result<bool> {
        if let Some(config) = &self.config {
            if read_journal(&config_journal_path(config))?.is_some() {
                return Ok(true);
            }
        }
        if let Some(mask_dir) = &self.mask_dir {
            if read_journal(&mask_dir.join(MASK_JOURNAL_NAME))?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
