//! Сохраняемая пассивная ссылка на inode. Карты привязок здесь не публикуются.
use super::{KernelWriter, PreparedExecutable};
use crate::bindings::BindingPlan;
use crate::linux::kernel::objects::open_pin;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

mod group;
mod mappings;
mod native;
mod record;
mod storage;
pub(in crate::linux::kernel::writer) use group::boot_digest;
pub(in crate::linux::kernel::writer) use group::{GroupEvidence, GroupRetention};
use record::{id, Record};

/// Закрытие FD и Drop сохраняют pins. Старый inode не дает доверия файлу,
/// который позже появился под тем же именем. Готовность backend не подтверждается.
pub struct PinnedRetention {
    record: Record,
    link: OwnedFd,
    instance: OwnedFd,
    metadata: OwnedFd,
}

impl PinnedRetention {
    pub fn link_id(&self) -> u32 {
        self.record.link()
    }
    pub fn application_slot(&self) -> u32 {
        self.record.application()
    }

    fn open(writer: &KernelWriter, base: &File, name: &std::ffi::CStr) -> io::Result<Self> {
        let directory = storage::open_record(base, name)?;
        let metadata = open_pin(&directory, c"record")?;
        let record = Record::read(&metadata)?;
        if name != storage::completed_name(record.link()).as_c_str() {
            return Err(invalid());
        }
        let retention = Self {
            record,
            link: open_pin(&directory, c"link")?,
            instance: open_pin(&directory, c"instance")?,
            metadata,
        };
        retention.verify(writer)?;
        Ok(retention)
    }
    fn verify(&self, writer: &KernelWriter) -> io::Result<()> {
        self.record.verify(writer, &self.instance)?;
        native::inspect(
            &self.link,
            self.record.program(),
            self.record.link(),
            self.record.pid(),
            false,
        )?;
        Ok(())
    }
}

impl PinnedRetention {
    fn new(
        writer: &KernelWriter,
        prepared: &PreparedExecutable,
        link: OwnedFd,
        ids: [u32; 3],
    ) -> io::Result<Self> {
        let file = File::from(prepared.file.executable.as_fd().try_clone_to_owned()?);
        let record = Record::new(
            writer,
            ids,
            prepared.application.get(),
            prepared.file.executable.filesystem_device(),
            file.metadata()?.ino(),
        )?;
        let metadata = native::record(&record.0)?;
        let instance = prepared.file.instance.as_fd().try_clone_to_owned()?;
        Ok(Self {
            record,
            link,
            instance,
            metadata,
        })
    }
    fn pin(&self, base: &File) -> io::Result<()> {
        let mut creation = storage::Creation::new(base, self.link_id())?;
        creation.pin(c"instance", &self.instance)?;
        creation.pin(c"record", &self.metadata)?;
        creation.pin(c"link", &self.link)?;
        creation.commit(self.link_id())
    }
    fn own_directory(
        &self,
        writer: &KernelWriter,
        base: &File,
        name: &std::ffi::CStr,
    ) -> io::Result<File> {
        let current = Self::open(writer, base, name)?;
        if current.record != self.record || id(&current.metadata)? != id(&self.metadata)? {
            return Err(invalid());
        }
        storage::open_record(base, name)
    }
    fn remove_pins(&self, directory: &File) -> io::Result<()> {
        storage::remove(directory, c"link", id(&self.link)?)?;
        storage::remove(directory, c"record", id(&self.metadata)?)?;
        storage::remove(directory, c"instance", id(&self.instance)?)
    }
}

impl KernelWriter {
    /// Удерживает проверенный inode после смерти службы, не меняя его привязки.
    ///
    /// # Safety
    /// Вызывающий сериализует mmap/exec во всем процессе с этой операцией.
    /// Пока исходный процесс жив, ни один его поток не должен отображать этот
    /// inode, включая dlopen и exec. Текущие mappings проверяются до и после attach;
    /// будущие mappings этот primitive запретить не может. Запуск приложения
    /// требует отдельного доверенного child с новым mm и отдельной интеграции.
    pub unsafe fn retain_executable(
        &mut self,
        plan: &BindingPlan,
        prepared: &PreparedExecutable,
    ) -> io::Result<PinnedRetention> {
        self.check_legacy_retention()?;
        prepared.verify(self, plan)?;
        let base = self.retention_base()?;
        let (link, ids) = self.attach_retention(prepared)?;
        prepared.verify(self, plan)?;
        mappings::exclude(&prepared.file.executable)?;
        let retained = PinnedRetention::new(self, prepared, link, ids)?;
        retained.pin(&base)?;
        Ok(retained)
    }

    fn check_legacy_retention(&self) -> io::Result<()> {
        self.check_owner()?;
        if self.slots.grouped_mode() {
            return Err(io::Error::other(
                "Нужно удержание через проверенную группу inode",
            ));
        }
        Ok(())
    }

    fn retention_base(&self) -> io::Result<File> {
        let base = storage::base(self.slots.namespace(), true)?;
        let inventory = self.recover_retentions()?;
        if inventory.len() == storage::LIMIT {
            return Err(io::Error::other("Лимит удержаний исчерпан"));
        }
        Ok(base)
    }

    fn attach_retention(&self, prepared: &PreparedExecutable) -> io::Result<(OwnedFd, [u32; 3])> {
        mappings::exclude(&prepared.file.executable)?;
        let program = self.kernel.program(c"retain_application_inode")?;
        let link = native::attach(program, prepared.file.executable.as_fd())?;
        let ids = native::inspect(&link, id(program)?, 0, std::process::id(), true)?;
        Ok((link, ids))
    }

    /// Принимает только завершенные записи того же образа, namespace и карты.
    /// Неполные записи сохраняются для отдельного разбора, автоматического GC нет.
    pub fn recover_retentions(&self) -> io::Result<Vec<PinnedRetention>> {
        self.check_owner()?;
        let base = match storage::base(self.slots.namespace(), false) {
            Ok(base) => base,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        storage::names(&base, storage::LIMIT)?
            .iter()
            .map(|name| PinnedRetention::open(self, &base, name))
            .collect()
    }

    /// Снимает только явно переданную проверенную ссылку. Backend сам определяет,
    /// когда завершен ее срок хранения; удаление имени файла не является GC.
    /// После сбоя удаления каталог releasing остается для отдельного разбора.
    pub fn release_retention(&mut self, retention: PinnedRetention) -> io::Result<()> {
        self.check_owner()?;
        retention.verify(self)?;
        let base = storage::base(self.slots.namespace(), false)?;
        let name = storage::completed_name(retention.link_id());
        let directory = retention.own_directory(self, &base, &name)?;
        let releasing = CString::new(format!("releasing_{:08x}", retention.link_id())).unwrap();
        storage::rename(&base, &name, &releasing)?;
        retention.remove_pins(&directory)?;
        storage::remove_directory(&base, &releasing, &directory)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Не удалось подтвердить сохраненное удержание inode",
    )
}
