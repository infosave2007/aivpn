use super::super::{
    api::{check, denied},
    security::service_authority,
};
use super::{channel_pair, desktop::Desktop, token, WorkerChannel};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{JobObjects::*, SystemInformation::GetSystemDirectoryW, Threading::*},
};

pub(super) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
pub(super) fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}
struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(handles: &[HANDLE]) -> io::Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut result = Self {
            storage: vec![0; size.div_ceil(std::mem::size_of::<usize>())],
            initialized: false,
        };
        check(unsafe { InitializeProcThreadAttributeList(result.raw(), 1, 0, &mut size) })?;
        result.initialized = true;
        check(unsafe {
            UpdateProcThreadAttribute(
                result.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        })?;
        Ok(result)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
}

pub struct WorkerProcess {
    process: OwnedHandle,
    thread: Option<OwnedHandle>,
    job: OwnedHandle,
    image: crate::state::TrustedImage,
    desktop: Desktop,
    private_sid: String,
    pub control: WorkerChannel,
    pub packets: WorkerChannel,
    pub(crate) administration: crate::administration::link::AdministrationLink,
}
impl WorkerProcess {
    /// Только доверенная конфигурация службы выбирает image и журнал.
    pub fn spawn_suspended(
        image: &Path,
        log: &Path,
        generation: u64,
        wake: &OwnedHandle,
    ) -> io::Result<Self> {
        service_authority()?;
        let image =
            crate::state::TrustedImage::open(image).map_err(|e| stage("Образ работника", e))?;
        let canonical = wide(&image.path.to_string_lossy());
        let token = token::restricted_token().map_err(|e| stage("Токен работника", e))?;
        let desktop = Desktop::new(&token).map_err(|e| stage("Desktop работника", e))?;
        let job = owned(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = 1024 * 1024 * 1024;
        check(unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        })?;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        check(unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectBasicUIRestrictions,
                (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of_val(&ui) as u32,
            )
        })?;
        let (control, child_control) = channel_pair()?;
        let (packets, child_packets) = channel_pair()?;
        let (administration, child_administration) = super::administration::pair(generation)?;
        // Работник получает EVENT_MODIFY_STATE; право ожидания остается у службы.
        let mut child_wake = ptr::null_mut();
        check(unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                wake.as_raw_handle(),
                GetCurrentProcess(),
                &mut child_wake,
                EVENT_MODIFY_STATE,
                1,
                0,
            )
        })?;
        let child_wake = owned(child_wake)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let output = owned(unsafe {
            CreateFileW(
                wide(&log.to_string_lossy()).as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })?;
        let input = owned(unsafe {
            CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })?;
        let handles = [
            child_control.as_raw_handle(),
            child_packets.as_raw_handle(),
            child_administration.as_raw_handle(),
            child_wake.as_raw_handle(),
            output.as_raw_handle(),
            input.as_raw_handle(),
        ];
        let mut attributes = Attributes::new(&handles)?;
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input.as_raw_handle();
        startup.StartupInfo.hStdOutput = output.as_raw_handle();
        startup.StartupInfo.hStdError = output.as_raw_handle();
        startup.lpAttributeList = attributes.raw();
        startup.StartupInfo.lpDesktop = desktop.name.as_ptr().cast_mut();
        let mut command = wide(&format!(
            "aivpn __packet-worker {} {} {} {}",
            child_control.as_raw_handle() as usize,
            child_packets.as_raw_handle() as usize,
            child_administration.as_raw_handle() as usize,
            child_wake.as_raw_handle() as usize
        ));
        // Пути поиска DLL и наследуемые переменные не принимаются из окружения GUI.
        let mut system = vec![0; 32768];
        let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) };
        if length == 0 || length as usize >= system.len() {
            return Err(io::Error::last_os_error());
        }
        let directory = String::from_utf16(&system[..length as usize]).map_err(io::Error::other)?;
        let root = Path::new(&directory)
            .parent()
            .ok_or_else(denied)?
            .to_string_lossy();
        let env = format!("SystemRoot={root}\0WINDIR={root}\0\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let own_security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: token.objects.0,
            bInheritHandle: 0,
        };
        check(unsafe {
            CreateProcessAsUserW(
                token.handle.as_raw_handle(),
                canonical.as_ptr(),
                command.as_mut_ptr(),
                &own_security,
                &own_security,
                1,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW,
                env.as_ptr().cast(),
                wide(&directory).as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        })
        .map_err(|e| stage("CreateProcessAsUserW", e))?;
        let process = owned(info.hProcess)?;
        let thread = owned(info.hThread)?;
        let result = Self {
            process,
            thread: Some(thread),
            job,
            image,
            desktop,
            private_sid: token.private_sid,
            control,
            packets,
            administration,
        };
        check(unsafe {
            AssignProcessToJobObject(result.job.as_raw_handle(), result.process.as_raw_handle())
        })?;
        token::verify_expected(&result.process, &result.private_sid)?;
        Ok(result)
    }
    /// Вызывается после регистрации process instance и lease в драйвере.
    pub fn resume(&mut self) -> io::Result<()> {
        self.verify()?;
        let thread = self.thread.take().ok_or_else(denied)?;
        if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn process(&self) -> &OwnedHandle {
        &self.process
    }
    pub fn image(&self) -> &std::fs::File {
        &self.image.file
    }
    pub(crate) fn image_path(&self) -> &Path {
        &self.image.path
    }
    pub fn inherited_station_access(&self) -> bool {
        self.desktop.inherited_access
    }
    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.process.as_raw_handle()) }
    }
    pub fn exited(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub fn exit_code(&self) -> io::Result<Option<u32>> {
        if !self.exited()? {
            return Ok(None);
        }
        let mut code = 0;
        check(unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) })?;
        Ok(Some(code))
    }
    pub(crate) fn wait_exit_code(&self) -> io::Result<Option<u32>> {
        unsafe {
            WaitForSingleObject(self.process.as_raw_handle(), 250);
        }
        self.exit_code()
    }
    pub fn verify(&self) -> io::Result<()> {
        if self.exited()? {
            return Err(denied());
        }
        token::verify_expected(&self.process, &self.private_sid)?;
        let mut member = 0;
        check(unsafe {
            IsProcessInJob(
                self.process.as_raw_handle(),
                self.job.as_raw_handle(),
                &mut member,
            )
        })?;
        if member == 0 {
            return Err(denied());
        }
        Ok(())
    }
}
fn stage(name: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{name}: {error}"))
}
impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.administration.close();
        unsafe {
            TerminateJobObject(self.job.as_raw_handle(), 1);
            TerminateProcess(self.process.as_raw_handle(), 1);
            WaitForSingleObject(self.process.as_raw_handle(), 1000);
        }
    }
}

/// Entry проверяет primary token до приема конфигурации из унаследованного канала.
pub fn verify_current_worker() -> io::Result<()> {
    token::verify_current()
}
