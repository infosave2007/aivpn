use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::Threading::*,
};

pub fn checked(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn owned(value: HANDLE) -> io::Result<OwnedHandle> {
    if value.is_null() || value == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(value) })
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

pub struct Process {
    pub process: OwnedHandle,
    _thread: OwnedHandle,
}
impl Process {
    pub fn wait(&self, timeout: Duration) -> io::Result<u32> {
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), timeout.as_millis() as u32) }
            != WAIT_OBJECT_0
        {
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
            }
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut code = 0;
        checked(unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) })?;
        Ok(code)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } == WAIT_TIMEOUT {
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
                WaitForSingleObject(self.process.as_raw_handle(), 1000);
            }
        }
    }
}

pub fn spawn(path: &Path, args: &str, output: &Path) -> io::Result<Process> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let log_name = wide(&output.to_string_lossy());
    let log = owned(unsafe {
        CreateFileW(
            log_name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &mut attributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    })?;
    let null_name = wide("NUL");
    let input = owned(unsafe {
        CreateFileW(
            null_name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &mut attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    })?;
    let mut bytes = 0;
    unsafe {
        InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
    }
    let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
    let list = storage.as_mut_ptr().cast();
    checked(unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) })?;
    let inherited = [log.as_raw_handle(), input.as_raw_handle()];
    let updated = checked(unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            std::mem::size_of_val(&inherited),
            ptr::null_mut(),
            ptr::null(),
        )
    });
    if let Err(error) = updated {
        unsafe {
            DeleteProcThreadAttributeList(list);
        }
        return Err(error);
    }
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.as_raw_handle();
    startup.StartupInfo.hStdOutput = log.as_raw_handle();
    startup.StartupInfo.hStdError = log.as_raw_handle();
    startup.lpAttributeList = list;
    let app = wide(&path.to_string_lossy());
    let mut command = wide(&format!("\"{}\" {args}", path.display()));
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let result = checked(unsafe {
        CreateProcessW(
            app.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    });
    unsafe {
        DeleteProcThreadAttributeList(list);
    }
    result?;
    Ok(Process {
        process: owned(info.hProcess)?,
        _thread: owned(info.hThread)?,
    })
}
