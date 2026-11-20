//! Вспомогательные операции окон и единственного экземпляра GUI.

// ── Win32 helpers ──────────────────────────────────────────────────────────

/// Claim (and intentionally leak, for the process lifetime) the named
/// single-instance mutex. Returns true when another AIVPN GUI already holds
/// it; false also when the mutex could not be created at all — an
/// undiagnosable failure must not block launching the app.
#[cfg(windows)]
pub(crate) fn claim_single_instance_mutex() -> bool {
    use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::synchapi::CreateMutexW;
    let name: Vec<u16> = "AIVPN_GUI_SingleInstance\0".encode_utf16().collect();
    unsafe {
        let h = CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr());
        if h.is_null() {
            return false;
        }
        // Handle deliberately not closed: the mutex must stay held for the
        // whole process lifetime; the OS releases it at process exit.
        GetLastError() == ERROR_ALREADY_EXISTS
    }
}

/// Bring the ALREADY-RUNNING instance's window to the foreground before this
/// duplicate process exits. This is the one place a cross-process
/// FindWindowW is the point (contrast find_own_aivpn_hwnd()) — any window
/// titled "AIVPN" here belongs to the other instance, not to us.
#[cfg(windows)]
pub(crate) fn focus_existing_instance() {
    unsafe {
        use winapi::um::winuser::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE};
        let title: Vec<u16> = "AIVPN\0".encode_utf16().collect();
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

/// Locate THIS process's main window (LOW-1). A bare FindWindowW(null,
/// "AIVPN") matches any top-level window with that title from any process —
/// so walk all title matches and keep the one owned by our PID.
#[cfg(windows)]
pub(crate) fn find_own_aivpn_hwnd() -> winapi::shared::windef::HWND {
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::winuser::{FindWindowExW, GetWindowThreadProcessId};
    let title: Vec<u16> = "AIVPN\0".encode_utf16().collect();
    unsafe {
        let my_pid = GetCurrentProcessId();
        let mut hwnd = FindWindowExW(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            title.as_ptr(),
        );
        while !hwnd.is_null() {
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == my_pid {
                return hwnd;
            }
            hwnd = FindWindowExW(std::ptr::null_mut(), hwnd, std::ptr::null(), title.as_ptr());
        }
        std::ptr::null_mut()
    }
}

/// Restore + focus the AIVPN window, bypassing SetForegroundWindow restrictions via
/// AttachThreadInput. Uses SW_RESTORE so a minimized window is un-minimized.
#[cfg(windows)]
pub(crate) fn bring_window_to_front() {
    unsafe {
        use winapi::um::processthreadsapi::GetCurrentThreadId;
        use winapi::um::winuser::{
            AttachThreadInput, BringWindowToTop, GetForegroundWindow, GetWindowThreadProcessId,
            SetForegroundWindow, ShowWindow, SW_RESTORE,
        };
        let hwnd = find_own_aivpn_hwnd();
        if hwnd.is_null() {
            return;
        }
        let fg_hwnd = GetForegroundWindow();
        let fg_thread = GetWindowThreadProcessId(fg_hwnd, std::ptr::null_mut());
        let my_thread = GetCurrentThreadId();
        if fg_thread != 0 && fg_thread != my_thread {
            AttachThreadInput(fg_thread, my_thread, 1);
        }
        ShowWindow(hwnd, SW_RESTORE);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        if fg_thread != 0 && fg_thread != my_thread {
            AttachThreadInput(fg_thread, my_thread, 0);
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn bring_window_to_front() {}

// ── Autostart (Windows registry) ───────────────────────────────────────────

#[cfg(windows)]
pub(crate) fn set_autostart(enable: bool) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    if let Ok((run, _)) = hkcu.create_subkey(run_path) {
        if enable {
            if let Ok(exe) = std::env::current_exe() {
                // LOW-6: write the path as an OsString (winreg encodes it to
                // UTF-16 losslessly) — to_string_lossy would corrupt a path
                // containing unpaired surrogates and register a broken
                // autostart command.
                let mut quoted = std::ffi::OsString::from("\"");
                quoted.push(exe.as_os_str());
                quoted.push("\"");
                let _ = run.set_value("AIVPN", &quoted);
            }
        } else {
            let _ = run.delete_value("AIVPN");
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn set_autostart(_enable: bool) {}

pub(crate) fn choose_mtls_file(lang: crate::localization::Lang) -> Option<String> {
    choose_file(
        crate::appearance::text(lang, "Выбрать сертификат mTLS", "Select mTLS certificate"),
        "PEM / CRT\0*.pem;*.crt;*.cer\0All files\0*.*\0\0",
    )
}

pub(crate) fn choose_application(lang: crate::localization::Lang) -> Option<String> {
    choose_file(
        crate::appearance::text(lang, "Выбрать приложение", "Select application"),
        "EXE\0*.exe\0All files\0*.*\0\0",
    )
}

fn choose_file(title: &str, filter: &str) -> Option<String> {
    use winapi::um::commdlg::{
        GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
        OPENFILENAMEW,
    };
    let title: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
    let filter: Vec<u16> = filter.encode_utf16().collect();
    let mut path = vec![0u16; 32768];
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = find_own_aivpn_hwnd();
    dialog.lpstrTitle = title.as_ptr();
    dialog.lpstrFilter = filter.as_ptr();
    dialog.lpstrFile = path.as_mut_ptr();
    dialog.nMaxFile = path.len() as u32;
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        return None;
    }
    let end = path.iter().position(|c| *c == 0)?;
    Some(String::from_utf16_lossy(&path[..end]))
}

pub(crate) fn choose_log_path(lang: crate::localization::Lang) -> Option<std::path::PathBuf> {
    use winapi::um::commdlg::{
        GetSaveFileNameW, OFN_EXPLORER, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST,
        OPENFILENAMEW,
    };
    let title: Vec<u16> = crate::appearance::text(lang, "Сохранить журнал", "Save log")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let filter: Vec<u16> = "Text (*.txt)\0*.txt\0All files\0*.*\0\0"
        .encode_utf16()
        .collect();
    let mut path = vec![0u16; 32768];
    for (i, c) in "aivpn-log.txt".encode_utf16().enumerate() {
        path[i] = c;
    }
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = find_own_aivpn_hwnd();
    dialog.lpstrTitle = title.as_ptr();
    dialog.lpstrFilter = filter.as_ptr();
    dialog.lpstrFile = path.as_mut_ptr();
    dialog.nMaxFile = path.len() as u32;
    dialog.Flags = OFN_EXPLORER | OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if unsafe { GetSaveFileNameW(&mut dialog) } == 0 {
        return None;
    }
    let end = path.iter().position(|c| *c == 0)?;
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &path[..end],
    )))
}
