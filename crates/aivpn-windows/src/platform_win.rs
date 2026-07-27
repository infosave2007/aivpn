// ── On-demand UAC elevation for full-tunnel mode ────────────────────────────
//
// aivpn-windows.exe itself launches without any elevation manifest — the
// user can run it as a normal user, and proxy-mode connections never need
// admin rights at all (Wintun is the only thing that does). Only when the
// user selects a full-tunnel key and the process isn't already elevated do
// we self-relaunch elevated, rather than forcing UAC at every launch.
//
// ShellExecuteEx (the API that actually shows the UAC consent prompt) has
// no equivalent of CreateProcess's lpEnvironment — there is no way to pass
// environment variables to the child it launches. The connection key is
// deliberately passed via an env var today (AIVPN_CONNECTION_KEY), not a
// CLI arg, specifically so it never appears in Task Manager's command-line
// column. Relaunching aivpn-client.exe directly through ShellExecuteEx with
// the key in its command line would reintroduce exactly that exposure.
//
// Instead, this relaunches aivpn-windows.exe ITSELF elevated, passing only
// a non-secret key index via --elevated-connect. The freshly-elevated GUI
// instance decrypts its own copy of the connection key from KeyStorage
// (DPAPI, CurrentUser scope — decryptable by any process running as this
// same user, elevated or not) and spawns aivpn-client.exe the normal way
// (Command::spawn + env, unchanged from the existing proxy-mode path). The
// original, non-elevated instance exits once the elevated one is launched.

#[cfg(windows)]
pub(crate) fn is_elevated() -> bool {
    use std::mem;
    use std::ptr;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut ret_size: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut winapi::ctypes::c_void,
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_size,
        );
        winapi::um::handleapi::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relaunch this exe elevated via ShellExecuteEx's "runas" verb (the API
/// that shows the native UAC consent dialog), passing only the non-secret
/// key index. Returns Err if the user cancels the prompt or ShellExecuteEx
/// itself fails; never returns Ok (the caller is expected to exit the
/// current process immediately after a successful launch, so there is
/// nothing meaningful to return to).
#[cfg(windows)]
pub(crate) fn relaunch_elevated(key_index: usize) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::shellapi::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use winapi::um::winuser::SW_SHOWNORMAL;

    let exe = std::env::current_exe()
        .map_err(|e| format!("Could not determine current executable path: {e}"))?;

    let wide = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let verb = wide(OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let params_str = format!("--elevated-connect {key_index}");
    let params = wide(OsStr::new(&params_str));
    let dir = exe.parent().map(|d| wide(d.as_os_str()));

    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.lpDirectory = dir.as_ref().map(|d| d.as_ptr()).unwrap_or(std::ptr::null());
    sei.nShow = SW_SHOWNORMAL;

    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 || sei.hProcess.is_null() {
        return Err(
            "Elevation was cancelled or failed. Full-tunnel mode requires Administrator \
             rights on Windows to create the network adapter — either allow the elevation \
             prompt, or switch this key to proxy mode (no admin rights needed)."
                .to_string(),
        );
    }
    // We don't need the handle — the elevated instance is now fully
    // independent and manages its own lifecycle.
    unsafe { winapi::um::handleapi::CloseHandle(sei.hProcess) };
    Ok(())
}

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
