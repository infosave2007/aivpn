use super::*;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

#[test]
fn rejects_pipe_path_injection() {
    for name in ["", "..", "a/b", "a\\b", "a\0b", "имя", &"a".repeat(129)] {
        assert!(pipe_name(name, false).is_err());
    }
    assert!(pipe_name("Agent_123-abc", true).is_ok());
}

#[test]
fn deadline_and_stop_are_absolute() {
    let stopped = AtomicBool::new(true);
    assert_eq!(
        api::remaining(Instant::now() + TIMEOUT, &stopped)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    let running = AtomicBool::new(false);
    assert_eq!(
        api::remaining(Instant::now() - TIMEOUT, &running)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn impersonated_thread_cannot_claim_service_authority() {
    use windows_sys::Win32::Security::*;
    security::no_impersonation().unwrap();
    let identity = primary_token_identity();
    let authority = security::service_authority().is_ok();
    check(unsafe { ImpersonateSelf(SecurityIdentification) }).unwrap();
    let denied = security::service_authority().is_err();
    check(unsafe { RevertToSelf() }).unwrap();
    assert!(denied);
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let error = unsafe { GetLastError() };
    if opened != 0 {
        drop(Handle::new(token).unwrap());
    }
    assert_eq!(opened, 0);
    assert_eq!(error, ERROR_NO_TOKEN);
    assert_eq!(primary_token_identity(), identity);
    assert_eq!(security::service_authority().is_ok(), authority);
}

fn primary_token_identity() -> ((i32, u32), (i32, u32)) {
    use windows_sys::Win32::Security::*;
    let mut raw = ptr::null_mut();
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }).unwrap();
    let token = Handle::new(raw).unwrap();
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    check(unsafe {
        GetTokenInformation(
            token.raw(),
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    })
    .unwrap();
    assert_eq!(returned as usize, std::mem::size_of::<TOKEN_STATISTICS>());
    (
        (statistics.TokenId.HighPart, statistics.TokenId.LowPart),
        (
            statistics.AuthenticationId.HighPart,
            statistics.AuthenticationId.LowPart,
        ),
    )
}

#[test]
fn both_ready_reserve_admin_without_starving_public() {
    assert_eq!(select_endpoint(true, true, false), Some(true));
    assert_eq!(select_endpoint(true, true, true), Some(false));
    assert_eq!(select_endpoint(false, true, true), Some(true));
    assert_eq!(select_endpoint(true, false, false), Some(false));
    assert_eq!(select_endpoint(false, false, false), None);
}
