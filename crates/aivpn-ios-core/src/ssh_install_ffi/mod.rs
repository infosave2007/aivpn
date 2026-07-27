//! SSH-install FFI (Wave C2b-iOS): C entry points wrapping `aivpn_common::ssh_install`
//! (gated behind this crate's `ssh-install` feature, DEFAULT-on — see `Cargo.toml`; the
//! `make ios` build invokes plain `cargo build -p aivpn-ios-core`, no `--features` flag,
//! so only a crate default reaches the real build).
//!
//! Mirrors the sync-FFI-over-async pattern used by `aivpn_mgmt_request` / `aivpn_qr_png`
//! in `lib.rs` / `ios_tunnel.rs`: a private `current_thread` Tokio runtime drives each
//! blocking call so it never depends on (or blocks) the tunnel's own runtime, and buffer
//! getters use the same written-len-or-needed-len convention.
//!
//! `aivpn_ssh_install_start` is the one call that keeps running in the background: it
//! spawns a dedicated OS thread with its own `current_thread` runtime driving
//! `run_install`, JSON-encoding (`install_event_to_json`) every `InstallEvent` into a
//! per-handle queue (`job_queue::JobRegistry`) that `aivpn_ssh_install_poll` drains.
//!
//! **No cancellation.** There is currently no way to abort an in-flight SSH install once
//! started — `aivpn_ssh_install_free` only detaches the caller's queue (see its doc
//! comment); the remote script keeps running on the VPS and the local SSH session/thread
//! run to completion (or their own timeout/error) regardless. A future wave could thread a
//! cancellation flag through `run_install`'s `on_event` callback (return a sentinel /
//! close the channel) if aborting becomes a requirement.

mod job_queue;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, OnceLock};

use aivpn_common::ssh_install::{
    install_event_to_json, install_params_from_json, installer_script, installer_script_sha256_hex,
    probe_host_fingerprint, run_install, InstallEvent, SshTarget,
};

use job_queue::{JobRegistry, PollOutcome};

fn registry() -> &'static Arc<JobRegistry> {
    static REGISTRY: OnceLock<Arc<JobRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(JobRegistry::new()))
}

/// Copies `s` into `out_buf`/`out_cap` using the written-len-or-needed-len convention
/// shared with `aivpn_mgmt_request` / `aivpn_qr_png` (see their doc comments in `lib.rs`):
/// if `s` fits, it's copied and the byte count is returned; otherwise `out_buf` is left
/// untouched and the needed length is returned instead (always `> out_cap` in that case).
///
/// # Safety
/// `out_buf` must point to at least `out_cap` writable bytes whenever a non-empty copy is
/// about to happen.
unsafe fn copy_str_getter(s: &str, out_buf: *mut u8, out_cap: usize) -> isize {
    let bytes = s.as_bytes();
    if bytes.len() > out_cap {
        return bytes.len() as isize;
    }
    if !bytes.is_empty() {
        if out_buf.is_null() {
            return -1;
        }
        // SAFETY: caller guarantees out_buf points to out_cap writable bytes when a copy
        // is needed; bytes.len() <= out_cap was just checked.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        }
    }
    bytes.len() as isize
}

/// Probes `host:port` over SSH as `user` — no real authentication is attempted (see
/// `aivpn_common::ssh_install::probe_host_fingerprint`) — and writes the server's
/// `SHA256:...` host-key fingerprint into `out_buf` for the caller to show the user for
/// out-of-band TOFU confirmation before calling `aivpn_ssh_install_start`.
///
/// Blocking: spins up a private `current_thread` Tokio runtime for the duration of this
/// one call, same pattern as `aivpn_mgmt_request`.
///
/// Buffer contract shared with `aivpn_mgmt_request` / `aivpn_qr_png` (see their doc
/// comments in `lib.rs`): returns the number of bytes written when `out_cap` was large
/// enough (always `<= out_cap`), or the needed length (`out_buf` left untouched, always
/// `> out_cap`) otherwise. Returns -1 on any error: NULL `host`/`user`, non-UTF-8 input,
/// DNS/TCP/protocol failure, or local runtime creation failure.
///
/// # Safety
/// `host` and `user` must be NUL-terminated, valid-UTF-8 C strings. `out_buf` must point
/// to at least `out_cap` writable bytes (may be NULL only if `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_ssh_probe_hostkey(
    host: *const c_char,
    port: u16,
    user: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    if host.is_null() || user.is_null() {
        return -1;
    }
    // SAFETY: host/user are NUL-terminated C strings from Swift; null-checked above.
    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };
    let user_str = match unsafe { CStr::from_ptr(user) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    let target = SshTarget {
        host: host_str,
        port,
        user: user_str,
    };
    match rt.block_on(probe_host_fingerprint(&target)) {
        Ok(fingerprint) => unsafe { copy_str_getter(&fingerprint, out_buf, out_cap) },
        Err(_) => -1,
    }
}

/// Decodes `privkey_b64` (32 raw bytes, base64 STANDARD) as an X25519 device static
/// private key and returns its public key, base64 STANDARD-encoded.
///
/// This is the mobile counterpart of desktop's
/// `aivpn_client::ssh_install_cmd::local_device_pubkey_b64` — but desktop reads its
/// 32-byte private key straight off disk (`~/.config/aivpn/device.key`), while this core
/// never persists the device key itself (there is no on-disk `device.key` on iOS/Android):
/// the app owns that secret (Keychain / Keystore) and already hands the raw 32 bytes to
/// `aivpn_run_tunnel`'s `static_privkey` parameter for JIT enrollment on every session, so
/// the getter mirrors that same input contract instead of inventing a new storage
/// location. Same `KeyPair::from_private_key` → `public_key_bytes()` derivation as
/// desktop, so a device produces the identical pubkey through either path.
///
/// Returns `None` if `privkey_b64` is not valid base64, or does not decode to exactly 32
/// bytes. Never panics.
pub(crate) fn device_pubkey_b64_from_privkey_b64(privkey_b64: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(privkey_b64.trim())
        .ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let kp = aivpn_common::crypto::KeyPair::from_private_key(arr);
    Some(base64::engine::general_purpose::STANDARD.encode(kp.public_key_bytes()))
}

/// Copies the device's X25519 public key — derived from the caller-supplied
/// `privkey_b64` (same 32-byte device static private key passed as `static_privkey` into
/// `aivpn_run_tunnel`), base64 STANDARD-encoded — into `out_buf`. Lets the in-app SSH
/// install wizard populate `install_params_from_json`'s `device_pubkey_b64` field to
/// request a device-bound (admin-capable) client at add time (mirrors desktop's
/// `--device-pubkey` flow), without the app needing to reimplement X25519 key derivation
/// or link a general-purpose crypto crate itself.
///
/// See `device_pubkey_b64_from_privkey_b64` for the pure derivation this wraps.
///
/// Buffer contract shared with `aivpn_ssh_probe_hostkey` (see its doc comment): returns
/// the number of bytes written when `out_cap` was large enough (always `<= out_cap`), or
/// the needed length (`out_buf` left untouched, always `> out_cap`) otherwise. Returns -1
/// if `privkey_b64` is NULL/not valid UTF-8/not valid base64/not exactly 32 decoded bytes.
///
/// # Safety
/// `privkey_b64` must be a NUL-terminated, valid-UTF-8 C string. `out_buf` must point to
/// at least `out_cap` writable bytes (may be NULL only if `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_device_pubkey_from_privkey(
    privkey_b64: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    if privkey_b64.is_null() {
        return -1;
    }
    // SAFETY: privkey_b64 is a NUL-terminated C string from Swift; null-checked above.
    let privkey_str = match unsafe { CStr::from_ptr(privkey_b64) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match device_pubkey_b64_from_privkey_b64(privkey_str) {
        Some(pubkey) => unsafe { copy_str_getter(&pubkey, out_buf, out_cap) },
        None => -1,
    }
}

/// Copies the SHA256 (hex, 64 chars) of the embedded installer script into `out_buf` — lets
/// the UI show the user what will run on their VPS before they confirm, ahead of starting
/// the install (mirrors `install-server.sh --print-sha256` /
/// `aivpn_common::ssh_install::bundle::installer_script_sha256_hex`).
///
/// Buffer contract: see `aivpn_ssh_probe_hostkey`. Cannot fail other than a too-small/NULL
/// buffer — the hash is computed at compile time from the embedded script.
///
/// # Safety
/// `out_buf` must point to at least `out_cap` writable bytes (may be NULL only if
/// `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_ssh_install_bundle_sha256(
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    let hex = installer_script_sha256_hex();
    unsafe { copy_str_getter(&hex, out_buf, out_cap) }
}

/// Copies the embedded installer script's own text (`deploy/install-server.sh`, typically
/// ~20 KB) into `out_buf` — lets the UI show the exact script that will run, alongside its
/// sha256 from `aivpn_ssh_install_bundle_sha256`, before the user confirms.
///
/// Buffer contract: see `aivpn_ssh_probe_hostkey`.
///
/// # Safety
/// `out_buf` must point to at least `out_cap` writable bytes (may be NULL only if
/// `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_ssh_install_script(out_buf: *mut u8, out_cap: usize) -> isize {
    unsafe { copy_str_getter(installer_script(), out_buf, out_cap) }
}

/// Parses `params_json` (see `aivpn_common::ssh_install::install_params_from_json` for the
/// full JSON contract: host/port/user/auth/fingerprint/binary/mode/...) and starts the SSH
/// install on a dedicated background OS thread — each with its own `current_thread` Tokio
/// runtime driving `run_install` — returning immediately with an opaque handle for
/// `aivpn_ssh_install_poll`. Every `InstallEvent` the install produces (connect / uploading
/// / raw output lines / parsed `##AIVPN` markers / the terminal finished event), JSON-
/// encoded via `install_event_to_json`, is queued for that handle as it arrives.
///
/// If `run_install` itself returns `Err` before producing its own `Finished` event
/// (connect/auth/host-key-mismatch/IO failure — as opposed to the remote script simply
/// exiting nonzero, which surfaces as a normal `Finished{exit_code!=0,...}` event from
/// inside `run_install`), a synthetic pair is queued instead, in this order:
///   1. `{"type":"line","line":"ERROR: <err>"}`
///   2. `{"type":"finished","exit_code":-1,"connection_key":null}`
/// so a caller that only inspects the terminal `finished` event still observes a definite
/// end, and one collecting `line` events for a transcript also sees the error message.
///
/// There is **no cancellation** — see this module's top-level doc comment.
///
/// Returns the job handle (always `>= 1`) on success, or `-1` if `params_json` is NULL,
/// not valid UTF-8, or fails to parse per `install_params_from_json`'s JSON contract.
///
/// # Safety
/// `params_json` must be a NUL-terminated, valid-UTF-8 C string, valid for the duration of
/// this call (it is copied before returning).
#[no_mangle]
pub unsafe extern "C" fn aivpn_ssh_install_start(params_json: *const c_char) -> i64 {
    if params_json.is_null() {
        return -1;
    }
    // SAFETY: params_json is a NUL-terminated C string from Swift; null-checked above.
    let json = match unsafe { CStr::from_ptr(params_json) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };
    let params = match install_params_from_json(&json) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    let reg = registry().clone();
    let handle = reg.create();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                reg.push(
                    handle,
                    install_event_to_json(&InstallEvent::Line(format!(
                        "ERROR: failed to start local runtime: {e}"
                    ))),
                );
                reg.push(
                    handle,
                    install_event_to_json(&InstallEvent::Finished {
                        exit_code: -1,
                        connection_key: None,
                    }),
                );
                reg.mark_done(handle);
                return;
            }
        };

        let reg_for_events = reg.clone();
        let result = rt.block_on(run_install(params, move |ev| {
            reg_for_events.push(handle, install_event_to_json(&ev));
        }));

        // `run_install` already emits its own `Finished` event just before returning
        // `Ok(exit_code)` (including a nonzero remote script exit code) — only an `Err`
        // return (which happens strictly BEFORE any `Finished` is emitted) needs a
        // synthetic one here.
        if let Err(err) = result {
            reg.push(
                handle,
                install_event_to_json(&InstallEvent::Line(format!("ERROR: {err}"))),
            );
            reg.push(
                handle,
                install_event_to_json(&InstallEvent::Finished {
                    exit_code: -1,
                    connection_key: None,
                }),
            );
        }
        reg.mark_done(handle);
    });

    handle
}

/// Pops the next queued `InstallEvent` (JSON-encoded, see `install_event_to_json`) for
/// `handle` into `out_buf`.
///
/// Buffer contract — peek-then-pop, a variant of the written-len-or-needed-len convention
/// shared with `aivpn_mgmt_request`/`aivpn_qr_png`:
///  - `> 0`: an event was available and fit in `out_cap`; it has been POPPED from the
///     queue and its JSON bytes (`<= out_cap`) were written into `out_buf`. The return
///     value is the byte count written.
///  - an event is available but does NOT fit in `out_cap`: the return value is the needed
///     length (always `> out_cap`), and the event is left in the queue — NOT popped — so a
///     retry with a buffer of at least that size gets the exact same event next.
///  - `0`: the queue is currently empty and the job is still running. Poll again later.
///  - `-2`: the queue is empty and the job has finished — no more events will ever arrive
///     for this handle. The caller should call `aivpn_ssh_install_free` and stop polling.
///  - `-1`: `handle` is not a currently registered job (never returned by
///     `aivpn_ssh_install_start`, or already freed via `aivpn_ssh_install_free`).
///
/// # Safety
/// `out_buf` must point to at least `out_cap` writable bytes (may be NULL only if
/// `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_ssh_install_poll(
    handle: i64,
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    match registry().poll(handle, out_cap) {
        PollOutcome::Event(event) => {
            let bytes = event.as_bytes();
            if !bytes.is_empty() {
                if out_buf.is_null() {
                    return -1;
                }
                // SAFETY: caller guarantees out_buf points to out_cap writable bytes;
                // bytes.len() <= out_cap is guaranteed by JobRegistry::poll's contract
                // (an Event is only returned when it fits the requested cap).
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
                }
            }
            bytes.len() as isize
        }
        PollOutcome::NeedsCapacity(needed) => needed as isize,
        PollOutcome::Pending => 0,
        PollOutcome::Done => -2,
        PollOutcome::NotFound => -1,
    }
}

/// Removes `handle` from the registry so `aivpn_ssh_install_poll` no longer recognizes it.
///
/// There is **no cancellation** of an in-flight SSH install (see this module's top-level
/// doc comment): if the background thread started by `aivpn_ssh_install_start` is still
/// running, it keeps calling into the (shared, `Arc`-backed) job registry after this
/// returns — those calls become silent no-ops for `handle` (the entry is gone), so nothing
/// leaks and nothing crashes; the SSH session and remote script simply run to completion
/// with no observer.
///
/// Returns `0` if `handle` was found and removed, `-1` if it was not registered (never
/// returned by `aivpn_ssh_install_start`, or already freed).
#[no_mangle]
pub extern "C" fn aivpn_ssh_install_free(handle: i64) -> c_int {
    if registry().free(handle) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_pubkey_known_vector() {
        // Fixed 32-byte privkey (bytes 0x01..=0x20) -> known pubkey, computed once via
        // the same KeyPair::from_private_key/public_key_bytes derivation this function
        // wraps (see device_pubkey_b64_from_privkey_b64's doc comment for why: same
        // desktop KeyPair API, just fed the app-supplied bytes instead of a device.key
        // file). Pins the derivation so a future accidental change (e.g. dropping X25519
        // clamping) is caught.
        let privkey_b64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
        let pubkey = device_pubkey_b64_from_privkey_b64(privkey_b64).expect("valid 32-byte key");
        assert_eq!(pubkey, "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=");
    }

    #[test]
    fn device_pubkey_roundtrips_against_keypair_generate() {
        // Cross-checks against a freshly generated KeyPair so this doesn't just pin a
        // magic constant: any random device key exported via export_private_key() must
        // decode back to the same public_key_bytes() through the FFI-facing helper.
        use base64::Engine;
        let kp = aivpn_common::crypto::KeyPair::generate();
        let privkey_b64 = base64::engine::general_purpose::STANDARD.encode(kp.export_private_key());
        let expected_pubkey_b64 =
            base64::engine::general_purpose::STANDARD.encode(kp.public_key_bytes());
        assert_eq!(
            device_pubkey_b64_from_privkey_b64(&privkey_b64),
            Some(expected_pubkey_b64)
        );
    }

    #[test]
    fn device_pubkey_rejects_garbage_input() {
        assert_eq!(device_pubkey_b64_from_privkey_b64(""), None);
        assert_eq!(device_pubkey_b64_from_privkey_b64("not base64!!!"), None);
        // valid base64 but wrong decoded length (16 bytes, not 32)
        assert_eq!(
            device_pubkey_b64_from_privkey_b64("AQIDBAUGBwgJCgsMDQ4PEA=="),
            None
        );
    }

    #[test]
    fn install_params_from_json_rejects_malformed_input_without_raw_pointers() {
        // Exercises the exact parse path aivpn_ssh_install_start uses on a bad
        // params_json, but through the safe Rust function directly (no unsafe FFI
        // pointers needed to prove this branch returns -1 at the FFI layer).
        assert!(install_params_from_json("not json at all").is_err());
        assert!(install_params_from_json("{}").is_err()); // missing required fields
    }

    #[test]
    fn registry_accessor_returns_the_same_shared_instance() {
        // Sanity check on the OnceLock wiring: two calls must hand back the same
        // registry (job handles issued via one FFI call must be visible to another).
        let a: *const JobRegistry = Arc::as_ptr(registry());
        let b: *const JobRegistry = Arc::as_ptr(registry());
        assert_eq!(a, b);
    }
}
