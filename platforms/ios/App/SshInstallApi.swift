import Foundation

// Swift wrapper around the in-app SSH server-installer FFI surface exposed
// by aivpn-ios-core's `ssh-install` feature (crates/aivpn-ios-core/include/
// aivpn_core.h — Wave C2b-iOS section — wrapping
// crates/aivpn-common/src/ssh_install.rs; DEFAULT-on, so a plain
// `cargo build -p aivpn-ios-core` picks it up with no extra flag):
//   intptr_t aivpn_ssh_probe_hostkey(host, port, user, out_buf, out_cap)
//   intptr_t aivpn_ssh_install_bundle_sha256(out_buf, out_cap)
//   intptr_t aivpn_ssh_install_script(out_buf, out_cap)
//   int64_t  aivpn_ssh_install_start(params_json)
//   intptr_t aivpn_ssh_install_poll(handle, out_buf, out_cap)
//   int      aivpn_ssh_install_free(handle)
//
// Declared in the bridging header (App/AivpnCoreBridge.h, which #includes
// the whole aivpn_core.h), so they're callable directly from Swift with no
// extra glue — same as AdminApi.swift's FFI calls.
//
// `params_json` / poll-event wire schema below is transcribed from the
// RUST side that (de)serializes them — `install_params_from_json` /
// `install_event_to_json` in crates/aivpn-common/src/ssh_install.rs, the
// ONLY place in the codebase that does this (de)serialization; the iOS
// FFI, Android JNI, and CLI all share it — not guessed:
//
//   params_json (aivpn_ssh_install_start's input):
//   {
//     "host": "1.2.3.4", "port": 22, "user": "root",
//     "auth": {"type":"password","password":"..."}
//           | {"type":"key_pem","pem":"...","passphrase":null},
//     "fingerprint": "SHA256:...",             // required — TOFU-confirmed
//     "binary": {"type":"default"},
//     "server_ip": null, "server_port": null,
//     "mode": "systemd" | "docker",
//     "device_pubkey_b64": null,                // see InstallServerView.swift
//     "extra_args": []
//   }
//
//   poll event JSON (aivpn_ssh_install_poll's output, one per call):
//   {"type":"connected","fingerprint":"..."}
//   {"type":"uploading","what":"..."}
//   {"type":"line","line":"..."}
//   {"type":"marker","step":"...","status":"ok|error|info","code":null|"...","msg":null|"...","connection_key":null|"..."}
//   {"type":"finished","exit_code":0,"connection_key":null|"..."}

/// Result of one `aivpn_ssh_install_poll` call, translated from its raw
/// int-return convention (documented on that function in aivpn_core.h)
/// into a Swift enum so callers never juggle sentinel values directly.
enum SshInstallPollResult {
    /// One event was popped from the queue — its raw single-line JSON
    /// string (see this file's header for the wire shape).
    case event(String)
    /// The queue is empty but the job is still running. Poll again later.
    case pending
    /// The queue is empty AND the job has finished — no more events will
    /// ever arrive for this handle. Caller must call `installFree` and
    /// stop polling.
    case done
    /// `handle` is not a currently registered job (never issued, or
    /// already freed).
    case badHandle
}

/// Stateless namespace wrapping the blocking FFI calls, mirroring
/// AdminApi.swift's shape and buffer-retry convention. Every function that
/// can block on real IO (network probe, or a written-len-or-needed-len
/// retry) hops off the caller's thread via `Task.detached`; callers are
/// responsible for hopping back to the main actor before mutating
/// `@State`/`@Published` UI state with the result.
enum SshInstallApi {

    // MARK: Probe (TOFU step 1)

    /// Probes `host:port` over SSH as `user` — no real authentication is
    /// attempted (key exchange alone yields the host key) — and returns
    /// its OpenSSH-style `SHA256:<base64>` fingerprint for out-of-band TOFU
    /// confirmation, or `nil` on any error (DNS/TCP/SSH protocol failure,
    /// bad UTF-8 input, or local runtime creation failure — see
    /// aivpn_ssh_probe_hostkey's doc comment).
    static func probeHostkey(host: String, port: UInt16, user: String) async -> String? {
        await Task.detached(priority: .userInitiated) {
            probeHostkeyBlocking(host: host, port: port, user: user)
        }.value
    }

    private static func probeHostkeyBlocking(host: String, port: UInt16, user: String) -> String? {
        var cap = 4096
        // One retry with the server-reported needed length, per the
        // written-len-or-needed-len convention shared with
        // aivpn_mgmt_request/aivpn_qr_png (see aivpn_core.h).
        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = host.withCString { hostPtr in
                user.withCString { userPtr in
                    outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                        aivpn_ssh_probe_hostkey(hostPtr, port, userPtr, outBufPtr.baseAddress, outBufPtr.count)
                    }
                }
            }
            if written < 0 { return nil }
            if written <= cap {
                return String(decoding: outBuf.prefix(written), as: UTF8.self)
            }
            cap = written
        }
        return nil
    }

    // MARK: Bundle info (shown to the user before they confirm an install)

    /// SHA256 (hex, 64 ASCII chars) of the embedded installer script — show
    /// alongside `installScript()`'s output so the user can verify what
    /// will run on their VPS before confirming. Never fails other than a
    /// too-small buffer, which this retries internally; falls back to an
    /// empty string only if that retry also somehow fails.
    static func bundleSha256() async -> String {
        await Task.detached(priority: .userInitiated) {
            bundleSha256Blocking() ?? ""
        }.value
    }

    private static func bundleSha256Blocking() -> String? {
        var cap = 128
        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                aivpn_ssh_install_bundle_sha256(outBufPtr.baseAddress, outBufPtr.count)
            }
            if written < 0 { return nil }
            if written <= cap {
                return String(decoding: outBuf.prefix(written), as: UTF8.self)
            }
            cap = written
        }
        return nil
    }

    /// The embedded installer script's own text
    /// (`deploy/install-server.sh`, typically ~20 KB), for display before
    /// the user confirms an install.
    static func installScript() async -> String {
        await Task.detached(priority: .userInitiated) {
            installScriptBlocking() ?? ""
        }.value
    }

    private static func installScriptBlocking() -> String? {
        var cap = 32 * 1024
        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                aivpn_ssh_install_script(outBufPtr.baseAddress, outBufPtr.count)
            }
            if written < 0 { return nil }
            if written <= cap {
                return String(decoding: outBuf.prefix(written), as: UTF8.self)
            }
            cap = written
        }
        return nil
    }

    // MARK: Install job lifecycle

    /// Parses `paramsJson` and starts the SSH install on a dedicated
    /// background thread inside aivpn-ios-core, returning immediately with
    /// an opaque job handle for `installPoll`. Unlike the other calls in
    /// this file this does NOT touch the network itself (it only parses
    /// JSON and spawns a thread — see aivpn_ssh_install_start's doc
    /// comment) and is cheap enough to call directly.
    ///
    /// @return handle (>= 1) on success, or -1 if `paramsJson` is NULL,
    ///         not valid UTF-8, or fails to parse.
    static func installStart(paramsJson: String) -> Int64 {
        paramsJson.withCString { aivpn_ssh_install_start($0) }
    }

    /// Pops the next queued install event for `handle`, translating
    /// `aivpn_ssh_install_poll`'s raw int convention (peek-then-pop, see
    /// aivpn_core.h) into `SshInstallPollResult`. Internally retries once
    /// with a bigger buffer if an available event doesn't fit the default
    /// capacity — callers never see that detail. Cheap (queue pop under a
    /// mutex, no network IO) — intended to be called directly from a
    /// polling `Timer` on the main thread, unlike the other functions here.
    static func installPoll(handle: Int64) -> SshInstallPollResult {
        var cap = 8192
        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                aivpn_ssh_install_poll(handle, outBufPtr.baseAddress, outBufPtr.count)
            }
            if written == -1 { return .badHandle }
            if written == 0 { return .pending }
            if written == -2 { return .done }
            if written > 0 && written <= cap {
                return .event(String(decoding: outBuf.prefix(written), as: UTF8.self))
            }
            // written > cap: the event was left in the queue (not popped)
            // — retry with the exact needed size to get it.
            cap = written
        }
        // Not normally reachable (the needed size shrinks the gap to zero
        // on the second try), but never spin forever on a resize race —
        // treat as transiently pending rather than losing the event.
        return .pending
    }

    /// Removes `handle` from the job registry so `installPoll` no longer
    /// recognizes it. Does NOT cancel an in-flight install (see
    /// aivpn_ssh_install_free's doc comment) — if the background SSH
    /// thread is still running, the remote script runs to completion with
    /// no observer.
    ///
    /// @return true if `handle` was found and removed.
    @discardableResult
    static func installFree(handle: Int64) -> Bool {
        aivpn_ssh_install_free(handle) == 0
    }
}
