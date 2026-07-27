import Foundation

/// Subprocess bridge to `aivpn-client ssh-install {script,probe,run}` — the
/// desktop CLI's SSH server installer (see
/// crates/aivpn-client/src/ssh_install_cmd.rs for the exact contract this
/// mirrors, in particular its module doc comment describing the `run`
/// stdout streaming protocol). The macOS GUI never links
/// `aivpn_common::ssh_install`/`russh` directly — same "subprocess, not
/// FFI" architecture `VPNManager`/`AdminApi` already use for the rest of
/// this app (see AdminApi.swift's own architecture note): it only shells
/// out to the aivpn-client binary already bundled in the app, built with
/// the `ssh-install` cargo feature enabled.
enum SshInstaller {

    enum InstallError: LocalizedError {
        case binaryNotFound
        case processFailed(String)
        case invalidOutput(String)

        var errorDescription: String? {
            switch self {
            case .binaryNotFound:
                return "aivpn-client not found in app bundle"
            case .processFailed(let msg):
                return msg
            case .invalidOutput(let msg):
                return "unparseable output: \(msg)"
            }
        }
    }

    /// Exactly one of `--password-env` / `--key-file` (+ optional
    /// `--key-passphrase-env`) is sent — mirrors `RunArgs`' mutually
    /// exclusive `auth_method` clap group (`--password-stdin` is not
    /// offered here: env-var is simpler for a GUI subprocess caller and the
    /// CLI accepts it as an equally valid member of that same group).
    enum Auth {
        case password(String)
        case keyFile(path: String, passphrase: String?)
    }

    /// Mirrors `RunArgs`' `--binary-file` / `--binary-url` / (neither ->
    /// GitHub Releases default) trio.
    enum BinarySource {
        case releases
        case file(String)
        case url(String)
    }

    /// Mirrors `InstallModeArg` (`--mode systemd|docker`).
    enum Mode: String {
        case systemd
        case docker
    }

    /// Mirrors `ssh_install::AivpnMarker` / `parse_marker_line`'s wire
    /// shape — the exact JSON object every `##AIVPN {...}` line (both
    /// remote-script and client-side markers) carries. `raw` (Rust-only,
    /// holds the full parsed `serde_json::Value` for forward-compat) is
    /// deliberately not modeled here; every field this struct's callers
    /// need is already a named key.
    struct Marker: Decodable {
        let step: String
        let status: String
        let code: String?
        let msg: String?
        let connection_key: String?
    }

    /// Parses a single stdout line as an `##AIVPN {...}` marker, or nil for
    /// an ordinary (non-marker) remote-script log line. Mirrors
    /// `ssh_install::parse_marker_line`'s `"##AIVPN "` prefix + JSON body.
    static func parseMarkerLine(_ line: String) -> Marker? {
        guard line.hasPrefix("##AIVPN ") else { return nil }
        let jsonPart = String(line.dropFirst("##AIVPN ".count))
        guard let data = jsonPart.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(Marker.self, from: data)
    }

    // MARK: - Binary lookup

    /// Same search `VPNManager.bundledClientBinaryPath()` uses — no
    /// trusted-install-location restriction, since `ssh-install` always
    /// runs as the console user (never via the privileged helper).
    static func binaryPath() -> String? {
        let candidates = [
            Bundle.main.bundlePath + "/Contents/Resources/aivpn-client",
            Bundle.main.bundlePath + "/Contents/MacOS/aivpn-client",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    // MARK: - Captured (non-streaming) subprocess helper

    /// Runs `aivpn-client <args>`, capturing stdout/stderr fully. Drains
    /// both pipes concurrently with the child (mirrors
    /// `VPNManager.runBundledClientCommand`'s doc comment: reading only
    /// after `waitUntilExit` deadlocks once the child writes more than the
    /// pipe buffer). `timeoutSeconds` bounds network-touching calls
    /// (`probe`); local, instant calls (`script`) pass nil for no bound.
    private static func runCaptured(
        _ args: [String], timeoutSeconds: Double? = nil
    ) -> (status: Int32, stdout: String, stderr: String) {
        guard let binary = binaryPath() else {
            return (-1, "", "aivpn-client not found in app bundle")
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: binary)
        task.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe

        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        do {
            try task.run()
        } catch {
            // Unblock the two drain threads: with no child holding the write
            // ends, EOF only arrives after we close our own copies — without
            // this, both readDataToEndOfFile calls (and their GCD threads +
            // pipe fds) leak forever on every failed spawn. Same reasoning as
            // `VPNManager.runBundledClientCommand`'s catch path.
            outPipe.fileHandleForWriting.closeFile()
            errPipe.fileHandleForWriting.closeFile()
            _ = group.wait(timeout: .now() + 1)
            return (-1, "", error.localizedDescription)
        }

        if let timeoutSeconds = timeoutSeconds {
            let deadline = Date().addingTimeInterval(timeoutSeconds)
            while task.isRunning && Date() < deadline {
                usleep(50_000)
            }
            if task.isRunning {
                task.terminate()
                usleep(300_000)
                if task.isRunning {
                    kill(task.processIdentifier, SIGKILL)
                }
            }
        }
        task.waitUntilExit()
        _ = group.wait(timeout: .now() + 2)

        let stdout = String(data: outData, encoding: .utf8) ?? ""
        let stderr = String(data: errData, encoding: .utf8) ?? ""
        return (task.terminationStatus, stdout, stderr)
    }

    // MARK: - script / probe (blocking helpers — call off the main thread)

    /// `aivpn-client ssh-install script` — the embedded install-server.sh,
    /// verbatim, for "paranoid mode" review before the user trusts a host.
    static func installerScript() -> String {
        let result = runCaptured(["ssh-install", "script"])
        return result.status == 0 ? result.stdout : ""
    }

    /// `aivpn-client ssh-install script --sha256-only` — hex SHA256 of the
    /// exact script `installerScript()` returns.
    static func installerScriptSha256() -> String {
        let result = runCaptured(["ssh-install", "script", "--sha256-only"])
        return result.status == 0 ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : ""
    }

    /// `aivpn-client ssh-install script --unit` — the systemd unit template
    /// the installer writes on the remote host.
    static func systemdUnit() -> String {
        let result = runCaptured(["ssh-install", "script", "--unit"])
        return result.status == 0 ? result.stdout : ""
    }

    /// `aivpn-client ssh-install probe --host H --port P --user U` — TOFU
    /// step 1: connects just far enough to read the remote host's SSH key
    /// fingerprint, no authentication attempted. Bounded to 20s: a
    /// filtered/unreachable host can otherwise hang the underlying TCP
    /// connect for a long time (the Rust `ssh_install` probe has no
    /// internal timeout of its own).
    static func probeHostkey(host: String, port: Int, user: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                guard binaryPath() != nil else {
                    continuation.resume(throwing: InstallError.binaryNotFound)
                    return
                }
                let args = ["ssh-install", "probe", "--host", host, "--port", String(port), "--user", user]
                let result = runCaptured(args, timeoutSeconds: 20.0)
                guard result.status == 0 else {
                    let msg = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                    continuation.resume(throwing: InstallError.processFailed(msg.isEmpty ? "probe failed (exit \(result.status))" : msg))
                    return
                }
                let trimmed = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                guard let data = trimmed.data(using: .utf8),
                      let decoded = try? JSONDecoder().decode(ProbeFingerprintResponse.self, from: data) else {
                    continuation.resume(throwing: InstallError.invalidOutput(trimmed))
                    return
                }
                continuation.resume(returning: decoded.fingerprint)
            }
        }
    }

    private struct ProbeFingerprintResponse: Decodable {
        let fingerprint: String
    }

    // MARK: - run (streaming)

    /// `aivpn-client ssh-install run …` — TOFU step 2: runs the remote
    /// installer over SSH using the fingerprint the caller already
    /// confirmed with the user (normally `probeHostkey`'s result). Streams
    /// every stdout line (raw remote-script lines and client-side
    /// `##AIVPN {...}` markers alike, per the module doc comment on
    /// `ssh_install_cmd.rs`) to `onLine`, invoked on the MAIN thread so
    /// callers (an `ObservableObject`'s `@Published` log) can append
    /// directly with no extra hop. Returns the child's exit code, which
    /// mirrors the remote installer's own exit code when the SSH session
    /// made it that far, or `1` for a connect/auth/fingerprint-mismatch
    /// failure that never reached the remote script at all.
    ///
    /// The SSH password/key passphrase are passed via the child's
    /// environment (`--password-env`/`--key-passphrase-env`), never argv —
    /// argv is visible to every same-uid process via `ps`/`/proc`, exactly
    /// the same reasoning `VPNManager.connectProxy` already documents for
    /// `AIVPN_CONNECTION_KEY`.
    static func runInstall(
        host: String, port: Int, user: String, fingerprint: String,
        auth: Auth,
        source: BinarySource,
        serverIp: String?, serverPort: Int?,
        mode: Mode,
        bindDevice: Bool,
        onLine: @escaping (String) -> Void
    ) async -> Int32 {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let binary = binaryPath() else {
                    DispatchQueue.main.async {
                        onLine(#"##AIVPN {"step":"ssh_connect","status":"error","code":"binary_missing","msg":"aivpn-client not found in app bundle","connection_key":null}"#)
                    }
                    continuation.resume(returning: 1)
                    return
                }

                var args = [
                    "ssh-install", "run",
                    "--host", host,
                    "--port", String(port),
                    "--user", user,
                    "--fingerprint", fingerprint,
                ]

                var env = ProcessInfo.processInfo.environment
                switch auth {
                case .password(let password):
                    args += ["--password-env", "AIVPN_SSH_INSTALL_PASSWORD"]
                    env["AIVPN_SSH_INSTALL_PASSWORD"] = password
                case .keyFile(let path, let passphrase):
                    args += ["--key-file", path]
                    if let passphrase = passphrase, !passphrase.isEmpty {
                        args += ["--key-passphrase-env", "AIVPN_SSH_INSTALL_KEY_PASSPHRASE"]
                        env["AIVPN_SSH_INSTALL_KEY_PASSPHRASE"] = passphrase
                    }
                }

                switch source {
                case .releases:
                    break
                case .file(let path):
                    args += ["--binary-file", path]
                case .url(let url):
                    args += ["--binary-url", url]
                }

                if let serverIp = serverIp, !serverIp.isEmpty {
                    args += ["--server-ip", serverIp]
                }
                if let serverPort = serverPort {
                    args += ["--server-port", String(serverPort)]
                }
                args += ["--mode", mode.rawValue]
                if !bindDevice {
                    // Toggle OFF -> never bind this install's created client
                    // to a local device key, even if one exists at
                    // ~/.config/aivpn/device.key. Toggle ON sends neither
                    // flag: `ssh-install run` then defaults to that local
                    // key itself (ssh_install_cmd.rs::local_device_pubkey_b64),
                    // or emits the informational `device_pubkey`/
                    // `no_local_device_key` marker and proceeds unbound if
                    // no such key exists yet.
                    args += ["--no-device-pubkey"]
                }

                let task = Process()
                task.executableURL = URL(fileURLWithPath: binary)
                task.arguments = args
                task.environment = env

                let outPipe = Pipe()
                let errPipe = Pipe()
                task.standardOutput = outPipe
                task.standardError = errPipe

                // Stream stdout line-by-line as it arrives; drain stderr
                // concurrently (unread, just to prevent a full pipe buffer
                // from blocking the child) — same concurrent-drain reasoning
                // as `VPNManager.runBundledClientCommand`'s doc comment.
                let stdoutDone = DispatchSemaphore(value: 0)
                let stderrDone = DispatchSemaphore(value: 0)
                var lineBuffer = Data()
                let newline = Data([0x0A])

                outPipe.fileHandleForReading.readabilityHandler = { handle in
                    let data = handle.availableData
                    if data.isEmpty {
                        handle.readabilityHandler = nil
                        if !lineBuffer.isEmpty, let line = String(data: lineBuffer, encoding: .utf8) {
                            let trimmed = line.trimmingCharacters(in: .newlines)
                            if !trimmed.isEmpty {
                                DispatchQueue.main.async { onLine(trimmed) }
                            }
                        }
                        stdoutDone.signal()
                        return
                    }
                    lineBuffer.append(data)
                    while let range = lineBuffer.range(of: newline) {
                        let lineData = lineBuffer.subdata(in: lineBuffer.startIndex..<range.lowerBound)
                        lineBuffer.removeSubrange(lineBuffer.startIndex..<range.upperBound)
                        if let line = String(data: lineData, encoding: .utf8) {
                            let trimmed = line.trimmingCharacters(in: .newlines)
                            DispatchQueue.main.async { onLine(trimmed) }
                        }
                    }
                }
                errPipe.fileHandleForReading.readabilityHandler = { handle in
                    let data = handle.availableData
                    if data.isEmpty {
                        handle.readabilityHandler = nil
                        stderrDone.signal()
                    }
                }

                do {
                    try task.run()
                } catch {
                    outPipe.fileHandleForReading.readabilityHandler = nil
                    errPipe.fileHandleForReading.readabilityHandler = nil
                    DispatchQueue.main.async {
                        let escaped = error.localizedDescription
                            .replacingOccurrences(of: "\\", with: "\\\\")
                            .replacingOccurrences(of: "\"", with: "\\\"")
                        onLine("##AIVPN {\"step\":\"ssh_connect\",\"status\":\"error\",\"code\":\"spawn_failed\",\"msg\":\"\(escaped)\",\"connection_key\":null}")
                    }
                    continuation.resume(returning: 1)
                    return
                }

                task.waitUntilExit()
                _ = stdoutDone.wait(timeout: .now() + 3)
                _ = stderrDone.wait(timeout: .now() + 3)
                continuation.resume(returning: task.terminationStatus)
            }
        }
    }
}
