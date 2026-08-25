#!/usr/bin/env swift
// ═══════════════════════════════════════════════════════════════
// AIVPN Privileged Helper Daemon v1.1.0
//
// Manages aivpn-client process on behalf of the AIVPN GUI app.
// Communicates via JSON over Unix domain socket.
// Installed as LaunchDaemon — runs as root, no password prompts.
// ═══════════════════════════════════════════════════════════════

import Foundation
import Darwin
import Security
import SystemConfiguration

// MARK: - Constants

let SOCKET_PATH = "/var/run/aivpn/helper.sock"
let DEFAULT_CLIENT_PATH = "/Library/Application Support/AIVPN/aivpn-client"
let ALLOWED_CLIENT_PATHS = [
    // build.sh produces "Aivpn.app"; the filesystem is case-insensitive but
    // this string comparison is not — keep both historical capitalizations.
    "/Applications/Aivpn.app/Contents/MacOS/aivpn-client",
    "/Applications/Aivpn.app/Contents/Resources/aivpn-client",
    "/Applications/AIVPN.app/Contents/MacOS/aivpn-client",
    "/Applications/AIVPN.app/Contents/Resources/aivpn-client",
    DEFAULT_CLIENT_PATH,
]
let LOG_PATH = "/var/run/aivpn/client.log"
let PID_PATH = "/var/run/aivpn/client.pid"
let RECORDING_STATUS_PATH = "/var/run/aivpn/recording.status"
let RECORDING_STATUS_FALLBACK_PATH = "/tmp/aivpn-recording.status"
let HELPER_VERSION = "1.1.0"

// MARK: - Protocol Types

struct HelperRequest: Codable {
    let action: String       // connect, disconnect, status, ping, log
    let key: String?         // connection key (for connect)
    let fullTunnel: Bool?    // full tunnel mode (for connect)
    let binaryPath: String?  // custom binary path (for connect/dev)
    let service: String?     // service name (for record_start)
    let mtlsCertPath: String? // optional path to mTLS client cert file (for connect)
    let excludeRoutes: String? // comma-separated CIDRs to bypass the VPN (split tunnel)
    let adaptiveLevel: Int?   // 0=Off, 1=Light, 2=Aggressive, 3=Satellite; nil treated as 0
    let dnsProxy: String?      // local bind address for DNS proxy (e.g. "127.0.0.1:5300")
    let killSwitch: Bool?      // block all non-VPN traffic when true
    let preferredMask: String? // mask profile name, e.g. "webrtc_zoom_v3"; nil/absent = auto
    // §3 Polymorphic mask: per-session unique traffic-shape variant of a base
    // preset. When present and valid, takes precedence over preferredMask.
    let polymorphicBase: String?
    // §2 Crowdsourced mask feedback opt-ins + region hint.
    let shareMaskFeedback: Bool?
    let receiveMaskHints: Bool?
    let countryCode: String? // ISO 3166-1 alpha-2, e.g. "RU"; must be exactly 2 letters
    // Advanced/operator bootstrap discovery (for connect) — forwarded verbatim
    // to aivpn-client's --bootstrap-* / --server-signing-key flags. Only
    // relevant when the client has no working aivpn:// key yet and needs to
    // discover a server/mask via signed multi-channel fallback.
    let bootstrapCdnUrl: String?
    let bootstrapTelegramToken: String?
    let bootstrapTelegramChat: String?
    let bootstrapGithub: String?
    let serverSigningKey: String?
}

struct HelperResponse: Codable {
    let status: String       // ok, error
    let message: String
    let connected: Bool?
    let pid: Int?
    let version: String?
    let log: String?

    init(status: String, message: String,
         connected: Bool? = nil, pid: Int? = nil,
         version: String? = nil, log: String? = nil) {
        self.status = status
        self.message = message
        self.connected = connected
        self.pid = pid
        self.version = version
        self.log = log
    }
}

// MARK: - Global State

var managedPID: pid_t = 0
var isConnected = false
// Set by the child-reap handler when the MANAGED client exits: the handler
// clears managedPID immediately (so a recycled pid can never be signalled or
// reported), and this flag preserves the one-shot "Process exited" + last
// error line report that getStatus owes the GUI's next status poll.
var clientExited = false
var childReapSources: [pid_t: DispatchSourceProcess] = [:]

// Serial queue that serialises all connection state mutations (managedPID,
// isConnected, childReapSources). Declared globally so startClient's child-reap
// handler and the main accept loop both use the same queue, eliminating the data
// race that existed when the child-reap handler ran on a separate private queue.
let connectionQueue = DispatchQueue(label: "aivpn.helper.connections")

// MARK: - Logging

func log(_ message: String) {
    let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
    fputs("[\(ts)] \(message)\n", stderr)
}

// MARK: - Shell Escaping

func shellEscape(_ str: String) -> String {
    return "'" + str.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
}

// MARK: - Mask Id Validation

/// True for a well-formed mask id: lowercase alphanumerics + underscore,
/// bounded length. Matches every id the server catalog can emit (presets,
/// generated "gen_…" masks, recorded masks) without pinning a preset list.
func isAcceptableMaskId(_ id: String) -> Bool {
    return id.range(of: #"^[a-z0-9_]{1,64}$"#, options: .regularExpression) != nil
}

// MARK: - Process Management

/// Kill any existing aivpn-client process
func killExistingClient() {
    // Deliberate stop/restart: any pending exit notice is obsolete.
    clientExited = false
    if managedPID > 0 {
        let pid = managedPID
        // Exited but not yet reaped? The reap source targets this same serial
        // queue and cannot run while we're on it, so reap directly. kill(pid, 0)
        // keeps returning 0 for a zombie — the old poll loop always burned its
        // full 1s here and finished with a pointless SIGKILL.
        if waitpid(pid, nil, WNOHANG) == pid {
            log("Reaped already-exited aivpn-client (PID: \(pid))")
        } else if kill(pid, 0) == 0, pidIsAivpnClient(pid) {
            // Identity-gate before signalling: managedPID could be stale after a
            // missed reap, and a root helper must never SIGTERM a recycled pid
            // that now belongs to an unrelated process.
            log("Stopping aivpn-client (PID: \(pid))")
            kill(pid, SIGTERM)
            var gone = false
            for _ in 0..<10 {
                usleep(100_000)
                // Our own child: reap the zombie. Adopted (non-child) pid:
                // waitpid never matches, but kill(pid, 0) fails once it dies.
                if waitpid(pid, nil, WNOHANG) == pid { gone = true; break }
                if kill(pid, 0) != 0 { gone = true; break }
            }
            if !gone {
                kill(pid, SIGKILL)
                _ = waitpid(pid, nil, WNOHANG)
            }
        }
        managedPID = 0
        isConnected = false
    }

    // Check PID file for orphaned processes
    if let pidStr = try? String(contentsOfFile: PID_PATH, encoding: .utf8),
       pidStr.count <= 16 {
        let trimmed = pidStr.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pid = Int32(trimmed), pid > 0 {
            // Same recycled-PID hazard as recoverExistingClient: never signal
            // a disk-sourced pid without confirming it is our client binary.
            if kill(pid, 0) == 0, pidIsAivpnClient(pid) {
                log("Stopping orphaned aivpn-client (PID: \(pid))")
                kill(pid, SIGTERM)
                usleep(500_000)
                if kill(pid, 0) == 0 {
                    kill(pid, SIGKILL)
                }
            }
        }
    }

    try? FileManager.default.removeItem(atPath: PID_PATH)
    
    // Restore IPv6 after stopping client
    restoreIPv6()
}

/// Restore IPv6 routing after VPN disconnect.
/// The Rust client's Drop impl already removes the blackhole and restores the
/// saved interface on clean exit.  This function is a safety net for cases where
/// the client process is killed externally (e.g. `killall`).
/// We only remove the blackhole here — we do NOT try to add the default route
/// back because we don't know which interface was active (that knowledge lives
/// in the Rust process).  macOS re-discovers the IPv6 gateway automatically
/// via ND/SLAAC once the blackhole is gone.
func restoreIPv6() {
    log("Clearing IPv6 blackhole (safety net)...")

    // Remove the blackhole if it still exists.
    let removed = runCommand("/sbin/route",
                             args: ["-n", "delete", "-inet6", "-net", "::/0", "-blackhole"])
    if removed {
        log("IPv6 blackhole removed — macOS will auto-restore via ND/SLAAC")
    } else {
        log("No IPv6 blackhole found (already removed by Rust client on clean exit)")
    }
}

/// Run a command and return success
func runCommand(_ path: String, args: [String]) -> Bool {
    let task = Process()
    task.launchPath = path
    task.arguments = args
    do {
        try task.run()
        task.waitUntilExit()
        return task.terminationStatus == 0
    } catch {
        log("Command failed: \(path) \(args.joined(separator: " ")) - \(error)")
        return false
    }
}

/// Resolve the home directory of the *console* (logged-in GUI) user.
///
/// This helper runs as a root LaunchDaemon, so `NSHomeDirectory()` here is
/// `/var/root` — NOT the interactive user's home. To validate a cert path the
/// GUI app stored under the user's home we must discover the real console user
/// via SystemConfiguration + the password database.
///
/// Returns nil (fail-closed) when there is no console user (login window,
/// SSH-only session) or the lookup fails, so callers reject the path rather
/// than widening the allow-list.
func consoleUserHomeDirectory() -> String? {
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard let consoleUser = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) else {
        return nil
    }
    let username = consoleUser as String
    // "loginwindow" is the sentinel reported when nobody is logged in.
    guard !username.isEmpty, username != "loginwindow" else {
        return nil
    }
    guard let pw = getpwnam(username), let homeC = pw.pointee.pw_dir else {
        return nil
    }
    let home = String(cString: homeC)
    // Sanity: an absolute path that is not the filesystem root itself.
    guard home.hasPrefix("/"), home != "/" else {
        return nil
    }
    return home
}

/// Start aivpn-client with the given configuration using posix_spawn
func startClient(key: String, fullTunnel: Bool, binaryPath: String?, mtlsCertPath: String? = nil, excludeRoutes: String? = nil, adaptiveLevel: Int = 0, dnsProxy: String? = nil, killSwitch: Bool = false, preferredMask: String? = nil, polymorphicBase: String? = nil, shareMaskFeedback: Bool = false, receiveMaskHints: Bool = false, countryCode: String? = nil, bootstrapCdnUrl: String? = nil, bootstrapTelegramToken: String? = nil, bootstrapTelegramChat: String? = nil, bootstrapGithub: String? = nil, serverSigningKey: String? = nil) -> HelperResponse {
    killExistingClient()

    // Resolve the requested path; fall back to default
    let requestedPath = binaryPath ?? DEFAULT_CLIENT_PATH

    // Canonicalize: resolve symlinks first, then normalize ./../ components
    let resolvedPath = URL(fileURLWithPath: requestedPath)
        .resolvingSymlinksInPath().standardized.path
    let clientPath: String
    if ALLOWED_CLIENT_PATHS.contains(resolvedPath) {
        clientPath = resolvedPath
    } else if ALLOWED_CLIENT_PATHS.contains(requestedPath) {
        clientPath = requestedPath
    } else {
        log("ERROR: binaryPath '\(requestedPath)' not in allowlist — rejected")
        return HelperResponse(status: "error",
                              message: "Rejected: binary path is not permitted")
    }

    guard FileManager.default.isExecutableFile(atPath: clientPath) else {
        log("ERROR: aivpn-client not found at \(clientPath)")
        return HelperResponse(status: "error",
                              message: "aivpn-client binary not found at \(clientPath)")
    }

    // Ensure directories exist
    try? FileManager.default.createDirectory(
        atPath: (LOG_PATH as NSString).deletingLastPathComponent,
        withIntermediateDirectories: true
    )

    // Clear log
    do {
        try Data().write(to: URL(fileURLWithPath: LOG_PATH))
    } catch {
        log("WARNING: could not clear log: \(error)")
    }

    // Build arguments. The connection key (which contains the PSK) is passed
    // via the AIVPN_CONNECTION_KEY environment variable, NOT argv: argv of any
    // process is visible to every local user via `ps`, while the spawned
    // child's environment is only readable by root/same-uid. The Rust client
    // reads the env var when -k is absent (crates/aivpn-client/src/main.rs)
    // and removes it from its own environment immediately after parsing.
    var args: [String] = [clientPath]
    if fullTunnel {
        args.append("--full-tunnel")
    }
    if let certPath = mtlsCertPath {
        // Canonicalize BEFORE validation: resolve symlinks and normalize ./..
        // components so a path like "/Users/x/../../../etc/passwd" or a symlink
        // pointing outside the allowed roots cannot slip through the prefix
        // check disguised as a valid location. Mirrors the binary-path
        // canonicalization above.
        let resolvedCertPath = URL(fileURLWithPath: certPath)
            .resolvingSymlinksInPath().standardized.path

        // Build the allow-list of acceptable roots. The GUI app stores certs in
        // the *console* user's home (e.g. ~/Library/Application Support/AIVPN),
        // but this helper runs as root — NSHomeDirectory() here is /var/root,
        // NOT the logged-in user's home. Resolve the real console user's home;
        // if it can't be resolved (login window, SSH-only session, lookup
        // failure) we omit it and fall back to the system roots only — fail
        // CLOSED, never widening the allow-list to all of /Users.
        var allowedRoots = ["/etc/ssl", "/usr/local/etc"]
        if let consoleHome = consoleUserHomeDirectory() {
            allowedRoots.append(consoleHome)
        }
        // Canonicalize the roots too, so system symlinks (e.g. /etc ->
        // /private/etc) don't cause a false rejection of a valid cert.
        let allowedPrefixes = allowedRoots.map {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardized.path
        }

        // Match at a path-component boundary: the prefix itself or "prefix/...",
        // so "/etc/ssl" cannot accidentally authorize "/etc/sslmalicious".
        let withinAllowedRoot = allowedPrefixes.contains { prefix in
            resolvedCertPath == prefix || resolvedCertPath.hasPrefix(prefix + "/")
        }

        // Regex allows spaces because the app's normal store path
        // (~/Library/Application Support/AIVPN) contains one; spaces are safe
        // here since posix_spawn passes argv directly with no shell.
        let certOk = resolvedCertPath.count <= 512
            && withinAllowedRoot
            && resolvedCertPath.range(of: #"^[\w /\.\-]+\.(pem|crt|cer)$"#,
                                      options: .regularExpression) != nil
        guard certOk else {
            log("ERROR: invalid mtlsCertPath '\(certPath)' — rejected")
            return HelperResponse(status: "error", message: "Invalid mTLS cert path")
        }
        args.append("--mtls-cert")
        args.append(resolvedCertPath)
    }
    if adaptiveLevel > 0 {
        args.append("--adaptive-level")
        args.append("\(adaptiveLevel)")
    }
    if killSwitch {
        args.append("--kill-switch")
    }
    if let proxy = dnsProxy, !proxy.isEmpty {
        // Validate HOST:PORT — character whitelist + port range 1–65535.
        let proxyCharset = CharacterSet(charactersIn: "0123456789abcdefABCDEF:.[]-")
        guard proxy.unicodeScalars.allSatisfy({ proxyCharset.contains($0) }),
              let colonIdx = proxy.lastIndex(of: ":"),
              let port = Int(proxy[proxy.index(after: colonIdx)...]),
              (1...65535).contains(port) else {
            log("ERROR: invalid dnsProxy '\(proxy)' — rejected")
            return HelperResponse(status: "error", message: "Invalid dns-proxy value")
        }
        args.append("--dns-proxy")
        args.append(proxy)
    }
    if let routes = excludeRoutes {
        // Validate: each token must look like a CIDR (digits, dots, colons, slash).
        // Reject anything containing shell-special characters or path traversal.
        let tokens = routes.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let cidrCharset = CharacterSet(charactersIn: "0123456789abcdefABCDEF:./")
        let allValid = tokens.allSatisfy { token in
            !token.isEmpty && token.unicodeScalars.allSatisfy { cidrCharset.contains($0) }
        }
        guard !tokens.isEmpty && allValid else {
            log("ERROR: invalid excludeRoutes — rejected")
            return HelperResponse(status: "error", message: "Invalid exclude-routes value")
        }
        args.append("--exclude-routes")
        args.append(tokens.joined(separator: ","))
    }
    // Shared validation for both --preferred-mask and --polymorphic-base.
    // Mask ids come from the server-pushed catalog — including auto-generated
    // masks and user-recorded ones — so a fixed preset allow-list rejected
    // valid ids and hard-failed the whole connect. posix_spawn passes argv
    // directly (no shell), so a conservative character/length pattern is the
    // right gate: it excludes anything malformed while accepting every
    // catalog-shaped id.
    if let polyBase = polymorphicBase, !polyBase.isEmpty, polyBase != "auto" {
        guard isAcceptableMaskId(polyBase) else {
            log("ERROR: invalid polymorphicBase '\(polyBase)' — rejected")
            return HelperResponse(status: "error", message: "Invalid polymorphic mask base")
        }
        // §3: polymorphic-base takes precedence over --preferred-mask.
        args.append("--polymorphic-base")
        args.append(polyBase)
    } else if let mask = preferredMask, !mask.isEmpty, mask != "auto" {
        guard isAcceptableMaskId(mask) else {
            log("ERROR: invalid preferredMask '\(mask)' — rejected")
            return HelperResponse(status: "error", message: "Invalid mask profile name")
        }
        args.append("--preferred-mask")
        args.append(mask)
    }

    // §2: crowdsourced mask feedback opt-ins (bool flags, no value).
    if shareMaskFeedback {
        args.append("--share-mask-feedback")
    }
    if receiveMaskHints {
        args.append("--receive-mask-hints")
    }
    if let cc = countryCode, !cc.isEmpty {
        let normalized = cc.uppercased()
        // Require exactly two ASCII A–Z letters. `CharacterSet.uppercaseLetters`
        // also matches non-ASCII uppercase (Cyrillic/Greek/…) and `.count` is by
        // grapheme, so a 2-char non-ASCII code would slip through and reach the
        // CLI as bytes it can't validate — match the CLI's ASCII-only rule.
        if normalized.count == 2,
           normalized.allSatisfy({ $0.isASCII && $0.isLetter }) {
            args.append("--country-code")
            args.append(normalized)
        } else {
            // Non-fatal: omit the flag rather than rejecting the whole connect —
            // this is a regional hint, not a security-sensitive path/binary value.
            log("WARNING: invalid countryCode '\(cc)' — omitted")
        }
    }

    // Advanced/operator bootstrap discovery flags — forwarded verbatim to
    // aivpn-client. These aren't filesystem paths or shell commands (Process
    // passes argv directly, no shell interpretation), so we only guard
    // against obviously-malformed input: empty-after-trim, embedded control
    // characters, or unreasonable length.
    func sanitizedBootstrapArg(_ raw: String?, maxLength: Int = 2048) -> String? {
        guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }
        guard value.count <= maxLength,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return value
    }

    if let cdnUrl = sanitizedBootstrapArg(bootstrapCdnUrl) {
        args.append("--bootstrap-cdn-url")
        args.append(cdnUrl)
    }
    // The Telegram bot token is a secret — like the connection key it goes via
    // the environment (AIVPN_BOOTSTRAP_TELEGRAM_TOKEN, declared as the clap env
    // fallback for --bootstrap-telegram-token in the Rust client), not argv.
    let telegramTokenEnv = sanitizedBootstrapArg(bootstrapTelegramToken, maxLength: 256)
    if let telegramChat = sanitizedBootstrapArg(bootstrapTelegramChat, maxLength: 256) {
        args.append("--bootstrap-telegram-chat")
        args.append(telegramChat)
    }
    if let github = sanitizedBootstrapArg(bootstrapGithub, maxLength: 256) {
        args.append("--bootstrap-github")
        args.append(github)
    }
    if let signingKey = sanitizedBootstrapArg(serverSigningKey, maxLength: 128) {
        args.append("--server-signing-key")
        args.append(signingKey)
    }

    // Use posix_spawn for reliable process management
    var fileActions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&fileActions) == 0 else {
        log("ERROR: posix_spawn_file_actions_init failed")
        return HelperResponse(status: "error", message: "Internal spawn setup failure")
    }

    // Redirect stdout/stderr to log file (root-only for security)
    let logFd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0o600)
    if logFd >= 0 {
        posix_spawn_file_actions_adddup2(&fileActions, logFd, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, logFd, STDERR_FILENO)
        posix_spawn_file_actions_addclose(&fileActions, logFd)
        chmod(LOG_PATH, 0o600)
    }

    // Set RUST_LOG=info so tracing outputs info-level logs (default is ERROR only)
    // Preserve the existing PATH so we can find system binaries like ifconfig/route
    var envp: [UnsafeMutablePointer<CChar>?] = []
    
    // Copy current environment, stripping variables we set explicitly below.
    let reservedEnvKeys = ["RUST_LOG", "AIVPN_CONNECTION_KEY", "AIVPN_BOOTSTRAP_TELEGRAM_TOKEN",
                           "HOME"]
    let currentEnv = ProcessInfo.processInfo.environment
    for (envKey, value) in currentEnv where !reservedEnvKeys.contains(envKey) {
        envp.append(strdup("\(envKey)=\(value)"))
    }

    // Pin HOME to a fixed root-owned directory. The client derives its device
    // identity (device.key) from a path under $HOME — but this daemon's own
    // HOME is unset (launchd) or whatever the installer session had (the
    // postinstall nohup fallback), so the identity silently changed between
    // launch paths and the server saw a "second device" and dropped the peer.
    let stateHome = "/Library/Application Support/AIVPN"
    if !FileManager.default.fileExists(atPath: stateHome) {
        try? FileManager.default.createDirectory(
            atPath: stateHome,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    // Force RUST_LOG=info — prevents leaked debug/trace output to the log file
    envp.append(strdup("RUST_LOG=info"))
    envp.append(strdup("HOME=\(stateHome)"))
    // Secrets via env, not argv (see comment at the args declaration above).
    envp.append(strdup("AIVPN_CONNECTION_KEY=\(key)"))
    if let telegramToken = telegramTokenEnv {
        envp.append(strdup("AIVPN_BOOTSTRAP_TELEGRAM_TOKEN=\(telegramToken)"))
    }
    envp.append(nil)

    var pid: pid_t = 0
    let argv = args.map { strdup($0) } + [nil]
    precondition(!argv.isEmpty, "argv must not be empty")

    let spawnResult = argv.withUnsafeBufferPointer { ptr in
        guard let base = ptr.baseAddress else {
            fatalError("argv buffer has no base address")
        }
        return envp.withUnsafeMutableBufferPointer { envPtr in
            posix_spawn(&pid, clientPath, &fileActions, nil,
                        UnsafeMutablePointer(mutating: base),
                        UnsafeMutablePointer(mutating: envPtr.baseAddress))
        }
    }

    // Free strdup'd strings
    for arg in argv { free(arg) }
    for envVar in envp {
        if let ptr = envVar {
            free(ptr)
        }
    }
    posix_spawn_file_actions_destroy(&fileActions)
    if logFd >= 0 { close(logFd) }

    if spawnResult != 0 {
        log("ERROR: posix_spawn failed: \(String(cString: strerror(spawnResult)))")
        return HelperResponse(status: "error",
                              message: "Failed to start client: \(String(cString: strerror(spawnResult)))")
    }

    managedPID = pid
    isConnected = false
    try? "\(pid)".write(toFile: PID_PATH, atomically: true, encoding: .utf8)
    log("Started aivpn-client (PID: \(pid))")

    // Reap child on exit to prevent zombie accumulation.
    // The source must be stored globally — a local variable would be released by ARC
    // immediately after startClient() returns, cancelling the source before it fires.
    // Use connectionQueue so the handler accesses childReapSources on the same serial
    // queue as startClient / handleConnection — eliminates the previous data race.
    let childSource = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit,
                                                       queue: connectionQueue)
    childSource.setEventHandler {
        waitpid(pid, nil, WNOHANG)
        childSource.cancel()
        childReapSources.removeValue(forKey: pid)
        // Forget the dead client immediately. Leaving managedPID set meant
        // getStatus kept "verifying" a pid that the kernel could recycle, and a
        // later disconnect would SIGTERM/SIGKILL an innocent process as root.
        // clientExited preserves the one-shot "Process exited" report for the
        // GUI's next status poll (see getStatus).
        if pid == managedPID {
            managedPID = 0
            isConnected = false
            clientExited = true
            try? FileManager.default.removeItem(atPath: PID_PATH)
        }
    }
    childSource.resume()
    childReapSources[pid] = childSource

    // A client that exits INSTANTLY (bad key, spawn into a broken env, …) can
    // be dead before the process source above was registered — a process source
    // does not fire for an already-exited pid, so the zombie would never be
    // reaped and status would say "Connecting..." forever. One synchronous
    // WNOHANG check closes the gap; the event handler cannot have run yet
    // (it targets this same serial queue), so reaping here is race-free.
    if waitpid(pid, nil, WNOHANG) == pid {
        childSource.cancel()
        childReapSources.removeValue(forKey: pid)
        managedPID = 0
        isConnected = false
        clientExited = true
        try? FileManager.default.removeItem(atPath: PID_PATH)
        log("aivpn-client (PID: \(pid)) exited immediately after spawn")
    }

    return HelperResponse(status: "ok", message: "Client started", pid: Int(pid))
}

func runClientCommand(args: [String], binaryPath: String?) -> HelperResponse {
    let requestedPath = binaryPath ?? DEFAULT_CLIENT_PATH
    let resolvedPath = URL(fileURLWithPath: requestedPath)
        .resolvingSymlinksInPath().standardized.path
    let clientPath: String
    if ALLOWED_CLIENT_PATHS.contains(resolvedPath) {
        clientPath = resolvedPath
    } else if ALLOWED_CLIENT_PATHS.contains(requestedPath) {
        clientPath = requestedPath
    } else {
        log("ERROR: runClientCommand binaryPath '\(requestedPath)' not in allowlist — rejected")
        return HelperResponse(status: "error", message: "Rejected: binary path is not permitted")
    }

    guard FileManager.default.isExecutableFile(atPath: clientPath) else {
        return HelperResponse(status: "error", message: "aivpn-client binary not found at \(clientPath)")
    }

    let task = Process()
    task.executableURL = URL(fileURLWithPath: clientPath)
    task.arguments = args

    let outputPipe = Pipe()
    task.standardOutput = outputPipe
    task.standardError = outputPipe

    // Drain the pipe CONCURRENTLY with the child's execution. Reading only
    // after waitUntilExit deadlocks once the child writes more than the pipe
    // buffer (~64KB): the child blocks on write, we block on wait — and this
    // runs on the helper's single serial queue, wedging the daemon forever.
    var outputData = Data()
    let drainDone = DispatchSemaphore(value: 0)
    let readHandle = outputPipe.fileHandleForReading
    DispatchQueue.global(qos: .utility).async {
        outputData = readHandle.readDataToEndOfFile()
        drainDone.signal()
    }

    do {
        try task.run()
    } catch {
        // Unblock the drain: with no child holding the write end, EOF only
        // arrives after we close our own copy.
        outputPipe.fileHandleForWriting.closeFile()
        _ = drainDone.wait(timeout: .now() + 1)
        return HelperResponse(status: "error", message: "Failed to run client command: \(error.localizedDescription)")
    }

    // Bounded wait: record subcommands are a local control-socket round-trip
    // and complete in well under a second. If the child hangs, kill it rather
    // than blocking the helper's serial queue indefinitely.
    let deadline = Date().addingTimeInterval(10)
    while task.isRunning && Date() < deadline {
        usleep(100_000)
    }
    if task.isRunning {
        log("WARNING: client command timed out — terminating")
        task.terminate()
        usleep(500_000)
        if task.isRunning {
            kill(task.processIdentifier, SIGKILL)
        }
    }
    task.waitUntilExit()
    // After exit every write end is closed, so the drain finishes promptly;
    // the timeout is a belt-and-braces bound, not an expected path.
    _ = drainDone.wait(timeout: .now() + 2)
    let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

    if task.terminationStatus == 0 {
        return HelperResponse(status: "ok", message: output.isEmpty ? "Command sent to client daemon." : output)
    }

    return HelperResponse(status: "error", message: output.isEmpty ? "Client command failed" : output)
}

/// Stop the managed aivpn-client process
func stopClient() -> HelperResponse {
    let wasConnected = isConnected
    killExistingClient()
    log("Client stopped")
    return HelperResponse(status: "ok",
                          message: wasConnected ? "Disconnected" : "No active connection")
}

/// True while the client's data-plane evidence is FRESH: the traffic.stats
/// file carries a session `since:` epoch (the pre-session zero-writes in the
/// client's reconnect loop deliberately omit it) and was rewritten recently —
/// the client's stats task rewrites it once per second while a session is up.
/// Stale/absent evidence means the client is between sessions (in-process
/// reconnect loop), even though historic log lines still say "Connected".
func connectionEvidenceFresh(maxAgeSeconds: TimeInterval = 10) -> Bool {
    let statsPath = "/var/run/aivpn/traffic.stats"
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: statsPath),
          let mtime = attrs[.modificationDate] as? Date,
          Date().timeIntervalSince(mtime) <= maxAgeSeconds else { return false }
    guard let stats = try? String(contentsOfFile: statsPath, encoding: .utf8),
          stats.contains("since:") else { return false }
    return true
}

/// G-A4: scans `logContent` (most recent line first) for the client's
/// machine-readable `"AIVPN-STATUS rejected <token>"` stdout line — printed
/// exactly once, right before the client exits, by the `HandshakeReject`
/// arm in crates/aivpn-client/src/client.rs (`handshake_reject_token()`
/// there defines the token set: one_time_used/expired/disabled/
/// unspecified). Returns the raw token (never the surrounding line) so the
/// GUI (VPNManager.pollStatus) can localize it without depending on the
/// client's English log wording — mirrors how the Linux/Windows GUIs parse
/// the same line straight off the child process's stdout; this daemon
/// instead redirects that stdout into `LOG_PATH` (see `startClient`), so
/// `getStatus()` has to recover the line from the log file instead.
func rejectToken(in logContent: String) -> String? {
    let prefix = "AIVPN-STATUS rejected "
    for line in logContent.components(separatedBy: "\n").reversed() {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix(prefix) {
            let token = String(trimmed.dropFirst(prefix.count))
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return token.isEmpty ? "unspecified" : token
        }
    }
    return nil
}

/// Decides Connected/not from the MOST RECENT transition line in the log.
/// A `contains` over the whole log latched Connected forever once any historic
/// line matched — even while the client was midway through its in-process
/// reconnect loop ("Client run failed … Reconnecting in …").
func lastLogTransitionIsConnected(_ logContent: String) -> Bool {
    let connectedMarkers = ["Connected to server", "PFS ratchet complete",
                            "forward secrecy established"]
    let disconnectedMarkers = ["Reconnecting in", "Client run failed",
                               "Failed to create client", "Shutdown requested"]
    for line in logContent.components(separatedBy: "\n").reversed() {
        if connectedMarkers.contains(where: { line.contains($0) }) { return true }
        if disconnectedMarkers.contains(where: { line.contains($0) }) { return false }
    }
    return false
}

/// Get current connection status
func getStatus() -> HelperResponse {
    if managedPID > 0 && kill(managedPID, 0) == 0 {
        if isConnected {
            if connectionEvidenceFresh() {
                return HelperResponse(status: "ok", message: "Connected",
                                      connected: true, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }
            // Data-plane evidence went stale: the client is re-establishing
            // in-process. Demote instead of reporting a stale Connected, and
            // fall through to the log-derived state below.
            isConnected = false
        }
        // Check log for connection status
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            // G-A4: an authenticated terminal refusal takes priority over
            // both the Connected-transition check and the generic
            // error-line fallback below. The client always exits right
            // after printing this line (see rejectToken's doc comment), so
            // by the time this poll runs the process may already be gone —
            // checking here (while the pid was still recognized alive a few
            // lines up) catches it the SAME poll cycle instead of racing the
            // "process exited" branch further down for one extra 2s tick.
            if let token = rejectToken(in: logContent) {
                return HelperResponse(status: "ok", message: "AIVPN-STATUS rejected \(token)",
                                      connected: false, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }
            if lastLogTransitionIsConnected(logContent), connectionEvidenceFresh() {
                isConnected = true
                return HelperResponse(status: "ok", message: "Connected",
                                      connected: true, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }
            if logContent.contains("Created TUN device") {
                return HelperResponse(status: "ok", message: "Establishing tunnel...",
                                      connected: false, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }

            // Check for repeated errors — if last non-empty line is an error, report it
            let lines = logContent.components(separatedBy: "\n").filter { !$0.isEmpty }
            if let lastLine = lines.last {
                // Strip ANSI escape codes (actual \x1b byte, not literal text)
                let cleanLine = lastLine.replacingOccurrences(
                    of: "\u{001b}\\[[0-9;]*m", with: "", options: .regularExpression
                )
                if isErrorLogLine(cleanLine) {
                    // Extract just the error message
                    let errorMsg: String
                    if let range = cleanLine.range(of: "ERROR") {
                        errorMsg = String(cleanLine[range.lowerBound...]).trimmingCharacters(
                            in: .whitespacesAndNewlines
                        )
                    } else {
                        errorMsg = cleanLine.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                    return HelperResponse(status: "ok", message: errorMsg,
                                          connected: false, pid: Int(managedPID),
                                          version: HELPER_VERSION)
                }
            }
        }
        return HelperResponse(status: "ok", message: "Connecting...",
                              connected: false, pid: Int(managedPID),
                              version: HELPER_VERSION)
    }

    // Process not running. clientExited covers the (normal) case where the
    // child-reap handler already cleared managedPID: the one-shot
    // "Process exited" + last-error report below is what lets the GUI turn
    // "Connecting…" into a visible failure.
    if managedPID > 0 || clientExited {
        managedPID = 0
        isConnected = false
        clientExited = false
        try? FileManager.default.removeItem(atPath: PID_PATH)

        var errorMsg = "Process exited"
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            // G-A4: same priority as the still-alive branch above — this is
            // the path that normally wins the race (the client's own
            // `terminal_rejected` break in main.rs exits the process right
            // after printing the line, so by the next poll it's usually
            // already reaped here rather than caught above).
            if let token = rejectToken(in: logContent) {
                errorMsg = "AIVPN-STATUS rejected \(token)"
            } else {
                let lines = logContent.components(separatedBy: "\n").filter { !$0.isEmpty }
                if let last = lines.last {
                    let cleanLast = last.replacingOccurrences(
                        of: "\u{001b}\\[[0-9;]*m", with: "", options: .regularExpression
                    )
                    // Level-token match only — a plain substring "error" would
                    // misreport ordinary INFO lines (URLs, counters) as failures.
                    if isErrorLogLine(cleanLast) {
                        errorMsg = String(cleanLast.prefix(200))
                    }
                }
            }
        }
        return HelperResponse(status: "ok", message: errorMsg,
                              connected: false, version: HELPER_VERSION)
    }

    return HelperResponse(status: "ok", message: "Idle",
                          connected: false, version: HELPER_VERSION)
}

/// True while the managed aivpn-client process is alive.
func clientProcessAlive() -> Bool {
    return managedPID > 0 && kill(managedPID, 0) == 0
}

/// Trim LOG_PATH to its last 500 lines — but ONLY when no client is running.
/// The client writes through an O_APPEND fd inherited at spawn; an atomic
/// (temp+rename) rewrite would detach that fd from the visible file, freezing
/// status/traffic/error reporting for the rest of the session. While a client
/// is alive the log is left alone (it is cleared in startClient before every
/// spawn anyway); when trimming, write in place (atomically: false) so the
/// inode is preserved as an extra safety.
func trimLogIfSafe(_ lines: [String]) {
    guard lines.count > 500, !clientProcessAlive() else { return }
    let kept = lines.suffix(500).joined(separator: "\n")
    try? kept.write(toFile: LOG_PATH, atomically: false, encoding: .utf8)
}

/// True when an (ANSI-stripped) log line is an actual ERROR-level record: the
/// tracing level token at/near the start of the line ("2026-…Z ERROR target: …"
/// or a line starting with "ERROR"), not merely the substring "error" anywhere
/// in the text — URLs, "0 errors", masked hostnames etc. must not count.
func isErrorLogLine(_ line: String) -> Bool {
    if line.hasPrefix("ERROR") { return true }
    return line.range(of: #"^\S+\s+ERROR\s"#, options: .regularExpression) != nil
}

/// Get recent log entries
func getLog() -> HelperResponse {
    guard let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) else {
        return HelperResponse(status: "ok", message: "No log",
                              connected: isConnected,
                              pid: managedPID > 0 ? Int(managedPID) : nil, log: "")
    }
    let lines = logContent.components(separatedBy: "\n")
    // Keep log file bounded so it doesn't grow unboundedly over a long session
    trimLogIfSafe(lines)
    let recent = lines.suffix(50).joined(separator: "\n")
    return HelperResponse(status: "ok", message: "Log retrieved",
                          connected: isConnected,
                          pid: managedPID > 0 ? Int(managedPID) : nil,
                          log: recent)
}

private func readQualityScore() -> String {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: "/var/run/aivpn/quality.json")),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let q = json["quality"] as? Int else { return "" }
    var result = ",quality:\(q)"
    if let a = json["adaptive"] as? Int { result += ",adaptive:\(a)" }
    return result
}

/// Get traffic statistics
func getTrafficStats() -> HelperResponse {
    // Try to read stats file first
    let statsPath = "/var/run/aivpn/traffic.stats"
    if let statsContent = try? String(contentsOfFile: statsPath, encoding: .utf8) {
        // Format: "sent:X,received:Y"
        let trimmed = statsContent.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("sent:") && trimmed.contains("received:") {
            return HelperResponse(status: "ok", message: trimmed + readQualityScore())
        }
    }
    
    // Fallback: parse last 100 lines of log. APPROXIMATE by construction —
    // the same historical "Sent N"/"received N" lines are re-summed on every
    // poll, so totals can double-count and jump around. Only used when the
    // stats file is missing entirely (very old client); the fresh stats file
    // above is always preferred.
    guard let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) else {
        return HelperResponse(status: "ok", message: "sent:0,received:0")
    }
    
    let lines = logContent.components(separatedBy: "\n")
    let recentLines = lines.suffix(100)
    
    var totalSent: Int64 = 0
    var totalReceived: Int64 = 0
    
    for line in recentLines {
        if line.contains("Sent") {
            let parts = line.components(separatedBy: " ")
            for (i, part) in parts.enumerated() {
                if part == "Sent" && i + 1 < parts.count {
                    if let bytes = Int64(parts[i + 1]) {
                        totalSent += bytes
                    }
                }
            }
        }
        if line.contains("received") || line.contains("Read") {
            let parts = line.components(separatedBy: " ")
            for (i, part) in parts.enumerated() {
                if (part == "received" || part == "Read") && i + 1 < parts.count {
                    if let bytes = Int64(parts[i + 1]) {
                        totalReceived += bytes
                    }
                }
            }
        }
    }
    
    // Trim log file if too large (no-op while the client holds its O_APPEND fd)
    trimLogIfSafe(lines)


    return HelperResponse(status: "ok", message: "sent:\(totalSent),received:\(totalReceived)\(readQualityScore())")
}

/// Reads a small status file with symlink hardening: opens with O_NOFOLLOW
/// (refuses to follow a symlink at the final path component) and O_CLOEXEC,
/// verifies the opened fd is a plain regular file via fstat (rejects FIFOs/
/// devices/sockets too), and caps the read at maxBytes. Needed specifically
/// for RECORDING_STATUS_FALLBACK_PATH, which lives directly under the
/// world-writable /tmp: without this, a local console-user attacker could
/// pre-create that path as a symlink to any root-readable file (e.g.
/// another user's SSH key) and have this root helper read it back and echo
/// it over the IPC socket via a hand-crafted record_info request. Also used
/// for the root-owned primary path for defense-in-depth/consistency, even
/// though /var/run/aivpn is not attacker-writable.
func readRegularFileNoFollow(_ path: String, maxBytes: Int = 65536) -> Data? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return nil }
    defer { close(fd) }

    var st = stat()
    // st.st_mode is mode_t; wrap the S_IFMT/S_IFREG macros in mode_t(...) so
    // this compiles regardless of which integer type the Clang importer
    // picked for them (both are small enough to convert losslessly either way).
    guard fstat(fd, &st) == 0, (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
        log("WARNING: refusing to read \(path) — not a regular file (symlink or other special file)")
        return nil
    }
    guard st.st_size >= 0 && st.st_size <= Int64(maxBytes) else {
        log("WARNING: refusing to read \(path) — size \(st.st_size) exceeds \(maxBytes)-byte cap")
        return nil
    }

    let toRead = Int(st.st_size)
    guard toRead > 0 else { return Data() }
    var buf = [UInt8](repeating: 0, count: toRead)
    let n = buf.withUnsafeMutableBytes { bytes -> Int in
        read(fd, bytes.baseAddress, toRead)
    }
    guard n > 0 else { return nil }
    return Data(buf[0..<n])
}

func getRecordingInfo() -> HelperResponse {
    if let data = readRegularFileNoFollow(RECORDING_STATUS_PATH),
       let json = String(data: data, encoding: .utf8) {
        return HelperResponse(status: "ok", message: json)
    }
    if let data = readRegularFileNoFollow(RECORDING_STATUS_FALLBACK_PATH),
       let json = String(data: data, encoding: .utf8) {
        return HelperResponse(status: "ok", message: json)
    }
    return HelperResponse(status: "ok", message: "{\"can_record\":null,\"state\":\"idle\",\"service\":null,\"message\":\"Recording access not checked yet\",\"mask_id\":null,\"confidence\":null,\"updated_at_ms\":0}")
}

// MARK: - Socket Helpers

/// Build a sockaddr_un for the given path
func makeSockAddr(_ path: String) -> sockaddr_un {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { buf in
        for (i, byte) in pathBytes.enumerated() where i < buf.count - 1 {
            buf[i] = byte
        }
    }
    return addr
}

// MARK: - Socket Server

/// Create and bind the Unix domain socket
func createSocket() -> Int32 {
    let socketDir = (SOCKET_PATH as NSString).deletingLastPathComponent
    do {
        try FileManager.default.createDirectory(atPath: socketDir,
                                                withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755],
                                              ofItemAtPath: socketDir)
    } catch {
        log("WARNING: Could not create socket dir: \(error)")
    }

    // Remove stale socket
    try? FileManager.default.removeItem(atPath: SOCKET_PATH)

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        log("ERROR: socket() failed: \(String(cString: strerror(errno)))")
        return -1
    }

    var addrBuf = makeSockAddr(SOCKET_PATH)
    let bindResult = withUnsafePointer(to: &addrBuf) {
        bind(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self),
             socklen_t(MemoryLayout<sockaddr_un>.size))
    }
    guard bindResult == 0 else {
        log("ERROR: bind() failed: \(String(cString: strerror(errno)))")
        close(fd)
        return -1
    }

    guard listen(fd, 5) == 0 else {
        log("ERROR: listen() failed: \(String(cString: strerror(errno)))")
        close(fd)
        return -1
    }

    // Restrict socket to owner only; chown to the console user so the GUI app
    // (running as the logged-in user, not root) can connect. 0o666 would expose
    // the socket — and any connection key/PSK it carries — to all local processes.
    try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                            ofItemAtPath: SOCKET_PATH)
    var consoleUID: uid_t = 0
    var consoleGID: gid_t = 0
    if SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) != nil {
        chown(SOCKET_PATH, consoleUID, consoleGID)
    }

    return fd
}

/// Read exactly `count` bytes from `fd`, returning nil on EOF/error/timeout.
func readExact(_ fd: Int32, count: Int) -> Data? {
    var buf = [UInt8](repeating: 0, count: count)
    var total = 0
    while total < count {
        let n = buf.withUnsafeMutableBytes { bytes in
            read(fd, bytes.baseAddress!.advanced(by: total), count - total)
        }
        if n <= 0 { return nil }
        total += n
    }
    return Data(buf)
}

// MARK: Peer code-signing verification
//
// The euid check in peerIsAuthorized proves only WHO the peer runs as, not
// WHAT it is: without a code-signing check, ANY process in the console user's
// session (malware, a script) could drive this root helper — spawn
// aivpn-client as root against an attacker-controlled server (full MITM),
// toggle kill-switch, etc. So we additionally pin the peer to the legitimate
// signed AIVPN.app: fetch its audit token via getsockopt(SOL_LOCAL,
// LOCAL_PEERTOKEN), build a SecCode for that token with
// SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit) and evaluate a
// code-signing requirement (bundle id + Team ID) with SecCodeCheckValidity.
// The audit token — unlike a bare pid — is immune to pid-reuse races.
// kSecGuestAttributeAudit is public API since macOS 10.14.

// Values from <sys/un.h> (verified against apple-oss-distributions/xnu);
// declared locally because the C macros are not reliably re-exported to Swift.
let AIVPN_SOL_LOCAL: Int32 = 0          // SOL_LOCAL
let AIVPN_LOCAL_PEERTOKEN: Int32 = 0x006 // LOCAL_PEERTOKEN — "retrieve peer audit token"

// SECURITY(TODO): set to the REAL Apple Developer Team ID that signs
// AIVPN.app before any production distribution, once that identity is known
// (it is not discoverable from this repository — the app is signed outside
// the repo). Setting it here is the recommended path for Developer-ID/App
// Store distribution: it pins peers to a specific, operator-chosen identity
// independent of whatever key happened to sign the running helper binary.
let REQUIRED_PEER_TEAM_ID = ""
let REQUIRED_PEER_BUNDLE_ID = "com.aivpn.client" // CFBundleIdentifier of AIVPN.app

/// Reads the Team Identifier from the CURRENTLY RUNNING helper binary's own
/// code signature (SecCodeCopySelf → SecCodeCopyStaticCode →
/// SecCodeCopySigningInformation, keyed on kSecCodeInfoTeamIdentifier — API
/// shapes verified against apple-oss-distributions/Security SecCode.h).
/// Used only as the fallback peer-pinning identity when
/// REQUIRED_PEER_TEAM_ID above is left unconfigured: it lets the helper
/// self-configure to "peer must be signed by whoever signed me" instead of
/// requiring a hardcoded constant. Returns nil (and logs why) if the helper
/// itself is unsigned/ad-hoc-signed (e.g. `codesign --sign -`, which is what
/// build.sh currently produces) or on any Security API failure — callers
/// must treat nil as "no identity available", not as "skip the check".
func selfTeamIdentifier() -> String? {
    var selfCode: SecCode?
    guard SecCodeCopySelf(SecCSFlags(), &selfCode) == errSecSuccess, let code = selfCode else {
        log("WARNING: SecCodeCopySelf failed — cannot determine helper's own Team ID")
        return nil
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
          let sCode = staticCode else {
        log("WARNING: SecCodeCopyStaticCode failed — cannot determine helper's own Team ID")
        return nil
    }
    var info: CFDictionary?
    // kSecCSSigningInformation is declared as a bare (untyped) enum constant
    // in SecCode.h, not pre-typed as SecCSFlags — go through
    // SecCSFlags.RawValue(...) rather than assuming its imported Swift type
    // matches SecCSFlags.RawValue (UInt32) exactly.
    guard SecCodeCopySigningInformation(sCode, SecCSFlags(rawValue: SecCSFlags.RawValue(kSecCSSigningInformation)),
                                        &info) == errSecSuccess,
          let dict = info as? [String: Any] else {
        log("WARNING: SecCodeCopySigningInformation failed — cannot determine helper's own Team ID")
        return nil
    }
    guard let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String, !teamID.isEmpty else {
        log("WARNING: running helper binary has no Team ID in its own code signature (unsigned or ad-hoc signed) — cannot self-pin peer identity")
        return nil
    }
    return teamID
}

/// The Team ID actually enforced against socket peers: the operator-set
/// REQUIRED_PEER_TEAM_ID if non-empty, else the helper's own signing Team ID
/// (resolved once, at first use). nil means NO identity is available, in
/// which case peerCodeSignatureIsValid fails closed — this constant is never
/// allowed to silently disable the check the way the old empty-string
/// short-circuit did.
let EFFECTIVE_PEER_TEAM_ID: String? = {
    if !REQUIRED_PEER_TEAM_ID.isEmpty {
        return REQUIRED_PEER_TEAM_ID
    }
    if let own = selfTeamIdentifier() {
        log("Peer code-signature check: REQUIRED_PEER_TEAM_ID not set — pinning peers to the helper's own Team ID (\(own)).")
        return own
    }
    log("WARNING: peer code-signature check has NO Team ID to enforce (REQUIRED_PEER_TEAM_ID unset and the helper binary itself is unsigned/ad-hoc). Failing CLOSED: every peer connection will be rejected until the helper is signed with a real Developer ID (or REQUIRED_PEER_TEAM_ID is set).")
    return nil
}()

/// Verifies the socket peer's code signature against a requirement pinning
/// the AIVPN.app bundle id + Team ID. Fails closed on every error path,
/// INCLUDING when no Team ID is configured/available at all (see
/// EFFECTIVE_PEER_TEAM_ID) — an unconfigured Team ID no longer disables this
/// check, it makes it reject everyone.
func peerCodeSignatureIsValid(_ fd: Int32) -> Bool {
    guard let requiredTeamID = EFFECTIVE_PEER_TEAM_ID else {
        log("WARNING: rejecting connection — no Team ID configured to verify the peer against (fail closed).")
        return false
    }

    var token = audit_token_t()
    var tokenLen = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, AIVPN_SOL_LOCAL, AIVPN_LOCAL_PEERTOKEN, &token, &tokenLen) == 0,
          tokenLen == socklen_t(MemoryLayout<audit_token_t>.size) else {
        log("WARNING: getsockopt(LOCAL_PEERTOKEN) failed (\(String(cString: strerror(errno)))) — rejecting connection")
        return false
    }
    let tokenData = withUnsafeBytes(of: token) { Data($0) }

    var guest: SecCode?
    let attrs: [CFString: Any] = [kSecGuestAttributeAudit: tokenData]
    let guestStatus = SecCodeCopyGuestWithAttributes(nil, attrs as CFDictionary,
                                                     SecCSFlags(), &guest)
    guard guestStatus == errSecSuccess, let code = guest else {
        log("WARNING: SecCodeCopyGuestWithAttributes failed (\(guestStatus)) — rejecting connection")
        return false
    }

    // Standard designated-requirement shape: Apple anchor, our bundle id, and
    // either an App Store leaf or a Developer ID chain with our Team ID.
    let requirementText =
        "anchor apple generic and identifier \"\(REQUIRED_PEER_BUNDLE_ID)\" and " +
        "(certificate leaf[field.1.2.840.113635.100.6.1.9] /* App Store */ or " +
        "certificate 1[field.1.2.840.113635.100.6.2.6] /* Developer ID CA */ and " +
        "certificate leaf[field.1.2.840.113635.100.6.1.13] /* Developer ID leaf */ and " +
        "certificate leaf[subject.OU] = \"\(requiredTeamID)\")"
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(requirementText as CFString, SecCSFlags(),
                                         &requirement) == errSecSuccess,
          let req = requirement else {
        log("WARNING: SecRequirementCreateWithString failed — rejecting connection")
        return false
    }

    let status = SecCodeCheckValidity(code, SecCSFlags(), req)
    guard status == errSecSuccess else {
        log("WARNING: peer code-signature check failed (\(status)) — rejecting connection")
        return false
    }
    return true
}

/// Defense-in-depth peer-credential check (LOCAL_PEERCRED via getpeereid).
/// The socket is already chmod 0600 + chown'd to the console user (see
/// createSocket), but file permissions alone are not a complete control:
/// an inherited/passed fd or a window where the console user changes would
/// bypass them. Verify the actual peer euid on every accepted connection and
/// only allow root (0) or the current console user — and for the console
/// user, additionally require the peer to BE the signed AIVPN.app
/// (peerCodeSignatureIsValid above). Fails closed on any error.
func peerIsAuthorized(_ fd: Int32) -> Bool {
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard getpeereid(fd, &uid, &gid) == 0 else {
        log("WARNING: getpeereid failed (\(String(cString: strerror(errno)))) — rejecting connection")
        return false
    }
    if uid == 0 { return true }
    var consoleUID: uid_t = 0
    var consoleGID: gid_t = 0
    guard SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) != nil else {
        log("WARNING: no console user — rejecting connection from uid \(uid)")
        return false
    }
    guard uid == consoleUID else {
        log("WARNING: rejected connection from uid \(uid) (console uid \(consoleUID))")
        return false
    }
    // euid alone is identity, not integrity: require the legitimate app.
    return peerCodeSignatureIsValid(fd)
}

/// Handle a single client connection
func handleConnection(_ clientFD: Int32) {
    // Reject peers that are neither root nor the console user before reading
    // any request bytes. The caller closes clientFD after we return.
    guard peerIsAuthorized(clientFD) else { return }

    // 5-second read AND write timeouts. Connections are handled on a serial
    // queue: a single write() blocked forever on a stalled peer would wedge
    // the queue and make the helper unreachable while launchd still reports
    // it running.
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO,
               &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(clientFD, SOL_SOCKET, SO_SNDTIMEO,
               &timeout, socklen_t(MemoryLayout<timeval>.size))

    // Read 4-byte big-endian length prefix
    guard let lenBytes = readExact(clientFD, count: 4) else { return }
    let payloadLen = Int(lenBytes[0]) << 24 | Int(lenBytes[1]) << 16
                   | Int(lenBytes[2]) << 8  | Int(lenBytes[3])
    guard payloadLen > 0 && payloadLen <= 65535 else {
        sendResponse(clientFD, HelperResponse(status: "error", message: "Invalid message length"))
        return
    }

    // Read exactly payloadLen bytes
    guard let data = readExact(clientFD, count: payloadLen) else { return }

    guard let request = try? JSONDecoder().decode(HelperRequest.self, from: data) else {
        sendResponse(clientFD, HelperResponse(status: "error", message: "Invalid JSON"))
        return
    }

    log("Action: \(request.action)")

    let response: HelperResponse
    switch request.action {
    case "connect":
        guard let key = request.key, !key.isEmpty else {
            response = HelperResponse(status: "error", message: "Missing connection key")
            break
        }
        response = startClient(key: key,
                               fullTunnel: request.fullTunnel ?? false,
                               binaryPath: request.binaryPath,
                               mtlsCertPath: request.mtlsCertPath,
                               excludeRoutes: request.excludeRoutes,
                               adaptiveLevel: request.adaptiveLevel ?? 0,
                               dnsProxy: request.dnsProxy,
                               killSwitch: request.killSwitch ?? false,
                               preferredMask: request.preferredMask,
                               polymorphicBase: request.polymorphicBase,
                               shareMaskFeedback: request.shareMaskFeedback ?? false,
                               receiveMaskHints: request.receiveMaskHints ?? false,
                               countryCode: request.countryCode,
                               bootstrapCdnUrl: request.bootstrapCdnUrl,
                               bootstrapTelegramToken: request.bootstrapTelegramToken,
                               bootstrapTelegramChat: request.bootstrapTelegramChat,
                               bootstrapGithub: request.bootstrapGithub,
                               serverSigningKey: request.serverSigningKey)

    case "disconnect":
        response = stopClient()

    case "status":
        response = getStatus()

    case "ping":
        // pid is included whenever a managed client process exists (even if
        // not connected yet) so the GUI can decide whether status polling is
        // worthwhile — an idle helper (no pid) needs no 2s poll loop.
        let clientAlive = managedPID > 0 && kill(managedPID, 0) == 0
        response = HelperResponse(status: "ok", message: "pong",
                                  connected: isConnected && clientAlive,
                                  pid: clientAlive ? Int(managedPID) : nil,
                                  version: HELPER_VERSION)

    case "log":
        response = getLog()

    case "traffic":
        response = getTrafficStats()

    case "record_start":
        guard let service = request.service, !service.isEmpty else {
            response = HelperResponse(status: "error", message: "Missing recording service name")
            break
        }
        guard service.count <= 128,
              service.range(of: #"^[a-zA-Z0-9 _\-]{1,128}$"#, options: .regularExpression) != nil else {
            response = HelperResponse(status: "error", message: "Invalid recording service name")
            break
        }
        response = runClientCommand(args: ["record", "start", "--service", service], binaryPath: request.binaryPath)

    case "record_stop":
        response = runClientCommand(args: ["record", "stop"], binaryPath: request.binaryPath)

    case "record_status":
        // Asks the running client daemon to refresh recording.status. Must be
        // executed BY this root helper: the record CLI authenticates against a
        // per-uid admin token/socket (/tmp/aivpn-<uid>), and the full-tunnel
        // client runs as uid 0 — a console-user invocation targets
        // /tmp/aivpn-501 where no daemon listens and is always rejected.
        response = runClientCommand(args: ["record", "status"], binaryPath: request.binaryPath)

    case "record_info":
        response = getRecordingInfo()

    default:
        response = HelperResponse(status: "error",
                                  message: "Unknown action: \(request.action)")
    }

    sendResponse(clientFD, response)
}

/// Send a JSON response to the client
func sendResponse(_ clientFD: Int32, _ response: HelperResponse) {
    guard let responseData = try? JSONEncoder().encode(response) else {
        log("ERROR: failed to encode response for action (status: \(response.status))")
        return
    }

    var sent = 0
    let total = responseData.count
    responseData.withUnsafeBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        while sent < total {
            let n = write(clientFD, base.advanced(by: sent), total - sent)
            if n <= 0 { return }
            sent += n
        }
    }
}

// MARK: - Signal Handling
//
// A raw signal(2) handler may only call async-signal-safe functions — the old
// handler called log()/FileManager/usleep and mutated managedPID from signal
// context, all of which are undefined behaviour (e.g. deadlock inside malloc).
// Instead: ignore the signal at the C level and turn delivery into a normal
// DispatchSource event, whose handler runs on connectionQueue — the same serial
// queue that owns managedPID/childReapSources — so the full cleanup path is safe.

// Must be retained globally: a released source is cancelled and never fires.
var signalSources: [DispatchSourceSignal] = []

func setupSignals() {
    signal(SIGHUP, SIG_IGN)
    // A peer that closes mid-response must produce EPIPE from write(), not
    // kill the whole daemon with the default SIGPIPE action.
    signal(SIGPIPE, SIG_IGN)
    for sig in [SIGTERM, SIGINT] {
        signal(sig, SIG_IGN) // required so default termination doesn't preempt the source
        let source = DispatchSource.makeSignalSource(signal: sig, queue: connectionQueue)
        source.setEventHandler {
            log("Signal \(sig), shutting down...")
            killExistingClient()
            try? FileManager.default.removeItem(atPath: SOCKET_PATH)
            exit(0)
        }
        source.resume()
        signalSources.append(source)
    }
}

// MARK: - Recovery

/// True when the live process `pid` is actually one of our allow-listed
/// aivpn-client binaries (checked via proc_pidpath). PIDs are recycled after
/// an unclean shutdown/reboot, so a PID read from disk must be
/// identity-checked before this root helper adopts it — otherwise a later
/// "disconnect" would SIGTERM/SIGKILL an unrelated process as root.
func pidIsAivpnClient(_ pid: pid_t) -> Bool {
    // 4096 == PROC_PIDPATHINFO_MAXSIZE (<sys/proc_info.h>); literal because
    // the macro is not reliably re-exported to Swift.
    var buf = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return false }
    let path = String(cString: buf)
    let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardized.path
    return ALLOWED_CLIENT_PATHS.contains(path) || ALLOWED_CLIENT_PATHS.contains(resolved)
}

/// Recover existing aivpn-client from a previous helper instance
func recoverExistingClient() {
    guard let pidStr = try? String(contentsOfFile: PID_PATH, encoding: .utf8),
          pidStr.count <= 16 else { return }
    let trimmed = pidStr.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let pid = Int32(trimmed), pid > 0 else { return }

    if kill(pid, 0) == 0 {
        // kill(pid, 0) only proves SOME process has this pid — confirm the
        // executable identity before adopting (see pidIsAivpnClient).
        guard pidIsAivpnClient(pid) else {
            log("WARNING: PID \(pid) from \(PID_PATH) is not aivpn-client (recycled pid?) — not adopting")
            try? FileManager.default.removeItem(atPath: PID_PATH)
            return
        }
        managedPID = pid
        log("Recovered aivpn-client (PID: \(pid))")
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            if logContent.contains("PFS ratchet complete") ||
               logContent.contains("forward secrecy established") {
                isConnected = true
            }
        }
    } else {
        try? FileManager.default.removeItem(atPath: PID_PATH)
    }
}

// MARK: - Console-user tracking

// The chown in createSocket() runs once, at daemon start. The LaunchDaemon
// starts at boot (RunAtLoad) BEFORE anyone is logged in, so that chown finds
// no console user and the socket stays root-only 0600 — the GUI then gets
// EACCES on connect() forever ("Service unavailable") even though the daemon
// is healthy. Track console-user changes and re-chown on every login/switch.

// Must be retained globally: a released store stops delivering notifications.
var consoleUserStore: SCDynamicStore?

func chownSocketToConsoleUser() {
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil, uid != 0 else {
        return // logged out / loginwindow — keep root-only
    }
    if chown(SOCKET_PATH, uid, gid) == 0 {
        log("Socket ownership updated for console user (uid \(uid))")
    } else {
        log("WARNING: chown(\(SOCKET_PATH)) to uid \(uid) failed: \(String(cString: strerror(errno)))")
    }
}

func setupConsoleUserWatcher() {
    // Non-capturing closure — bridges to the C callback pointer.
    guard let store = SCDynamicStoreCreate(nil, "aivpn-helper" as CFString,
                                           { _, _, _ in chownSocketToConsoleUser() },
                                           nil) else {
        log("WARNING: SCDynamicStoreCreate failed — socket ownership will not track console-user changes")
        return
    }
    let key = SCDynamicStoreKeyCreateConsoleUser(nil)
    guard SCDynamicStoreSetNotificationKeys(store, [key] as CFArray, nil),
          SCDynamicStoreSetDispatchQueue(store, connectionQueue) else {
        log("WARNING: SCDynamicStore notification setup failed — socket ownership will not track console-user changes")
        return
    }
    consoleUserStore = store
}

// MARK: - Main

func main() {
    setupSignals()
    recoverExistingClient()

    let sockFD = createSocket()
    guard sockFD >= 0 else {
        log("FATAL: Could not create helper socket")
        exit(1)
    }
    // Fix ownership for the already-logged-in case and track future logins.
    chownSocketToConsoleUser()
    setupConsoleUserWatcher()
    defer {
        close(sockFD)
        try? FileManager.default.removeItem(atPath: SOCKET_PATH)
    }

    log("AIVPN Helper v\(HELPER_VERSION) started (socket: \(SOCKET_PATH))")

    // Main accept loop — runs forever (LaunchDaemon manages lifecycle)
    while true {
        var clientAddr = sockaddr_un()
        var clientLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let clientFD = withUnsafeMutablePointer(to: &clientAddr) {
            accept(sockFD,
                   UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self),
                   &clientLen)
        }

        guard clientFD >= 0 else {
            if errno == EINTR { continue }
            break
        }

        connectionQueue.async {
            handleConnection(clientFD)
            close(clientFD)
        }
    }

    log("AIVPN Helper exiting")
}

main()
