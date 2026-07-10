//! aivpn-ip-helper — minimal privileged network helper for aivpn-linux.
//!
//! Installed by aivpn-linux's one-time setup to a root-owned system path
//! (`/usr/local/libexec/aivpn/aivpn-ip-helper`) and registered with polkit
//! via a sibling `.policy` action (`com.aivpn.client.configure-network`,
//! `allow_active=auth_admin_keep`) so a single `pkexec <this-path>`
//! authorization is cached for the polkit session instead of re-prompting
//! on every VPN reconnect. See `crates/aivpn-linux/src/app.rs` for the
//! installer and `crates/aivpn-client/src/tunnel.rs` for the caller.
//!
//! SECURITY MODEL: this binary runs as root. It does NOT execute a shell
//! and does NOT accept arbitrary commands. It reads a small, strictly
//! whitelisted command grammar from stdin (see `parse_line` below), one
//! command per line, and for every line that validates, execs the
//! corresponding `ip <argv...>` directly via `std::process::Command`
//! (never `sh -c`), so there is no shell metacharacter interpretation
//! layer anywhere in this process.
//!
//! Wire protocol (stdin, UTF-8, one command per line, `\n`-terminated):
//!
//! ```text
//! <name>\t<verb>\t<field>\t<field>...
//! ```
//!
//! `name` is an opaque caller-chosen label (echoed back in the output, see
//! below), restricted to `[A-Za-z0-9_]{1,32}`. `verb` selects one of a
//! fixed, exhaustive set of `ip` command shapes (see `Verb`); the
//! remaining tab-separated fields are verb-specific and are validated
//! field-by-field (IPv4 dotted-quad / CIDR / interface-name char classes —
//! see the `is_valid_*` functions) before ANY command in the batch is
//! executed.
//!
//! Validation is ALL-OR-NOTHING across the whole batch: if any line fails
//! to parse or validate, NO command is executed at all, and the process
//! exits non-zero with no stdout. This means a well-formed line earlier in
//! the batch can never be used to "smuggle" an adjacent malformed one into
//! partial execution — the entire input is fully validated before the
//! first `ip` invocation happens.
//!
//! On success, prints one `<name>:<exit_code>` line per executed command,
//! in input order, to stdout — the caller (`parse_helper_statuses` in
//! `crates/aivpn-client/src/tunnel.rs`) parses these the same way the
//! `pkexec sh -c "..."` fallback path parses its own
//! `__AIVPN_STATUS:<name>:<code>` markers.

use std::io::{Read, Write};
use std::process::{Command, ExitCode};

/// Hard cap on the number of commands accepted in a single batch. This
/// codebase never needs more than a handful per connect/reconnect; a low
/// cap bounds the work an authorized caller could make root do in one
/// shot, and guards against unbounded memory/CPU use.
const MAX_COMMANDS: usize = 64;

/// Hard cap on total stdin size, checked before any UTF-8/line processing.
/// Bounds memory use for a process that runs as root.
const MAX_STDIN_BYTES: usize = 64 * 1024;

/// The fixed, exhaustive set of `ip` command shapes this helper will ever
/// execute. Every shape corresponds 1:1 to an `ip` invocation this
/// codebase issues via the privileged path (see `run_ip_batch_privileged`
/// / `run_ip_privileged` in `crates/aivpn-client/src/tunnel.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// `ip addr replace <CIDR> dev <IFACE>`
    AddrReplaceDev,
    /// `ip addr del <CIDR> dev <IFACE>` — removes the stale address after a
    /// server-pushed network override moved the client to a new VPN IP
    AddrDelDev,
    /// `ip route replace <CIDR> dev <IFACE>`
    RouteReplaceDev,
    /// `ip route replace <IP> via <GW> dev <IFACE>`
    RouteReplaceViaDev,
    /// `ip route replace <IP> via <GW> dev <IFACE> onlink`
    RouteReplaceViaDevOnlink,
    /// `ip route replace <GW> dev <IFACE> scope link`
    RouteReplaceGwLink,
    /// `ip route replace 0.0.0.0/1 dev <IFACE>` (literal CIDR, no field for it)
    RouteReplaceFulltunnelLower,
    /// `ip route replace 128.0.0.0/1 dev <IFACE>` (literal CIDR, no field for it)
    RouteReplaceFulltunnelUpper,
    /// `ip route replace <CIDR> via <GW>`
    RouteReplaceVia,
    /// `ip -6 route replace blackhole default` (no fields — a fixed command
    /// that blackholes IPv6 so it cannot leak outside a full tunnel).
    RouteReplaceIpv6BlackholeDefault,
}

impl Verb {
    fn parse(s: &str) -> Option<Verb> {
        Some(match s {
            "addr_replace" => Verb::AddrReplaceDev,
            "addr_del" => Verb::AddrDelDev,
            "route_replace_dev" => Verb::RouteReplaceDev,
            "route_replace_via_dev" => Verb::RouteReplaceViaDev,
            "route_replace_via_dev_onlink" => Verb::RouteReplaceViaDevOnlink,
            "route_replace_gw_link" => Verb::RouteReplaceGwLink,
            "route_replace_fulltunnel_lower" => Verb::RouteReplaceFulltunnelLower,
            "route_replace_fulltunnel_upper" => Verb::RouteReplaceFulltunnelUpper,
            "route_replace_via" => Verb::RouteReplaceVia,
            "route_replace_ipv6_blackhole" => Verb::RouteReplaceIpv6BlackholeDefault,
            _ => return None,
        })
    }

    /// Number of tab-separated fields (beyond `name` and `verb`) this
    /// shape requires — enforced exactly, no optional/variadic fields.
    fn field_count(self) -> usize {
        match self {
            Verb::AddrReplaceDev => 2,                   // CIDR, IFACE
            Verb::AddrDelDev => 2,                       // CIDR, IFACE
            Verb::RouteReplaceDev => 2,                  // CIDR, IFACE
            Verb::RouteReplaceViaDev => 3,               // IP, GW, IFACE
            Verb::RouteReplaceViaDevOnlink => 3,         // IP, GW, IFACE
            Verb::RouteReplaceGwLink => 2,               // GW, IFACE
            Verb::RouteReplaceFulltunnelLower => 1,      // IFACE
            Verb::RouteReplaceFulltunnelUpper => 1,      // IFACE
            Verb::RouteReplaceVia => 2,                  // CIDR, GW
            Verb::RouteReplaceIpv6BlackholeDefault => 0, // fixed command, no fields
        }
    }
}

/// A validated command ready to run: `name` for the output marker, `argv`
/// the exact arguments to pass to `ip` (never through a shell).
#[derive(Debug)]
struct ParsedCommand {
    name: String,
    argv: Vec<String>,
}

/// Command/output-label charset: alphanumeric + underscore only. Excludes
/// `:` (the output separator) and whitespace, so `<name>:<code>` output
/// lines are always unambiguous to re-parse.
fn is_valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One 0-255 decimal octet: digits only, no leading zeros (other than the
/// literal single-character "0").
fn is_valid_octet(s: &str) -> bool {
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if s.len() > 1 && s.starts_with('0') {
        return false;
    }
    s.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
}

/// Plain IPv4 dotted-quad, no prefix length.
fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| is_valid_octet(p))
}

/// IPv4 dotted-quad, optionally with a `/0`-`/32` prefix-length suffix.
fn is_valid_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            is_valid_ipv4(ip)
                && !prefix.is_empty()
                && prefix.len() <= 2
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && (prefix.len() == 1 || !prefix.starts_with('0'))
                && prefix.parse::<u8>().map(|v| v <= 32).unwrap_or(false)
        }
        None => is_valid_ipv4(s),
    }
}

/// Linux interface name charset: `[A-Za-z0-9_.-]{1,15}` — 15 bytes is
/// `IFNAMSIZ - 1`. Covers both this codebase's own generated TUN names
/// (`tun{:04x}`, see `TunnelConfig::default()` in
/// `crates/aivpn-client/src/tunnel.rs`) and the host's own default-route
/// interface name (read from `ip route show default` output, which could
/// in principle be unusual on an atypical system — this charset is
/// permissive enough for realistic names while excluding anything that
/// could be a shell metacharacter, whitespace, or path separator).
fn is_valid_iface(s: &str) -> bool {
    // First byte must be alphanumeric (real interface names always start
    // this way) — defense in depth against a leading '-' ever being
    // positioned as an `ip` argument and reinterpreted as a flag. In
    // practice this field's values only ever come from this codebase's own
    // generated TUN names or the kernel's own default-route interface name,
    // never attacker input, but there's no reason to allow it structurally.
    matches!(s.as_bytes().first(), Some(b) if b.is_ascii_alphanumeric())
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Parse+validate a single input line into a `ParsedCommand`, or return a
/// human-readable rejection reason. Nothing here executes anything — this
/// is pure validation, called for every line before any command in the
/// batch is allowed to run (see `parse_batch`).
fn parse_line(line: &str, line_no: usize) -> Result<ParsedCommand, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 2 {
        return Err(format!(
            "line {line_no}: expected at least <name>\\t<verb>, got {} field(s)",
            fields.len()
        ));
    }
    let name = fields[0];
    let verb_str = fields[1];
    let rest = &fields[2..];

    if !is_valid_name(name) {
        return Err(format!("line {line_no}: invalid command name {name:?}"));
    }
    let verb = Verb::parse(verb_str)
        .ok_or_else(|| format!("line {line_no}: unknown verb {verb_str:?}"))?;
    if rest.len() != verb.field_count() {
        return Err(format!(
            "line {line_no}: verb {verb_str:?} expects exactly {} field(s), got {}",
            verb.field_count(),
            rest.len()
        ));
    }

    let argv = match verb {
        Verb::AddrReplaceDev | Verb::AddrDelDev => {
            let (cidr, iface) = (rest[0], rest[1]);
            if !is_valid_cidr(cidr) {
                return Err(format!("line {line_no}: invalid CIDR {cidr:?}"));
            }
            if !is_valid_iface(iface) {
                return Err(format!("line {line_no}: invalid interface {iface:?}"));
            }
            let action = if verb == Verb::AddrDelDev {
                "del"
            } else {
                "replace"
            };
            vec![
                "addr".to_string(),
                action.to_string(),
                cidr.to_string(),
                "dev".to_string(),
                iface.to_string(),
            ]
        }
        Verb::RouteReplaceDev => {
            let (cidr, iface) = (rest[0], rest[1]);
            if !is_valid_cidr(cidr) {
                return Err(format!("line {line_no}: invalid CIDR {cidr:?}"));
            }
            if !is_valid_iface(iface) {
                return Err(format!("line {line_no}: invalid interface {iface:?}"));
            }
            vec![
                "route".to_string(),
                "replace".to_string(),
                cidr.to_string(),
                "dev".to_string(),
                iface.to_string(),
            ]
        }
        Verb::RouteReplaceViaDev | Verb::RouteReplaceViaDevOnlink => {
            let (ip, gw, iface) = (rest[0], rest[1], rest[2]);
            if !is_valid_ipv4(ip) {
                return Err(format!("line {line_no}: invalid IP {ip:?}"));
            }
            if !is_valid_ipv4(gw) {
                return Err(format!("line {line_no}: invalid gateway {gw:?}"));
            }
            if !is_valid_iface(iface) {
                return Err(format!("line {line_no}: invalid interface {iface:?}"));
            }
            let mut argv = vec![
                "route".to_string(),
                "replace".to_string(),
                ip.to_string(),
                "via".to_string(),
                gw.to_string(),
                "dev".to_string(),
                iface.to_string(),
            ];
            if verb == Verb::RouteReplaceViaDevOnlink {
                argv.push("onlink".to_string());
            }
            argv
        }
        Verb::RouteReplaceGwLink => {
            let (gw, iface) = (rest[0], rest[1]);
            if !is_valid_ipv4(gw) {
                return Err(format!("line {line_no}: invalid gateway {gw:?}"));
            }
            if !is_valid_iface(iface) {
                return Err(format!("line {line_no}: invalid interface {iface:?}"));
            }
            vec![
                "route".to_string(),
                "replace".to_string(),
                gw.to_string(),
                "dev".to_string(),
                iface.to_string(),
                "scope".to_string(),
                "link".to_string(),
            ]
        }
        Verb::RouteReplaceFulltunnelLower | Verb::RouteReplaceFulltunnelUpper => {
            let iface = rest[0];
            if !is_valid_iface(iface) {
                return Err(format!("line {line_no}: invalid interface {iface:?}"));
            }
            // Deliberately a literal, exact-match CIDR — never taken from
            // the input. There's no legitimate reason for this specific
            // shape to ever carry a different value (see field_count():
            // it only accepts an IFACE field, nothing else).
            let cidr = if verb == Verb::RouteReplaceFulltunnelLower {
                "0.0.0.0/1"
            } else {
                "128.0.0.0/1"
            };
            vec![
                "route".to_string(),
                "replace".to_string(),
                cidr.to_string(),
                "dev".to_string(),
                iface.to_string(),
            ]
        }
        Verb::RouteReplaceVia => {
            let (cidr, gw) = (rest[0], rest[1]);
            if !is_valid_cidr(cidr) {
                return Err(format!("line {line_no}: invalid CIDR {cidr:?}"));
            }
            if !is_valid_ipv4(gw) {
                return Err(format!("line {line_no}: invalid gateway {gw:?}"));
            }
            vec![
                "route".to_string(),
                "replace".to_string(),
                cidr.to_string(),
                "via".to_string(),
                gw.to_string(),
            ]
        }
        Verb::RouteReplaceIpv6BlackholeDefault => {
            // Every argument is a fixed literal — no input fields (field_count
            // is 0), so there is nothing to validate or interpolate.
            vec![
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "blackhole".to_string(),
                "default".to_string(),
            ]
        }
    };

    Ok(ParsedCommand {
        name: name.to_string(),
        argv,
    })
}

/// Parse+validate the full batch, all-or-nothing: returns `Err` (with a
/// diagnostic) on the first invalid line, before anything has been
/// executed. This is what makes "a valid-looking line followed by
/// garbage" safe: the garbage line's failure rejects the whole batch, so
/// the valid line never runs either.
fn parse_batch(input: &str) -> Result<Vec<ParsedCommand>, String> {
    let lines: Vec<&str> = input.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return Err("empty input: no commands given".to_string());
    }
    if lines.len() > MAX_COMMANDS {
        return Err(format!(
            "too many commands: {} (max {MAX_COMMANDS})",
            lines.len()
        ));
    }
    lines
        .iter()
        .enumerate()
        .map(|(i, line)| parse_line(line, i + 1))
        .collect()
}

fn main() -> ExitCode {
    if std::env::args().count() > 1 {
        eprintln!("aivpn-ip-helper: takes no arguments, reads commands from stdin");
        return ExitCode::from(64); // EX_USAGE
    }

    let mut raw = Vec::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock().take(MAX_STDIN_BYTES as u64 + 1);
    if let Err(e) = handle.read_to_end(&mut raw) {
        eprintln!("aivpn-ip-helper: failed to read stdin: {e}");
        return ExitCode::from(1);
    }
    if raw.len() > MAX_STDIN_BYTES {
        eprintln!("aivpn-ip-helper: input exceeds {MAX_STDIN_BYTES} bytes");
        return ExitCode::from(65); // EX_DATAERR
    }

    let input = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("aivpn-ip-helper: stdin is not valid UTF-8");
            return ExitCode::from(65);
        }
    };

    let commands = match parse_batch(&input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aivpn-ip-helper: rejecting batch: {e}");
            return ExitCode::from(65);
        }
    };

    let mut all_ok = true;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for cmd in &commands {
        let status = Command::new("ip").args(&cmd.argv).status();
        let code = match status {
            Ok(s) => s.code().unwrap_or(-1),
            Err(e) => {
                eprintln!("aivpn-ip-helper: failed to exec ip {:?}: {e}", cmd.argv);
                -1
            }
        };
        if code != 0 {
            all_ok = false;
        }
        let _ = writeln!(out, "{}:{}", cmd.name, code);
        let _ = out.flush();
    }

    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ipv6 blackhole verb ─────────────────────────────────────────

    #[test]
    fn ipv6_blackhole_parses_to_fixed_argv() {
        let cmd = parse_line("ipv6_blackhole\troute_replace_ipv6_blackhole", 1)
            .expect("valid fixed command");
        assert_eq!(cmd.name, "ipv6_blackhole");
        assert_eq!(cmd.argv, ["-6", "route", "replace", "blackhole", "default"]);
    }

    #[test]
    fn ipv6_blackhole_rejects_extra_fields() {
        // The verb takes no fields; a trailing field must be rejected so no
        // attacker-controlled token can ever reach the argv.
        assert!(parse_line("n\troute_replace_ipv6_blackhole\teth0", 1).is_err());
    }

    // ── field validators ────────────────────────────────────────────

    #[test]
    fn octet_valid() {
        for s in ["0", "1", "9", "10", "99", "100", "199", "200", "255"] {
            assert!(is_valid_octet(s), "{s} should be valid");
        }
    }

    #[test]
    fn octet_invalid() {
        for s in [
            "256", "300", "999", "01", "00", "-1", "", "1a", "1.0", " 1", "1 ",
        ] {
            assert!(!is_valid_octet(s), "{s} should be invalid");
        }
    }

    #[test]
    fn ipv4_valid() {
        for s in ["0.0.0.0", "10.0.0.2", "255.255.255.255", "192.168.1.1"] {
            assert!(is_valid_ipv4(s), "{s} should be valid");
        }
    }

    #[test]
    fn ipv4_invalid() {
        for s in [
            "10.0.0",
            "10.0.0.0.0",
            "10.0.0.256",
            "10.0.0.01",
            "",
            "a.b.c.d",
            "10.0.0.0/24",
            "10.0.0.0 ",
            "10.0.0.0;ls",
            "::1",
        ] {
            assert!(!is_valid_ipv4(s), "{s} should be invalid");
        }
    }

    #[test]
    fn cidr_valid() {
        for s in [
            "10.0.0.0/24",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "10.0.0.2",
            "255.255.255.255/32",
            "0.0.0.0/0",
        ] {
            assert!(is_valid_cidr(s), "{s} should be valid");
        }
    }

    #[test]
    fn cidr_invalid() {
        for s in [
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/",
            "10.0.0.0/01",
            "10.0.0.0/24/24",
            "10.0.0.256/24",
            "",
            "10.0.0.0/24; rm -rf /",
        ] {
            assert!(!is_valid_cidr(s), "{s} should be invalid");
        }
    }

    #[test]
    fn iface_valid() {
        for s in [
            "tun0",
            "tun1a2b",
            "eth0",
            "wlp3s0",
            "enp0s31f6",
            "a",
            "a.b-c_d",
        ] {
            assert!(is_valid_iface(s), "{s} should be valid");
        }
    }

    #[test]
    fn iface_invalid() {
        for s in [
            "",
            "this_name_is_16ch", // > 15 bytes
            "tun 0",
            "tun;0",
            "tun/0",
            "tun$0",
            "tun`id`",
            "../../etc",
            "tun0\n",
            "tun0\t",
            "-f",
            "--help",
            "-oProxyCommand=x",
            ".hidden",
            "_leading",
        ] {
            assert!(!is_valid_iface(s), "{s} should be invalid");
        }
    }

    #[test]
    fn name_valid_invalid() {
        assert!(is_valid_name("addr"));
        assert!(is_valid_name("bypass_onlink"));
        assert!(is_valid_name("ft_0"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name("has:colon"));
        assert!(!is_valid_name("has\ttab"));
        assert!(!is_valid_name(&"x".repeat(33)));
    }

    // ── full line/batch parsing: every valid shape must be accepted ────

    #[test]
    fn accepts_addr_replace() {
        let cmd = parse_line("addr\taddr_replace\t10.0.0.2/24\ttun0000", 1).unwrap();
        assert_eq!(cmd.name, "addr");
        assert_eq!(
            cmd.argv,
            vec!["addr", "replace", "10.0.0.2/24", "dev", "tun0000"]
        );
    }

    #[test]
    fn accepts_route_replace_dev() {
        let cmd = parse_line("route\troute_replace_dev\t10.0.0.0/24\ttun0000", 1).unwrap();
        assert_eq!(
            cmd.argv,
            vec!["route", "replace", "10.0.0.0/24", "dev", "tun0000"]
        );
    }

    #[test]
    fn accepts_route_replace_via_dev() {
        let cmd = parse_line(
            "bypass_plain\troute_replace_via_dev\t203.0.113.5\t192.168.1.1\teth0",
            1,
        )
        .unwrap();
        assert_eq!(
            cmd.argv,
            vec![
                "route",
                "replace",
                "203.0.113.5",
                "via",
                "192.168.1.1",
                "dev",
                "eth0"
            ]
        );
    }

    #[test]
    fn accepts_route_replace_via_dev_onlink() {
        let cmd = parse_line(
            "bypass_onlink\troute_replace_via_dev_onlink\t203.0.113.5\t192.168.1.1\teth0",
            1,
        )
        .unwrap();
        assert_eq!(
            cmd.argv,
            vec![
                "route",
                "replace",
                "203.0.113.5",
                "via",
                "192.168.1.1",
                "dev",
                "eth0",
                "onlink"
            ]
        );
    }

    #[test]
    fn accepts_route_replace_gw_link() {
        let cmd = parse_line("gw_link\troute_replace_gw_link\t192.168.1.1\teth0", 1).unwrap();
        assert_eq!(
            cmd.argv,
            vec![
                "route",
                "replace",
                "192.168.1.1",
                "dev",
                "eth0",
                "scope",
                "link"
            ]
        );
    }

    #[test]
    fn accepts_fulltunnel_lower_and_upper_with_literal_cidr() {
        let lower = parse_line("ft_0\troute_replace_fulltunnel_lower\ttun0000", 1).unwrap();
        assert_eq!(
            lower.argv,
            vec!["route", "replace", "0.0.0.0/1", "dev", "tun0000"]
        );

        let upper = parse_line("ft_1\troute_replace_fulltunnel_upper\ttun0000", 1).unwrap();
        assert_eq!(
            upper.argv,
            vec!["route", "replace", "128.0.0.0/1", "dev", "tun0000"]
        );
    }

    #[test]
    fn fulltunnel_verb_ignores_any_attempt_to_pass_a_cidr_field() {
        // field_count() for these verbs is 1 (IFACE only) — an extra field
        // (even one that looks like a CIDR override attempt) must be
        // rejected outright, not silently accepted/ignored.
        let err = parse_line(
            "ft_0\troute_replace_fulltunnel_lower\ttun0000\t10.0.0.0/8",
            1,
        )
        .unwrap_err();
        assert!(err.contains("expects exactly 1"));
    }

    #[test]
    fn accepts_route_replace_via() {
        let cmd = parse_line("exclude\troute_replace_via\t192.168.1.0/24\t10.0.0.1", 1).unwrap();
        assert_eq!(
            cmd.argv,
            vec!["route", "replace", "192.168.1.0/24", "via", "10.0.0.1"]
        );
    }

    // ── adversarial / malformed inputs: must all be rejected ───────────

    #[test]
    fn rejects_empty_input() {
        assert!(parse_batch("").is_err());
        assert!(parse_batch("\n\n\n").is_err());
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(parse_line("addr", 1).is_err());
        assert!(parse_line("addr\taddr_replace", 1).is_err());
        assert!(parse_line("addr\taddr_replace\t10.0.0.2/24", 1).is_err());
    }

    #[test]
    fn rejects_unknown_verb() {
        let err = parse_line("x\tdelete_everything\ta\tb", 1).unwrap_err();
        assert!(err.contains("unknown verb"));
    }

    #[test]
    fn rejects_wrong_field_count() {
        assert!(parse_line("addr\taddr_replace\t10.0.0.2/24", 1).is_err());
        assert!(parse_line("addr\taddr_replace\t10.0.0.2/24\ttun0\textra", 1).is_err());
    }

    #[test]
    fn rejects_out_of_range_octets() {
        assert!(parse_line("addr\taddr_replace\t10.0.0.256/24\ttun0", 1).is_err());
        assert!(parse_line("addr\taddr_replace\t999.0.0.1/24\ttun0", 1).is_err());
    }

    #[test]
    fn rejects_oversized_interface() {
        assert!(parse_line("addr\taddr_replace\t10.0.0.2/24\tthis_name_is_16ch", 1).is_err());
    }

    #[test]
    fn rejects_shell_metacharacters_in_every_field() {
        let adversarial = [
            "10.0.0.2/24; rm -rf /",
            "10.0.0.2/24 && rm -rf /",
            "$(rm -rf /)",
            "`rm -rf /`",
            "10.0.0.2/24\ndel",
            "10.0.0.2/24|id",
            "../../../etc/passwd",
        ];
        for bad in adversarial {
            let line = format!("addr\taddr_replace\t{bad}\ttun0");
            assert!(
                parse_line(&line, 1).is_err(),
                "expected rejection for CIDR field {bad:?}"
            );
            let line2 = format!("addr\taddr_replace\t10.0.0.2/24\t{bad}");
            assert!(
                parse_line(&line2, 1).is_err(),
                "expected rejection for IFACE field {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_smuggled_second_command_via_field() {
        // A field that itself looks like a second whole command line must
        // not be reinterpreted — it just fails char-class validation as a
        // single field value (embedded tab/newline are not part of any
        // valid CIDR/IFACE charset).
        let smuggle = "10.0.0.0/24\tdelete_everything\tx\ty";
        let line = format!("addr\taddr_replace\t{smuggle}\ttun0");
        // This actually changes the *field count* once split on '\t', so
        // it's rejected for that reason — but confirm it's rejected.
        assert!(parse_line(&line, 1).is_err());
    }

    #[test]
    fn rejects_batch_with_valid_line_followed_by_garbage() {
        let input = "addr\taddr_replace\t10.0.0.2/24\ttun0000\nnot a valid line at all";
        let err = parse_batch(input).unwrap_err();
        assert!(err.contains("line 2"));
    }

    #[test]
    fn rejects_batch_exceeding_max_commands() {
        let mut lines = Vec::new();
        for _ in 0..(MAX_COMMANDS + 1) {
            lines.push("ft_0\troute_replace_fulltunnel_lower\ttun0000".to_string());
        }
        let input = lines.join("\n");
        let err = parse_batch(&input).unwrap_err();
        assert!(err.contains("too many commands"));
    }

    #[test]
    fn accepts_batch_at_max_commands() {
        let mut lines = Vec::new();
        for _ in 0..MAX_COMMANDS {
            lines.push("ft_0\troute_replace_fulltunnel_lower\ttun0000".to_string());
        }
        let input = lines.join("\n");
        assert!(parse_batch(&input).is_ok());
    }

    #[test]
    fn rejects_invalid_name() {
        assert!(parse_line("bad name\taddr_replace\t10.0.0.2/24\ttun0", 1).is_err());
        assert!(parse_line("bad:name\taddr_replace\t10.0.0.2/24\ttun0", 1).is_err());
    }

    #[test]
    fn rejects_gw_that_is_a_cidr() {
        // GW fields must be plain IPv4, not CIDR — a prefix suffix must be
        // rejected even though it "looks like an IP".
        assert!(parse_line(
            "bypass\troute_replace_via_dev\t203.0.113.5\t192.168.1.1/24\teth0",
            1
        )
        .is_err());
    }

    #[test]
    fn full_batch_of_every_valid_shape_is_accepted() {
        let input = [
            "addr\taddr_replace\t10.0.0.2/24\ttun0000",
            "route\troute_replace_dev\t10.0.0.0/24\ttun0000",
            "bypass_plain\troute_replace_via_dev\t203.0.113.5\t192.168.1.1\teth0",
            "bypass_onlink\troute_replace_via_dev_onlink\t203.0.113.5\t192.168.1.1\teth0",
            "gw_link\troute_replace_gw_link\t192.168.1.1\teth0",
            "ft_0\troute_replace_fulltunnel_lower\ttun0000",
            "ft_1\troute_replace_fulltunnel_upper\ttun0000",
            "exclude\troute_replace_via\t192.168.1.0/24\t10.0.0.1",
        ]
        .join("\n");
        let parsed = parse_batch(&input).unwrap();
        assert_eq!(parsed.len(), 8);
    }
}
