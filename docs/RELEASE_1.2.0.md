# Release 1.2.0 Configuration and Verification

## Artifact Signing

The remote installer verifies Ed25519 signatures of the server binary and mask archives. `.SHA256SUMS` files verify integrity; `.sig` files prove authorship against a pre-trusted public key.

CI requires the `RELEASE_SIGNING_KEY_PEM` secret (PEM) and the `RELEASE_PUBLIC_KEY` variable (DER public key in base64). `deploy/ci/sign-release-assets.sh` checks that the keys match. The public key is embedded into the client at build time via `AIVPN_RELEASE_PUBKEY`; the SSH installer forwards it to the server script. For standalone runs, `--release-pubkey` and `AIVPN_RELEASE_PUBKEY` are supported. The trusted key must be verified out-of-band, separately from the download being checked.

A local `--binary-file` is treated as a trusted source. A neighbouring `.SHA256SUMS`, if present, is also verified. When rotating keys, first distribute the new trusted public key, then the artifacts signed with it.

## Email Bootstrap via JMAP

The `Email` channel reads JSON descriptors from the text parts of emails via JMAP. `address` specifies the exact sender, `subject_pattern` is a subject substring. The body contains a single descriptor or an array of descriptors signed with the server's trusted key.

- `AIVPN_BOOTSTRAP_JMAP_URL` — HTTPS URL of the JMAP session resource.
- `AIVPN_BOOTSTRAP_JMAP_TOKEN` — read-only mailbox token.

The API and session resource must share the same origin. Limits: 16 most recent messages and 4 MiB per response. Truncated parts, wrong encoding, different sender and bad signatures are rejected. The channel never sends mail and never mutates the mailbox. Protocol: [JMAP Mail, RFC 8621](https://www.rfc-editor.org/rfc/rfc8621.html).

## DNS in SOCKS5 Mode

`--proxy-dns 1.1.1.1,9.9.9.9` takes one to four IPv4 DNS servers. Queries are sent inside the VPN. An internal DNS reachable through the tunnel can be configured. An empty list, loopback, multicast and broadcast are rejected before the listener starts.

## Control-Message Fragmentation

Large control messages are fragmented before encryption. Each fragment gets its own nonce and sequence number. Reassembly happens after AEAD and replay protection. Limits: 512 KiB per message, four incomplete messages per session, 10-second reassembly timeout. Conflicting fragments are rejected. A lost message is never delivered partially to the handler; the caller receives a normal timeout.

## Mandatory Checks

`make mask-gate` uses the real `MimicryEngine` and a standalone nDPI build. `deploy/ci/build-dpi-tools.sh` builds the pinned nDPI 5.0 revision. Without the tool the check fails. Protocol classification does not prove indistinguishability from the real application on all networks and classifiers.

Clippy `correctness` and `suspicious` diagnostics block the build; style warnings remain visible. `swift test --package-path platforms/ios` verifies read failures, RNG, persistence and corrupted-key handling without access to a real Keychain.

## Local Dependency Patches

`vendor/cryoglyph` contains the unmodified library sources of cryoglyph 0.1.0. The manifest bumps `lru` to the fixed 0.18 line; examples and benchmark dependencies are excluded. Original package licenses are preserved.

Bun applies `patches/braces@3.0.3.patch` which caps parser nesting at 128 levels. A regression test verifies rejection before a stack overflow and normal pattern expansion. Registry auditors still report version 3.0.3 because the local patch does not bump the package version.

## Dual-Stack (IPv4/IPv6)

With `ipv6_enabled=true` the server validates `ipv6_prefix`, enables forwarding and NAT66, assigns an address to the interface and delivers the client's IPv6 address, prefix and MTU via `ServerHello`. An IPv6 setup failure aborts startup. Minimum MTU for IPv6 is 1280. The low 32 bits of the client's address contain its assigned IPv4; reverse mapping validates the whole address.

Data, FEC-recovered packets and ChainForward are subject to IP-packet length, source, client-isolation and QoS checks for both families. A non-zero tail beyond the declared IP length is rejected. DSCP preserves ECN; IPv4 recomputes the header checksum including options.

Desktop intercepts IPv6 via `::/1` and `8000::/1` routes through the TUN and removes its own routes on disconnect. Android enables IPv6 after the server assignment and recreates the TUN when the address, prefix or MTU changes. iOS applies the assignment via Network Extension. Without an assignment the server rejects IPv6.

## Windows Network Protection (Kill-Switch)

The kill-switch uses persistent Windows Filtering Platform filters in its own sublayer. Allowed: VPN interface, loopback, server address, DHCP and link-local ICMPv6. All other outbound traffic is blocked. Third-party firewall policies are preserved. Priority is described in [WFP documentation](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).

A client crash keeps the restrictions. An explicit disconnect runs cleanup and removes the marker only on success. On failure the marker stays and the UI reports the error. Rules are updated in a single transaction. When migrating from the old netsh backend the saved policy is restored; a corrupted value is not replaced with a guessed default.

## Passive Mask Distribution

The `passive_distribution` section contains `enable`, `allow_network`, `operator_pubkey_b64`, `check_interval_secs`, `dns_domains`, `dns_resolver`, `image_urls`, `chain_endpoints`, `max_image_bytes`, `max_image_pixels`. Reception is disabled by default. Active polling requires `enable=true`, `allow_network=true` and a trusted Ed25519 operator public key in base64. HTTP fetching requires the `passive-distribution` feature.

Supported carriers: signed AVM1 container in DNS TXT, RGB LSB of PNG images, Bitcoin OP_RETURN part sets and Ethereum calldata. DNS retries over TCP when the UDP answer is truncated. HTTP accepts only public HTTPS, enforces size limits and validates each redirect address. PNG is checked by file size and pixel count before decoding.

`chain_endpoints` are public HTTPS GET URLs returning an AVBC container, calldata, or a transaction / transaction-array JSON. For Bitcoin, `vout[].scriptpubkey` ([Esplora](https://github.com/Blockstream/esplora/blob/master/API.md)) and `vout[].scriptPubKey.hex` are read; for Ethereum, `input` from the object or `result` ([JSON-RPC format](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionbyhash)). This is reading published chain data. The application never publishes transactions and never spends funds. Part-set completeness and signature are verified before a mask is added.

The profile is written via a temporary file, fsync and rename. A write error does not publish the profile to the live directory. The filename and the signed profile ID must match.

## Inter-Server Links and Client Database

Pool, exit relay and site nodes use masked handshakes with per-session keys, rotation and replay protection. An empty `pool.transport` means `masked`; an explicit `legacy` value is rejected. Old static sessions and the standalone chain forwarder are removed. The tag-prefix packet layout remains supported as the ordinary handshake-session format.

Sites can connect without pool configuration. Multiple sites may share one key with an explicit identity allowlist. The site key must differ from the pool key, otherwise their privileges cannot be separated; a match aborts startup. Their per-session keys grant RouteSync and SiteData but not pool-DB sync or management. SiteData sources are validated against the authenticated node's allowed subnets; IPv6 subnets are carried even over an IPv4 inter-server link. Site routes are injected into the TUN. With strict enrollment the exchange is allowed only after the identity signature is verified in the context of the current handshake.

The server requires a client database. Address allocation uses its network configuration and pool partitions; the fixed fallback range without a DB is removed. The same external IP does not mean the same client. `clients.json` mutations run under a shared file lock with a reload of the current version. Do not edit the live file manually bypassing that lock.

## Persistent Device Key

The client stores an X25519 key at `~/.config/aivpn/device.key` (`USERPROFILE` instead of `HOME` on Windows). A corrupted or inaccessible file is a hard error, not a silent identity replacement. A new key is published without overwriting an existing file; concurrent processes converge on one key. A save failure does not allow continuing with an ephemeral key. On Unix the file is 0600, the directory 0700; symlinks instead of a regular file are rejected. Inter-server links use their own node identity and never create a device key.

## Hardened Build (`production-secure`)

`production-secure` requires trusted signing keys and artifact verification in enforce mode. The generator signs both forward and reverse mask profiles. A missing key, mutated signed fields or a bad signature causes a hard failure. Ed25519 verification rejects small-order public keys. Migration requires distributing the trusted public key and signed profiles to both sides in advance.

## Node Trust Revocation

`pool_nodes.json` is re-read under a shared lock on authentication and on live-channel checks. Corrupted JSON, a bad key, a symlink or disappearance of an already-loaded file denies access. A missing file on first start means a new registry. A zero-length file counts as corrupted. After corruption, restore the file and restart the process; there is no automatic trust reset.

A binding is considered successful only after it is persisted. A failed revocation returns a CLI error and keeps the node denied in the current process; a failed un-revocation does not grant access. An active inbound handshake is checked before any message is processed. An outbound channel additionally checks revocation once per second and tears down the connection. After revocation and re-registration under a different key, the old session does not inherit the new node's privileges.

## Linux Kernel Acceleration

Client and server use ABI 7. The device is opened by one process with `CAP_NET_ADMIN`; a second process continues normal handling. Closing the last descriptor of the owner removes UDP/egress hooks, frees sessions and the TUN. The server requires a successfully configured TUN. Server downlink is enabled separately via `AIVPN_KERNEL_DOWNLINK=1`.

A session is installed in order: keys and layout, replay epoch, policy. Re-installing a layout preserves the window. A new key gets a new epoch; the previous one is kept for in-flight packets. Each accepted packet claims a counter in the shared window before delivery to the handler. A failed shared claim rejects the packet. If the window of an already-active session is lost, a new handshake is required; a local window does not replace the kernel's lost history.

Policy distinguishes client vs. server, assigned IPv4/IPv6, isolation, pending enrollment/mTLS, sites and exit. Access revocation takes priority over userspace fallback. QoS for accelerated and normal packets drains a single per-client bucket. Re-applying a policy does not refill the balance; a session change does not create a new bucket for the same client. Byte quotas are part of the ABI; the current client-DB model has no separate quota setting.

The client advertises FEC usage. Before the advertisement and while FEC is enabled the server sends uplink to userspace so loss recovery sees the full group. DSCP, neural checks and metadata recording also keep required handling in userspace. For Light/Full downlink, packets go through the userspace padding generator. Server IPv6 downlink still uses userspace. This is a per-packet handler choice; tunnel functionality is preserved.

Kernel counters are included in statistics and liveness. The server counts UDP payload length, the client counts the inner IP packet, matching the normal path. Building the module and the policy tests do not replace testing a loaded module on the target kernel.
