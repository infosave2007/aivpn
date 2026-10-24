# AIVPN Threat Model

This document describes the security properties of AIVPN, the adversary model it is designed against, and the known limitations of the current implementation.

---

## 1. Goals

AIVPN is designed to provide:

1. **Confidentiality** — payload content is not visible to a passive observer on the network path.
2. **Traffic-analysis resistance** — packet sizes, inter-arrival times, and connection patterns are disguised as known benign application traffic (WebRTC, QUIC, etc.).
3. **Active-probing resistance** — a server does not respond recognizably to unsolicited or malformed probe packets.
4. **Forward secrecy** — compromise of long-term keys does not decrypt previously captured sessions.
5. **Availability under censorship** — the system detects when a mask profile is fingerprinted by DPI and rotates to a fresh one automatically.

---

## 2. Adversary Model

### 2.1 In-scope adversaries

| Adversary | Capability | Threat |
|-----------|-----------|--------|
| **Passive ISP/censor** | Reads all packets between client and server | Traffic analysis, protocol identification |
| **Active prober** | Sends crafted packets to the server endpoint | Fingerprinting by server response behavior |
| **DPI appliance** | Stateful analysis of flow characteristics | Mask fingerprinting, throttling |
| **Network observer** | Correlates timing of flows across vantage points | Traffic correlation |
| **Stolen server key** | Off-line; gains static server private key | Cannot decrypt past sessions (PFS) |
| **Compromised server** | Full access to server memory and disk | Ongoing sessions exposed; past sessions protected by PFS |

### 2.2 Out-of-scope adversaries

| Adversary | Reason out of scope |
|-----------|-------------------|
| **Compromised client endpoint** | If the OS or application running the client is controlled by the adversary, no VPN protocol can help. |
| **Global passive adversary** | Traffic correlation between the client's ISP and the server's ISP is a hard problem; AIVPN does not claim resistance to a global passive adversary. |
| **Physical server seizure** | Best handled by full-disk encryption and key destruction procedures outside the scope of this protocol. |
| **DNS interception** | Hostname resolution for the server address happens before the VPN is established; protect DNS separately. |

---

## 3. Cryptographic Design

### 3.1 Key exchange

- **Algorithm:** X25519 Diffie-Hellman (ephemeral client keypair, static server public key).
- **PSK:** An optional 32-byte pre-shared key is mixed into key derivation, providing a second authentication factor.
- **Derived keys:** BLAKE3-based KDF produces `session_key`, `tag_secret`, and `nonce_suffix` from the DH output.

### 3.2 Authenticated encryption

- **Algorithm:** ChaCha20-Poly1305 (IETF variant, 96-bit nonce).
- **Nonce construction:** `counter (8 bytes) || nonce_suffix (4 bytes)`. The counter is monotonically increasing per session; reuse is prevented by design.

### 3.3 Session tags (O(1) lookup without session IDs)

Every packet carries an 8-byte *resonance tag* derived from the current timestamp and `tag_secret`. The server maintains a 256-entry sliding window per session to allow out-of-order delivery. Tags are non-guessable without `tag_secret`.

**Anti-replay:** Tags outside the acceptance window (`DEFAULT_WINDOW_MS = 10 000 ms`) are dropped. The XDP early filter enforces the same window at NIC level.

### 3.4 Perfect Forward Secrecy (PFS ratchet)

After the initial session, the server sends a `ServerHello` with a fresh ephemeral public key. The client computes a new DH secret, derives ratcheted keys, and begins sending on the new keys immediately. The old keys are retained briefly for in-flight packets, then discarded.

**Property:** An attacker who records the ciphertext stream and later obtains the server's static private key cannot decrypt any session that has completed at least one ratchet step.

---

## 4. Traffic Analysis Resistance

### 4.1 Mask mimicry

Outbound packets are shaped to match a selected traffic profile (`MaskProfile`):
- **Header injection:** Synthetic application-layer headers are prepended to each packet.
- **Size shaping:** Payloads are padded to match the target size distribution.
- **Timing shaping (IAT):** The mimicry engine enforces inter-arrival time distributions from the mask profile.
- **FSM-driven state transitions:** Traffic evolves through a finite-state machine matching the modeled application's conversation phases.

### 4.2 Neural Resonance (automated mask rotation)

The shipped reference encoders load learned MLP weights matched to each mask's signature hash; section 5.1 describes training, validation and the projection fallback for unknown signatures. During warm-up, the server uses the configured MSE threshold. After 500 live checks for a mask, its own `mean + 3σ` threshold applies. Crossing the threshold triggers rotation and pushes the new mask to clients. MSE measures statistical drift and does not prove that DPI identified the tunnel. The separate GBDT classifier in section 5.2 estimates tunnel resemblance and is included in the standard `make server` build.

Features monitored: packet size distribution, IAT statistics, entropy, burst patterns, packet direction ratio, and IAT periodicity.

**Rotation cooldown:** 60 seconds between rotations prevents oscillation under sustained active probing.

### 4.3 Active-probing resistance

- The server does not respond to packets that fail tag validation.
- Tag validation requires knowledge of `tag_secret`, which is only derivable after a successful DH handshake.
- Unsolicited probes receive no response, making the server's protocol indistinguishable from a UDP echo service or game server to an outside observer.

---

## 5. Machine Learning Components

AIVPN uses two local ML components to monitor the masks in section 4. Neither needs a GPU or a remote inference service. MLP weights load from the bundled reference library or a configured validated file; the GBDT tables are embedded in the binary. They answer two different questions:

| Component | Question it answers | Family | Where |
|---|---|---|---|
| **Neural Resonance** | "Does the *live* traffic still look like this mask's fingerprint?" | Fully-connected MLP **autoencoder** (anomaly detection) | `crates/aivpn-server/src/neural.rs` |
| **ML-DPI gate** | "Does a masked flow *read as a tunnel* rather than the target protocol?" | **GBDT** (gradient-boosted decision trees) | `crates/aivpn-server/src/dpi_gate.rs` *(R2 Phase D)* |

Both feed the same action: **rotate the mask** when it looks compromised.

### 5.1 Neural Resonance - trained reconstruction model

The shipped reference encoders use a `64 -> 16 -> 64` MLP with ReLU. Weights are learned by backpropagation and Adam, then loaded from `assets/neural/models.json`. The runtime checks the model version, feature version, finite weights, tensor sizes and the hash of the mask's signature vector. `neural.trained_models_file` can select another validated library.

`neural_dataset` prepares 64-dimensional features from recorded packet sizes and timestamps. It uses the gateway's sampling stride of 16; encrypted-payload entropy is modeled with uniform bytes of the same length. The current reference data covers the WebRTC and QUIC families. It does not establish a separate validated fingerprint for every named service. Input payloads, addresses and credentials are not exported.

Each capture is split chronologically into train, validation and test, with disjoint packets, fresh statistics per partition and a 256-packet gap at each boundary. Adam uses train only; validation selects the epoch; test is scored after that choice. `assets/neural/heldout.json` contains aggregate held-out feature windows so CI can verify reconstruction and drift without private PCAP files. The metadata records the capture digest and partition ranges.

A mask without a model matching its signature uses the deterministic projection from `BakedMaskEncoder::from_signature`. That fallback is not trained reconstruction. An operator can train and install a reference library for a new mask with `neural_dataset`, `neural_train` and `neural_evaluate`.

The score is mean squared reconstruction error. It measures statistical deviation from a reference, not proof that DPI recognized the tunnel. Ordinary workload or network changes can also raise it. The separate GBDT classifier remains responsible for the tunnel-resemblance estimate.

The configured warm-up thresholds remain `warning_threshold = 0.35` and `compromised_threshold = 0.50`, with checks every 30 seconds and a 60-second rotation cooldown. After 500 live MSE checks for a mask, its observed `mean + 1.5σ` and `mean + 3σ` thresholds apply. These are counts of checks, not packets. Offline training does not silently lower the operator's warm-up thresholds.

### 5.2 The ML-DPI gate — GBDT "reads-as-tunnel" classifier (R2 Phase D)

#### What kind of model

A **gradient-boosted decision-tree ensemble (GBDT)** — an ensemble of shallow trees whose additive votes produce a probability. **Not a neural network at all**; a different ML family, chosen because it is cheap, needs no matrix math, and handles the mixed size/entropy/header features well.

#### What it does

Full deep-packet-inspection (running nDPI) is far too heavy for the live data path. The GBDT is a **cheap inline approximation** of a DPI verdict: given a window of a session's packets it outputs the probability that the flow **reads as an obfuscated tunnel** rather than as its declared target protocol.

- **Features (23, all cheap, no deep payload parsing)**: packet-size moments and histogram, first-16-byte entropy, and a few protocol-structure checks (STUN message-type / magic-cookie / length-consistency, QUIC long-header form). Inter-arrival time was deliberately **excluded** — it proved leaky/unstable in the offline study.
- **Training**: `tools/dpi/train_gbdt.py` uses external frames collected after authenticated VPN admission and transport decryption checks. nDPI labels the complete session capture; only verified target protocols and teacher-confirmed negative variants enter training. Whole independent captures stay in train, validation or test, including all derived variants. Hyperparameters and the decision threshold are fixed before test scoring. Current metrics, baselines and limits are in [the model report](assets/dpi/report.md). The held-out captures use the same workload generator, so these results do not establish generalization to arbitrary applications or DPI systems.
- **Deployment**: the trained tree ensemble is exported to **constant weights embedded in the server binary** (the same idea as the baked MLP), traversed in place — no model file, no allocation on the hot path. Gated behind the `neural` Cargo feature.

#### How it composes with Neural Resonance

The GBDT verdict is a **sibling signal**, not a replacement. Both feed the same gateway rotate decision:

- **Neural Resonance** watches for *drift from self* (this mask stopped looking like itself).
- **ML-DPI gate** watches for *reads-as-tunnel* (this mask looks like obfuscation to a DPI-style classifier).

Crossing either configured threshold requests rotation. The signals can correlate and both can produce false alarms. Their combination does not establish resistance to an external DPI system.

The unchanged GBDT also detected 15 of 15 non-overlapping windows from three independent WireGuard sessions, each with 2048 acknowledged UDP exchanges; nDPI confirmed WireGuard. These windows were excluded from training. This validates one known VPN and workload, not detection of unknown tunnels that retain QUIC/STUN classification. Normalized evidence is in `assets/dpi/external_vpn_fixtures.json`.

### 5.3 Related offline ML (not on the data path)

The same GBDT/discriminator also powers **offline** tooling, so it never costs runtime latency there:

- **CI DPI gate** (R2 Phase A): every published mask is nDPI-classified before it can be merged.
- **Adversarial mask-repair** (R2 Phase C, `aivpn-mask-repair`): a mask that fails the DPI gate is automatically *repaired* by a bounded hill-climb scored by the real nDPI discriminator until it classifies as its target protocol.

Design details: `docs/R2_DESIGN.md`, `docs/R2_PHASE_{A,C,D}.md`.

---

## 6. Kill-Switch & Leak Protection

When `--kill-switch` is active, the client installs firewall rules that drop all outbound traffic except:
- Traffic on the VPN TUN interface.
- Traffic to the physical VPN server IP (so the tunnel can be re-established).
- Loopback traffic.

**Implementation:**
- **Linux:** nftables table `aivpn_ks` with drop policy; iptables chain `AIVPN_KS` as fallback.
- **macOS:** pfctl anchor `aivpn_ks`.
- **Windows:** Windows Firewall rules via `netsh advfirewall`.

Rules persist across unexpected process death (SIGKILL) by design — the user remains protected until they explicitly run `aivpn-client kill-switch clear`.

**No shell injection:** All firewall rule arguments are passed as distinct `argv` elements; no string interpolation through a shell.

**macOS secure write:** pfctl anchor rules are written to `/var/run/aivpn/` (mode `0700`) using `O_NOFOLLOW | O_CREAT_NEW | mode(0o600)` to prevent symlink attacks against world-writable directories.

---

## 7. XDP Early Filter

When `xdp_prog.o` is installed, the client attaches an XDP BPF program to the physical NIC (the default-route interface). The filter runs at NIC RX level, before socket buffer allocation:

- Drops UDP packets shorter than 26 bytes (minimum valid AIVPN payload).
- Drops UDP packets whose resonance tag timestamp falls outside the acceptance window (default ±10 s from `bpf_ktime_get_ns()`).
- All other packets pass through to the normal network stack unchanged.

**Effect:** Volumetric DDoS packets with random payloads are dropped before they consume kernel networking resources. Legitimate traffic is unaffected.

**Failure mode:** If `xdp_prog.o` is absent or attachment fails, the VPN operates normally without XDP — it is a best-effort optimization, not a security requirement.

---

## 8. Known Limitations

| Limitation | Notes |
|-----------|-------|
| **XDP filter is IPv4-only** | IPv6 packets pass through XDP unconditionally. For IPv6-only deployments this reduces DDoS protection at NIC level. |
| **Traffic correlation** | Timing correlations between the client ISP and server ISP may be exploitable by a sufficiently resourced adversary. |
| **Mask quality** | A poorly crafted mask (low confidence score) may be distinguishable from real traffic by a trained classifier. Use `--validate-mask` before deploying custom profiles. |
| **Single-hop** | AIVPN is a single-hop VPN; the server knows the client's real IP. Use in combination with a trusted exit node if anonymity is required. |
| **PSK distribution** | The PSK embedded in the connection key must be distributed securely. Compromise of the connection key string allows impersonation. |
| **Kill-switch on SIGKILL only persists until reboot** | The firewall rules are loaded in the running kernel/firewall; they do not survive a reboot. This is intentional — a rebooted system starts clean. |

