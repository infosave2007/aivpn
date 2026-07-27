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

A per-mask MLP (~66 KB, deterministically derived from the mask signature vector) monitors live traffic statistics. When the reconstruction error (MSE) exceeds `compromised_threshold = 0.50`, the server triggers a mask rotation and pushes the new mask to connected clients.

Features monitored: packet size distribution, IAT statistics, entropy, burst patterns, packet direction ratio, and IAT periodicity.

**Rotation cooldown:** 60 seconds between rotations prevents oscillation under sustained active probing.

### 4.3 Active-probing resistance

- The server does not respond to packets that fail tag validation.
- Tag validation requires knowledge of `tag_secret`, which is only derivable after a successful DH handshake.
- Unsolicited probes receive no response, making the server's protocol indistinguishable from a UDP echo service or game server to an outside observer.

---

## 5. Machine Learning Components

AIVPN ships two small, self-contained ML components that defend the masks described in Section 4. Neither is an LLM and neither needs a GPU — both are baked into the binary as constant weights and run in microseconds. They answer two different questions:

| Component | Question it answers | Family | Where |
|---|---|---|---|
| **Neural Resonance** | "Does the *live* traffic still look like this mask's fingerprint?" | Fully-connected MLP **autoencoder** (anomaly detection) | `crates/aivpn-server/src/neural.rs` |
| **ML-DPI gate** | "Does a masked flow *read as a tunnel* rather than the target protocol?" | **GBDT** (gradient-boosted decision trees) | `crates/aivpn-server/src/dpi_gate.rs` *(R2 Phase D)* |

Both feed the same action: **rotate the mask** when it looks compromised.

### 5.1 Neural Resonance — the reconstruction autoencoder

#### What kind of network

A **feed-forward, fully-connected multilayer perceptron (MLP)** used as an **autoencoder** — *not* convolutional, *not* recurrent, *not* a transformer.

```
input (64) ──▶ Linear(64→128) ──▶ ReLU ──▶ Linear(128→64) ──▶ output (64)
                                                                    │
              reconstruction error  MSE(input, output)  ◀──────────┘
```

- **Input**: a 64-dimensional feature vector summarising the session's recent traffic — a packet-size histogram (16 bins from 0 to ≥1280 B), byte entropy, packets/sec, bytes/sec, and inter-arrival-time statistics — normalised through a saturating transform (`saturate()`) so heavy tails don't blow up the scale.
- **Output**: a 64-dimensional *reconstruction* of that same vector.
- **Score**: `MSE(input, output)` — the mean-squared reconstruction error, aka the **resonance score**.

Because input and output share the same 64 dimensions and the model is trained (here: *baked*) to reproduce the mask's "normal" fingerprint, it behaves as a classic **unsupervised novelty detector**:

- **Low MSE** → live traffic matches the mask → healthy.
- **High MSE** → live traffic has drifted from the mask's signature → the mask is likely fingerprinted by DPI → **rotate**.

#### What makes it unusual: weights are *derived*, not *trained*

The distinctive design choice: the MLP's weights are **not learned by backpropagation**. They are **deterministically baked** from the mask's own 64-float `signature_vector` — each weight is seeded from a BLAKE3 hash of the signature (`MaskNet::from_signature`). Consequences:

- Every mask induces its **own** network — a per-mask "resonance chamber."
- No training data, no gradient descent, no model files: the network is a pure function of the mask, so client and server derive the identical net.
- Conceptually this is closer to a **random-projection / Extreme-Learning-Machine (ELM)-style** fixed-weight autoencoder than to a conventionally trained one. Reconstruction works because the fixed projection is *tuned to that mask's* fingerprint, so on-fingerprint input reconstructs well and off-fingerprint input does not.

#### Thresholds & rotation logic

- Defaults (`NeuralConfig`): `warning_threshold = 0.35`, `compromised_threshold = 0.50`, check every `30 s`, rotation cooldown `60 s`. Calibrated against the realcap2 real-capture corpora replayed through every bundled mask (healthy-traffic MSE: overall p99 ≈ 0.26, max ≈ 0.26; live stand observed up to ≈ 0.31) — see `crates/aivpn-server/examples/neural_calib.rs`.
- These fixed defaults only gate the **warm-up window**. After `MIN_CALIBRATION_SAMPLES`, a **per-mask adaptive calibration** takes over: the thresholds become `mean + 1.5σ` (warning) and `mean + 3σ` (compromised) of that mask's own observed MSE distribution — so each mask is judged against its own baseline rather than a global constant.
- Crossing `compromised_threshold` (subject to cooldown) triggers **mask rotation** in the gateway.

> Patent-pending. The point is O(1), stateless, per-mask anomaly detection that needs no labelled attack data — it detects *deviation from self*, so it reacts to novel DPI fingerprinting it has never seen.

### 5.2 The ML-DPI gate — GBDT "reads-as-tunnel" classifier (R2 Phase D)

#### What kind of model

A **gradient-boosted decision-tree ensemble (GBDT)** — an ensemble of shallow trees whose additive votes produce a probability. **Not a neural network at all**; a different ML family, chosen because it is cheap, needs no matrix math, and handles the mixed size/entropy/header features well.

#### What it does

Full deep-packet-inspection (running nDPI) is far too heavy for the live data path. The GBDT is a **cheap inline approximation** of a DPI verdict: given a window of a session's packets it outputs the probability that the flow **reads as an obfuscated tunnel** rather than as its declared target protocol.

- **Features (23, all cheap, no deep payload parsing)**: packet-size moments and histogram, first-16-byte entropy, and a few protocol-structure checks (STUN message-type / magic-cookie / length-consistency, QUIC long-header form). Inter-arrival time was deliberately **excluded** — it proved leaky/unstable in the offline study.
- **Training** (offline, `research/mask-generation/r2/`): a teacher/student setup — nDPI labels the synthetic + real captures, the GBDT learns to reproduce the verdict. Honest **grouped** cross-validation (split by mask, so no leakage): **93.3 %** masked-domain accuracy, and the binary "reads-as-tunnel" gate reached **precision + recall = 1.000** — it never rejected a genuine masked flow and caught every broken one.
- **Deployment**: the trained tree ensemble is exported to **constant weights embedded in the server binary** (the same idea as the baked MLP), traversed in place — no model file, no allocation on the hot path. Gated behind the `neural` Cargo feature.

#### How it composes with Neural Resonance

The GBDT verdict is a **sibling signal**, not a replacement. Both feed the same gateway rotate decision:

- **Neural Resonance** watches for *drift from self* (this mask stopped looking like itself).
- **ML-DPI gate** watches for *reads-as-tunnel* (this mask looks like obfuscation to a DPI-style classifier).

Either crossing its threshold ⇒ the mask is considered compromised ⇒ rotate. Two independent detectors of different families make the trigger robust: a DPI technique that fools one is unlikely to fool both.

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

