//! Shared upload pipeline for AIVPN clients.
//!
//! Both the CLI client and Android core use this module to avoid duplicating
//! the biased-select + burst-drain + keepalive upload loop.

use std::sync::Arc;
use std::time::Duration;

use crate::client_wire::{build_inner_packet, build_random_mdh_packet, DEFAULT_MDH_LEN};
use crate::crypto::SessionKeys;
use crate::error::{Error, Result};
use crate::fec::FecEncoder;
use crate::protocol::{ControlPayload, InnerType};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;

// ──────────── Configuration ────────────

/// Tuneable knobs for the upload pipeline shared by all clients.
pub struct UploadConfig {
    /// Maximum additional packets to drain from the channel after the first
    /// recv without yielding back to the async executor.
    pub burst_size: usize,
    /// How often a keepalive is sent when there is no data traffic.
    pub keepalive_interval: Duration,
    /// Shared keepalive interval in milliseconds; updated dynamically by the client.
    /// When set, the upload loop polls this value each tick and resets the interval
    /// when the value changes (e.g. after KeepaliveAck / AdaptiveHint).
    pub keepalive_ms: Option<Arc<portable_atomic::AtomicU64>>,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            burst_size: 63,
            keepalive_interval: Duration::from_secs(25),
            keepalive_ms: None,
        }
    }
}

// ──────────── Trait: pluggable packet encryption ────────────

/// Platform-specific packet encryption and framing.
///
/// The CLI client implements this via its MimicryEngine (variable MDH,
/// traffic-shaped padding, FSM updates). Android implements it via
/// [`ZeroMdhEncryptor`] (fixed zero-length MDH, random padding).
pub trait PacketEncryptor: Send {
    /// Encrypt a TUN data payload into a ready-to-send UDP datagram.
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>>;
    /// Encrypt an arbitrary control message into a ready-to-send UDP datagram.
    fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>>;
    /// Encrypt a keepalive control message into a ready-to-send UDP datagram.
    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>>;
    /// Called after a data datagram has been successfully sent.
    /// Use this for stats tracking, FSM transitions, etc.
    fn on_data_sent(&mut self, payload_len: usize);
    /// Return a pre-encrypted FEC repair datagram if one is ready, else None.
    /// Called after every data send; default is a no-op.
    fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Encrypt a keepalive stamped with `send_ts` (milliseconds since UNIX epoch).
    /// The server echoes `send_ts` in `KeepaliveAck` so the client can measure RTT.
    /// Default delegates to `encrypt_keepalive()` with `send_ts = 0` (no RTT tracking).
    fn encrypt_keepalive_ts(&mut self, _send_ts: u64) -> Result<Vec<u8>> {
        self.encrypt_keepalive()
    }
}

// ──────────── Trait: outbound wire inspector (optional) ────────────

/// Optional hook that observes every outbound *wire* datagram just before it is
/// sent, and may ask the pipeline to emit a control payload in response.
///
/// This is the seam the client-side inline ML-DPI self-gate
/// (`crate::dpi_gate::ClientSelfGate`, behind `client-dpi-gate`) plugs into: it
/// samples the shaped bytes a DPI box would see and, when its own flow starts
/// reading as a tunnel, returns a [`ControlPayload::MaskPreference`] rotate
/// request that the pipeline encrypts and sends through the normal control path
/// — no new wire message. Default builds pass `None` and pay nothing.
pub trait OutboundInspector: Send {
    /// Observe one ready-to-send wire datagram. Return `Some(payload)` to have
    /// the pipeline encrypt and send that control message next, else `None`.
    fn observe(&mut self, wire: &[u8]) -> Option<ControlPayload>;
}

// ──────────── Ready-made encryptor: zero MDH ────────────

/// Encryptor using random MDH — suitable for Android and any
/// client that does not require Mimicry traffic shaping.
/// Each packet gets fresh random MDH bytes (Issue #30 fix).
pub struct ZeroMdhEncryptor {
    keys: SessionKeys,
    counter: u64,
    seq: u16,
    mdh_len: usize,
    fec_encoder: Option<FecEncoder>,
    pending_fec: Option<Vec<u8>>,
}

impl ZeroMdhEncryptor {
    pub fn new(keys: SessionKeys, counter: u64, seq: u16) -> Self {
        Self {
            keys,
            counter,
            seq,
            mdh_len: DEFAULT_MDH_LEN,
            fec_encoder: None,
            pending_fec: None,
        }
    }

    pub fn with_mdh_len(keys: SessionKeys, counter: u64, seq: u16, mdh_len: usize) -> Self {
        Self {
            keys,
            counter,
            seq,
            mdh_len,
            fec_encoder: None,
            pending_fec: None,
        }
    }

    /// Enable XOR FEC with the given group size. group_size=0 disables FEC.
    pub fn set_fec_group(&mut self, group_size: u8) {
        self.fec_encoder = if group_size > 0 {
            Some(FecEncoder::new(group_size, 1500))
        } else {
            None
        };
    }
}

impl PacketEncryptor for ZeroMdhEncryptor {
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let inner = build_inner_packet(InnerType::Data, self.seq, payload);
        self.seq = self.seq.wrapping_add(1);
        let pkt =
            build_random_mdh_packet(&self.keys, &mut self.counter, &inner, None, self.mdh_len)?;
        if let Some(fec) = self.fec_encoder.as_mut() {
            if let Some(repair) = fec.feed(payload) {
                let repair_inner =
                    build_inner_packet(InnerType::FecRepair, self.seq, &repair.encode());
                self.seq = self.seq.wrapping_add(1);
                if let Ok(enc) = build_random_mdh_packet(
                    &self.keys,
                    &mut self.counter,
                    &repair_inner,
                    None,
                    self.mdh_len,
                ) {
                    self.pending_fec = Some(enc);
                }
            }
        }
        Ok(pkt)
    }

    fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
        let bytes = payload.encode()?;
        let inner = build_inner_packet(InnerType::Control, self.seq, &bytes);
        self.seq = self.seq.wrapping_add(1);
        build_random_mdh_packet(&self.keys, &mut self.counter, &inner, None, self.mdh_len)
    }

    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
        self.encrypt_keepalive_ts(0)
    }

    fn encrypt_keepalive_ts(&mut self, send_ts: u64) -> Result<Vec<u8>> {
        let keepalive = ControlPayload::Keepalive { send_ts }.encode()?;
        let inner = build_inner_packet(InnerType::Control, self.seq, &keepalive);
        self.seq = self.seq.wrapping_add(1);
        build_random_mdh_packet(&self.keys, &mut self.counter, &inner, None, self.mdh_len)
    }

    fn on_data_sent(&mut self, _payload_len: usize) {}

    fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
        self.pending_fec.take()
    }
}

// ──────────── The upload loop ────────────

/// Returns true for transient OS-level errors where retrying immediately
/// or just dropping the packet is safer than triggering a full reconnect.
fn is_transient_send_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        NetworkUnreachable
            | HostUnreachable
            | NetworkDown
            | AddrNotAvailable
            | Interrupted
            // EPERM: a local firewall dropped the datagram. Our own kill-switch
            // briefly flushes and re-adds its accept rules on reactivation, so a
            // send to the server can transiently hit EPERM. Dropping the packet
            // is far safer than tearing the session down into a reconnect storm.
            | PermissionDenied
    )
}

/// Send helper that tolerates transient network errors (e.g. mid-switch on mobile).
/// Returns Ok(()) on success or transient error (logged, packet dropped).
/// Returns Err only on fatal errors (e.g. EBADF = socket closed).
async fn send_tolerant(udp: &UdpSocket, data: &[u8]) -> Result<()> {
    match udp.send(data).await {
        Ok(_) => Ok(()),
        Err(e) if is_transient_send_error(&e) => {
            tracing::debug!("upload: transient send error (dropped packet): {e}");
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// Run the upload loop: pull TUN packets from `rx`, encrypt via `enc`, send
/// over `udp`. Uses biased `select!` to prioritise data over keepalives and a
/// burst-drain after the first recv to amortise per-packet scheduler overhead.
///
/// Control messages are drained opportunistically between every packet of
/// the data burst (see the `try_recv` call inside the loop below). Without
/// this, `biased` `select!` always re-polls the data branch first on every
/// outer-loop iteration; under sustained continuous data traffic (e.g. an
/// active SOCKS5 proxy session), `rx.recv()` is essentially always instantly
/// ready, so the `control_rx` branch of the outer `select!` could be starved
/// indefinitely — a `KeyRotate` response could sit unencrypted for seconds.
/// The caller's inline-rekey handler blocks the entire receive loop on an
/// ack rendezvous with this exact send (see `client.rs`
/// `handle_server_control`'s `KeyRotate` arm), so a long stall here lets a
/// large backlog of in-flight packets accumulate in the OS socket receive
/// buffer. Draining that backlog afterwards is not free: each packet that
/// needs the transition-key fallback costs a full exhaustive
/// `RecvWindow::find_counter` scan (measured ~1-2ms in a release build) on
/// the primary path alone before even trying the fallback. A big enough
/// backlog can burn through the receiver's 2-second transition grace window
/// while still draining, permanently losing the fallback for whatever is
/// left of the backlog (and, since the response was still stuck queued
/// while the server has not yet received the rekey confirmation, any
/// further old-key traffic that keeps arriving) — the whole session then
/// desyncs. This starvation window in the sender is the actual root trigger;
/// checking `control_rx` between every burst-drained data packet keeps the
/// worst-case control latency to O(1) packet, not O(unbounded backlog).
///
/// Returns `Err` on fatal I/O or channel close. Never returns `Ok` — the
/// caller is expected to `.abort()` the task when the session ends.
pub async fn run_upload_loop(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    mut control_rx: Option<&mut mpsc::Receiver<ControlPayload>>,
    udp: &Arc<UdpSocket>,
    enc: &mut impl PacketEncryptor,
    config: &UploadConfig,
    mut inspector: Option<&mut dyn OutboundInspector>,
) -> Result<()> {
    use std::sync::atomic::Ordering;

    // Feed one just-sent data datagram to the optional outbound inspector; if it
    // asks for a control message (e.g. a MaskPreference rotate-request from the
    // client self-gate), encrypt and send it through the normal control path.
    // `None` inspector (the default) is a no-op.
    async fn inspect_sent(
        inspector: &mut Option<&mut dyn OutboundInspector>,
        udp: &Arc<UdpSocket>,
        enc: &mut impl PacketEncryptor,
        wire: &[u8],
    ) -> Result<()> {
        if let Some(insp) = inspector.as_deref_mut() {
            if let Some(req) = insp.observe(wire) {
                let enc_req = enc.encrypt_control(&req)?;
                send_tolerant(udp, &enc_req).await?;
            }
        }
        Ok(())
    }
    let mut current_ka_ms = config.keepalive_interval.as_millis() as u64;
    let mut ka_interval = time::interval_at(tokio::time::Instant::now(), config.keepalive_interval);
    let mut data_packet_count: u64 = 0;
    // Last time a keepalive actually went out. Bounds how long continuous data
    // may suppress keepalives (see the data branch): keepalives are the only RTT
    // probe, so unbounded suppression leaves connection quality stuck at 0/100 on
    // a busy tunnel.
    let mut last_keepalive = tokio::time::Instant::now();

    // Drains and sends every control payload currently queued, without
    // blocking. Called between data sends so control traffic (especially a
    // KeyRotate response the receive loop is blocked waiting to observe)
    // can never be starved by a continuous run of data packets.
    async fn drain_pending_control(
        control_rx: &mut Option<&mut mpsc::Receiver<ControlPayload>>,
        udp: &Arc<UdpSocket>,
        enc: &mut impl PacketEncryptor,
    ) -> Result<()> {
        if let Some(crx) = control_rx.as_mut() {
            loop {
                match crx.try_recv() {
                    Ok(payload) => {
                        let encrypted = enc.encrypt_control(&payload)?;
                        send_tolerant(udp, &encrypted).await?;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }
        Ok(())
    }

    loop {
        tokio::select! {
            biased;

            // ── Data path (highest priority) ──
            maybe_pkt = rx.recv() => {
                let pkt_data = match maybe_pkt {
                    Some(p) => p,
                    None => return Err(Error::Channel("TUN->UDP channel closed".into())),
                };

                let encrypted = enc.encrypt_data(&pkt_data)?;
                send_tolerant(udp, &encrypted).await?;
                inspect_sent(&mut inspector, udp, enc, &encrypted).await?;
                if let Some(repair) = enc.take_fec_repair() {
                    send_tolerant(udp, &repair).await?;
                }
                data_packet_count = data_packet_count.wrapping_add(1);
                enc.on_data_sent(pkt_data.len());

                // Burst drain: process up to burst_size without yielding.
                // Check control_rx on every iteration (not just once the
                // burst ends) so a pending KeyRotate/other control response
                // is never stuck behind a long, continuous run of data
                // traffic — see the starvation note on this function.
                for _ in 0..config.burst_size {
                    drain_pending_control(&mut control_rx, udp, enc).await?;
                    match rx.try_recv() {
                        Ok(pkt) => {
                            let encrypted = enc.encrypt_data(&pkt)?;
                            send_tolerant(udp, &encrypted).await?;
                            inspect_sent(&mut inspector, udp, enc, &encrypted).await?;
                            if let Some(repair) = enc.take_fec_repair() {
                                send_tolerant(udp, &repair).await?;
                            }
                            data_packet_count = data_packet_count.wrapping_add(1);
                            enc.on_data_sent(pkt.len());
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            return Err(Error::Channel("TUN->UDP channel closed".into()));
                        }
                    }
                }
                // Final check: pick up anything queued during the very last
                // burst-drain packet before looping back to the outer select.
                drain_pending_control(&mut control_rx, udp, enc).await?;
                // Suppress the next keepalive tick ONLY when one went out
                // recently: a keepalive right after real data wastes bandwidth and
                // the server's ACK resets the peer's rx-silence timer anyway. But do
                // NOT let continuous data STARVE keepalives forever — they are the
                // only RTT probe, so a busy tunnel would otherwise never measure
                // connection quality (score stuck at 0/100). Once a keepalive is
                // overdue, let the tick fire so quality keeps updating under load.
                if last_keepalive.elapsed() < Duration::from_millis(current_ka_ms) {
                    ka_interval.reset();
                }
            }

            // ── Keepalive (fires only when data path is idle) ──
            _ = ka_interval.tick() => {
                // Check if keepalive interval was updated dynamically
                if let Some(ref ka_atomic) = config.keepalive_ms {
                    let new_ms = ka_atomic.load(Ordering::Relaxed);
                    if new_ms > 0 && new_ms != current_ka_ms {
                        current_ka_ms = new_ms;
                        ka_interval = time::interval(Duration::from_millis(new_ms));
                    }
                }
                let encrypted = enc.encrypt_keepalive()?;
                send_tolerant(udp, &encrypted).await?;
                last_keepalive = tokio::time::Instant::now();
            }

            // ── Control payloads ──
            maybe_ctrl = async {
                if let Some(crx) = control_rx.as_mut() {
                    crx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let payload = match maybe_ctrl {
                    Some(p) => p,
                    // All control senders are gone: the session is tearing
                    // down (the receive loop dropped its sender). Returning
                    // `None` here used to be IGNORED, and since a closed
                    // channel's recv() resolves immediately on every poll,
                    // this arm kept winning the select! — a 100% CPU busy
                    // spin for the rest of the session. Exit like the data
                    // channel does ("TUN->UDP channel closed" above).
                    None => return Err(Error::Channel("control channel closed".into())),
                };
                let encrypted = enc.encrypt_control(&payload)?;
                send_tolerant(udp, &encrypted).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// Minimal `PacketEncryptor` test double: no real crypto, just tags each
    /// outgoing datagram with a marker byte (0 = data, 1 = control, 2 =
    /// keepalive) followed by an ever-increasing sequence number, so a test
    /// can identify what kind of payload was sent and in what order without
    /// caring about wire-format details.
    struct MarkerEncryptor {
        next_seq: u32,
    }

    impl PacketEncryptor for MarkerEncryptor {
        fn encrypt_data(&mut self, _payload: &[u8]) -> Result<Vec<u8>> {
            let seq = self.next_seq;
            self.next_seq += 1;
            Ok([&[0u8][..], &seq.to_le_bytes()].concat())
        }

        fn encrypt_control(&mut self, _payload: &ControlPayload) -> Result<Vec<u8>> {
            let seq = self.next_seq;
            self.next_seq += 1;
            Ok([&[1u8][..], &seq.to_le_bytes()].concat())
        }

        fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
            let seq = self.next_seq;
            self.next_seq += 1;
            Ok([&[2u8][..], &seq.to_le_bytes()].concat())
        }

        fn on_data_sent(&mut self, _payload_len: usize) {}
    }

    /// Regression test for the control-channel busy-spin: when every control
    /// sender is dropped, `control_rx.recv()` resolves to `None` on EVERY
    /// poll, and ignoring that used to keep the `select!` hot — a 100% CPU
    /// spin for the rest of the session. The loop must instead terminate with
    /// an error, exactly like a closed data channel does.
    #[tokio::test]
    async fn test_closed_control_channel_terminates_upload_loop() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        client_sock.connect(server_addr).await.unwrap();

        let config = UploadConfig::default();
        // Data channel stays open (sender alive) so the ONLY closed channel is
        // the control one — the error must be the control-channel close.
        let (_data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(4);
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        drop(control_tx);

        let mut enc = MarkerEncryptor { next_seq: 0 };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_upload_loop(
                &mut data_rx,
                Some(&mut control_rx),
                &client_sock,
                &mut enc,
                &config,
                None,
            ),
        )
        .await;

        match result {
            Ok(Err(e)) => assert!(
                e.to_string().contains("control channel closed"),
                "expected the control-channel-close error, got: {e}"
            ),
            Ok(Ok(())) => panic!("run_upload_loop must not return Ok on a closed control channel"),
            Err(_) => panic!("run_upload_loop did not terminate within 2s — busy-spin regression"),
        }
    }

    /// Regression test for the control-starvation bug: under `biased`
    /// `select!`, a continuous run of data packets used to be able to starve
    /// `control_rx` indefinitely, since the burst-drain loop only checked
    /// `control_rx` once *after* fully draining up to `burst_size` data
    /// packets (and the outer `select!` always re-picks the data branch
    /// first whenever `rx.recv()` is immediately ready). In production this
    /// is exactly what let a `KeyRotate` response sit unencrypted for long
    /// enough that the receive loop's transition-key grace window could
    /// expire while draining the resulting backlog — see the long comment on
    /// `run_upload_loop`.
    ///
    /// To reproduce "data is continuously, immediately available" without
    /// relying on wall-clock races against a live feeder task (which made
    /// earlier versions of this test flaky — real UDP loopback traffic is
    /// genuinely lossy under sustained flood, and a live producer can't
    /// deterministically keep the channel saturated relative to the
    /// consumer), both the data and control payloads are queued in full
    /// *before* `run_upload_loop` even starts: the data channel is
    /// pre-filled well beyond `burst_size`, and the one control payload is
    /// already sitting in `control_rx`. This makes `rx.recv()`/`try_recv()`
    /// unconditionally, deterministically ready for a long stretch — exactly
    /// the condition `biased select!` needs to keep re-picking the data
    /// branch — with no timing dependency at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_control_message_not_starved_by_continuous_data_traffic() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        client_sock.connect(server_addr).await.unwrap();

        let config = UploadConfig::default();
        // Comfortably more than one burst-drain cycle's worth of data,
        // pre-queued so it is unconditionally ready from the very first
        // poll — no producer task needed, no timing race possible.
        let prefill = config.burst_size * 20;
        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(prefill + 1);
        for _ in 0..prefill {
            data_tx.try_send(vec![0u8; 16]).unwrap();
        }
        // Keep a sender alive so the channel doesn't close once drained past
        // the pre-filled amount (irrelevant to the assertion, which only
        // looks at packets sent before the control marker, but avoids
        // `run_upload_loop` erroring out on a closed channel mid-test).
        let _data_tx_keepalive = data_tx.clone();
        drop(data_tx);

        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        // The control payload is already queued before the loop starts —
        // there is a data backlog of `prefill` packets ahead of it.
        control_tx
            .try_send(ControlPayload::Keepalive { send_ts: 0 })
            .unwrap();

        let mut enc = MarkerEncryptor { next_seq: 0 };
        let upload_fut = run_upload_loop(
            &mut data_rx,
            Some(&mut control_rx),
            &client_sock,
            &mut enc,
            &config,
            None,
        );

        // Count data datagrams observed on the wire before the control
        // marker (byte 1) shows up.
        let data_packets_before_control = Arc::new(AtomicUsize::new(0));
        let counter = data_packets_before_control.clone();
        let receiver = async move {
            let mut buf = [0u8; 64];
            loop {
                let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
                if n == 0 {
                    continue;
                }
                match buf[0] {
                    1 => return, // control marker observed
                    _ => {
                        counter.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            }
        };

        tokio::select! {
            _ = upload_fut => panic!("run_upload_loop returned unexpectedly"),
            _ = receiver => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                panic!(
                    "control message was not observed within 10s — starved by \
                     a pre-queued backlog of {} data packets (data packets \
                     seen so far: {})",
                    prefill,
                    data_packets_before_control.load(AtomicOrdering::Relaxed)
                );
            }
        }

        let seen = data_packets_before_control.load(AtomicOrdering::Relaxed);
        assert!(
            seen < config.burst_size * 3,
            "control message was starved behind {} of the {} pre-queued data \
             packets — expected it to be picked up within roughly one \
             burst-drain cycle ({} packets), not stuck behind the whole \
             backlog",
            seen,
            prefill,
            config.burst_size
        );
    }
}
