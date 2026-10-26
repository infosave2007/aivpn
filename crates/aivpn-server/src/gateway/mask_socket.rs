//! Протокольное состояние маски поверх общего UDP-сокета.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{collections::VecDeque, io, net::SocketAddr, sync::Arc, time::Instant};

use aivpn_common::{
    error::Result,
    mask_state::MaskState,
    quic_mask::{QuicMask, QuicMaskOutput, QuicRouting},
    rtc_carrier::{RtcCarrier as RtcMask, RtcKind},
    Error,
};
use dashmap::{mapref::entry::Entry, DashMap};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore},
};

const PEERS: usize = 1024;
const QUEUE: usize = 64;
const QUIC_QUEUE: usize = 4 * crate::batch_io::MAX_BATCH;
const PENDING_QUIC: usize = 128;
const PENDING_PER_PEER: usize = 2;
const PENDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
static QUIC_RECEIVE_DROPS: AtomicU64 = AtomicU64::new(0);
pub(crate) type WireObserver = Arc<dyn Fn([u8; 16], &[u8]) + Send + Sync>;
type SessionOwner = std::sync::Weak<parking_lot::Mutex<crate::session::Session>>;

#[derive(Clone)]
struct Peer {
    ready: Arc<AtomicBool>,
    quic: Option<QuicPeer>,
    rtc: Option<Arc<RtcAdmission>>,
    incoming: mpsc::Sender<Vec<u8>>,
    outgoing: mpsc::Sender<(Vec<u8>, bool)>,
}

struct RtcAdmission {
    session_id: [u8; 16],
    offer: MaskState,
    answer: MaskState,
    inner_budget: usize,
}

enum MaskEngine {
    Quic(QuicMask),
    Rtc(RtcMask),
}

impl MaskEngine {
    fn observe_verified_wire(&mut self) {
        match self {
            Self::Quic(engine) => engine.observe_verified_wire(),
            Self::Rtc(engine) => engine.observe_verified_wire(),
        }
    }

    fn take_verified_wire(&mut self) -> Vec<Vec<u8>> {
        match self {
            Self::Quic(engine) => engine.take_verified_wire(),
            Self::Rtc(engine) => engine.take_verified_wire(),
        }
    }

    fn poll(&mut self, now: Instant) -> Result<QuicMaskOutput> {
        match self {
            Self::Quic(engine) => engine.poll(now),
            Self::Rtc(engine) => engine.poll(now).map(|output| QuicMaskOutput {
                wire: output.wire,
                payloads: output.payloads,
                connected: output.connected,
            }),
        }
    }
    fn deadline(&mut self) -> Option<Instant> {
        match self {
            Self::Quic(engine) => engine.deadline(),
            Self::Rtc(engine) => engine.deadline(),
        }
    }
    fn receive(&mut self, packet: &[u8], peer: SocketAddr, now: Instant) -> Result<()> {
        match self {
            Self::Quic(engine) => engine.receive(packet, peer, now),
            Self::Rtc(engine) => engine.receive(packet, now),
        }
    }
    fn send(&mut self, packet: &[u8], now: Instant) -> Result<bool> {
        match self {
            Self::Quic(engine) => engine.send(packet).map(|_| true),
            Self::Rtc(engine) if !engine.connected() => Ok(false),
            Self::Rtc(engine) => engine.send(packet, now).map(|_| true),
        }
    }
    fn close(&mut self, now: Instant) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Quic(engine) => engine.close(now),
            Self::Rtc(_) => Ok(vec![]),
        }
    }
}

#[derive(Clone)]
struct QuicPeer {
    routing: QuicRouting,
    context: QuicContext,
}

fn try_queue<T>(
    sender: &mpsc::Sender<T>,
    limit: usize,
    make_packet: impl FnOnce() -> T,
) -> std::result::Result<(), mpsc::error::TrySendError<()>> {
    let permit = sender.try_reserve()?;
    // Резерв учитывается в capacity до проверки. Параллельные producers
    // не могут одновременно занять последний логический pending-слот.
    if sender.max_capacity() - sender.capacity() > limit {
        return Err(mpsc::error::TrySendError::Full(()));
    }
    permit.send(make_packet());
    Ok(())
}

#[cfg(test)]
pub(super) type BeforeCommitHook = Arc<dyn Fn() + Send + Sync>;

/// Поколение проверенного TLS transport. Само по себе не дает VPN admission.
#[derive(Clone)]
pub(crate) struct QuicContext {
    generation: Arc<()>,
    pub local: Option<crate::udp_source::LocalEndpoint>,
    admission: Arc<parking_lot::Mutex<QuicAdmission>>,
    commit_gate: Arc<parking_lot::Mutex<()>>,
    retired: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    work_budget: Arc<parking_lot::Mutex<super::preauth::PreauthBudget>>,
    #[cfg(test)]
    pub(super) before_commit: Arc<parking_lot::Mutex<Option<BeforeCommitHook>>>,
    #[cfg(test)]
    before_ingress_owner: Arc<parking_lot::Mutex<Option<BeforeCommitHook>>>,
    #[cfg(test)]
    work_attempts: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    work_calls: Arc<std::sync::atomic::AtomicUsize>,
}

struct QuicAdmission {
    owner: Option<SessionOwner>,
    pending_permit: Option<OwnedSemaphorePermit>,
}

pub(crate) struct DecodedPacket {
    pub payload: Vec<u8>,
    pub peer: SocketAddr,
    pub quic: bool,
    pub context: Option<QuicContext>,
}

impl QuicContext {
    fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.generation, &other.generation)
    }

    fn owner(&self) -> Option<SessionOwner> {
        self.admission.lock().owner.clone()
    }

    fn queue_limit(&self, peer: SocketAddr) -> usize {
        if !self.active.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return QUEUE;
        }
        let Some(owner) = self.owner().and_then(|owner| owner.upgrade()) else {
            return QUEUE;
        };
        let admitted = {
            let owner = owner.lock();
            owner.client_admitted
                && owner.is_ratcheted
                && !owner.is_removed()
                && owner.client_addr == peer
        };
        if admitted && self.active.load(Ordering::Acquire) && !self.retired.load(Ordering::Acquire)
        {
            QUIC_QUEUE
        } else {
            QUEUE
        }
    }

    fn protocol_work<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
        #[cfg(test)]
        self.work_attempts.fetch_add(1, Ordering::SeqCst);
        if self.retired.load(Ordering::Acquire) {
            return Err(Error::InvalidPacket("Поколение QUIC уже закрыто"));
        }
        let _lease = if self.active.load(Ordering::Acquire) {
            None
        } else {
            match super::preauth::PreauthLease::acquire(self.work_budget.clone()) {
                Some(lease) => Some(lease),
                None => return Ok(None),
            }
        };
        #[cfg(test)]
        self.work_calls.fetch_add(1, Ordering::SeqCst);
        operation().map(Some)
    }

    fn pending(&self) -> bool {
        !self.active.load(Ordering::Acquire) && !self.retired.load(Ordering::Acquire)
    }

    fn retire_locked(&self) {
        self.retired.store(true, Ordering::Release);
        self.admission.lock().pending_permit.take();
    }

    fn retire(&self) {
        let _guard = self.commit_gate.lock();
        self.retire_locked();
    }
}

pub(super) struct QuicCommitGuard<'a> {
    socket: &'a MaskSocket,
    peer: SocketAddr,
    context: &'a QuicContext,
    current: Peer,
    _guard: parking_lot::MutexGuard<'a, ()>,
}

impl QuicCommitGuard<'_> {
    pub fn authenticate(&mut self, session: &Arc<parking_lot::Mutex<crate::session::Session>>) {
        if self.context.active.load(Ordering::Acquire) {
            return;
        }
        {
            let mut admission = self.context.admission.lock();
            admission.owner = Some(Arc::downgrade(session));
            admission.pending_permit.take();
        }
        self.context.active.store(true, Ordering::Release);
        let previous = self.socket.peers.insert(self.peer, self.current.clone());
        if let Some(previous) = previous.and_then(|previous| previous.quic) {
            if !previous.context.same_generation(self.context) {
                previous.context.retire_locked();
                remove_quic_route(&self.socket.quic_transports, self.peer, &previous.context);
            }
        }
    }
}

fn remove_quic_route(
    transports: &DashMap<SocketAddr, Vec<Peer>>,
    peer: SocketAddr,
    context: &QuicContext,
) {
    if let Entry::Occupied(mut entry) = transports.entry(peer) {
        entry.get_mut().retain(|current| {
            !current
                .quic
                .as_ref()
                .is_some_and(|quic| quic.context.same_generation(context))
        });
        if entry.get().is_empty() {
            entry.remove();
        }
    }
}

fn retire_quic_generation(
    peers: &DashMap<SocketAddr, Peer>,
    transports: &DashMap<SocketAddr, Vec<Peer>>,
    peer: SocketAddr,
    context: &QuicContext,
) {
    context.retire();
    peers.remove_if(&peer, |_, current| {
        current
            .quic
            .as_ref()
            .is_some_and(|quic| quic.context.same_generation(context))
    });
    remove_quic_route(transports, peer, context);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wire_samples_require_admission_pfs_and_a_live_session() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let samples = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let sink = samples.clone();
        let socket = MaskSocket::with_wire_observer(
            raw,
            Some(Arc::new(move |sid, wire| {
                sink.lock().push((sid, wire.to_vec()));
            })),
        );
        let server_key = aivpn_common::crypto::KeyPair::generate();
        let client_key = aivpn_common::crypto::KeyPair::generate();
        let manager = crate::session::SessionManager::new(
            server_key,
            ed25519_dalek::SigningKey::from_bytes(&[41; 32]),
            aivpn_common::mask::preset_masks::webrtc_vk_teams_v1(),
        );
        let session = manager
            .create_session(
                "127.0.0.1:30000".parse().unwrap(),
                client_key.public_key_bytes(),
                None,
                None,
            )
            .unwrap();
        let sid = session.lock().session_id;
        socket.observe_plain_wire(&session, b"before-admission");
        session.lock().client_admitted = true;
        socket.observe_plain_wire(&session, b"before-pfs");
        assert!(samples.lock().is_empty());
        session.lock().is_ratcheted = true;
        socket.observe_plain_wire(&session, b"authenticated");
        assert_eq!(&*samples.lock(), &[(sid, b"authenticated".to_vec())]);
        assert!(manager.remove_session(&sid).is_some());
        socket.observe_plain_wire(&session, b"removed-session");
        assert_eq!(samples.lock().len(), 1);
    }

    #[tokio::test]
    async fn plain_wire_sampling_counts_verified_frames_instead_of_aead_counters() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let samples = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let sink = samples.clone();
        let socket = MaskSocket::with_wire_observer(
            raw,
            Some(Arc::new(move |_, wire| {
                sink.lock().push(wire.to_vec());
            })),
        );
        let mut owner = crate::session::Session::new(
            [7; 16],
            "127.0.0.1:30000".parse().unwrap(),
            aivpn_common::crypto::derive_session_keys(&[1; 32], None, &[2; 32]),
            [3; 32],
        );
        owner.client_admitted = true;
        owner.is_ratcheted = true;
        let session = Arc::new(parking_lot::Mutex::new(owner));
        for index in 0u8..33 {
            socket.observe_plain_wire(&session, &[index]);
        }
        assert_eq!(*samples.lock(), vec![vec![0], vec![16], vec![32]]);
    }

    #[tokio::test]
    async fn rtc_pending_media_never_sends_downlink_data_as_raw_bootstrap() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = raw.local_addr().unwrap();
        let socket = MaskSocket::new(raw);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let owner = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer_address,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        owner.lock().mask = Some(mask.clone());
        let rtc = RtcMask::new(false, peer_address, address, address, Instant::now()).unwrap();
        socket
            .accept_rtc_offer(
                &MaskState {
                    offer_id: [3; 16],
                    answer: false,
                    mask_id: mask.mask_id,
                    mask_version: mask.version,
                    parameters: rtc.parameters(),
                },
                &owner,
                peer_address,
            )
            .unwrap();
        socket
            .send_data_with_mask(b"encrypted DATA", peer_address, true)
            .await
            .unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            peer.recv(&mut [0; 2048])
        )
        .await
        .is_err());
        socket
            .send_with_mask(b"bootstrap control", peer_address, false)
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], b"bootstrap control");
        socket.use_plain_mask(peer_address);
        assert!(socket
            .send_data_with_mask(b"encrypted DATA", peer_address, true)
            .await
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        assert!(peer.try_recv(&mut [0; 2048]).is_err());
    }

    #[tokio::test]
    async fn closed_peer_cleanup_cannot_remove_replacement_generation() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30000".parse().unwrap();
        let (old, old_rx) = mpsc::channel(QUEUE);
        drop(old_rx);
        let (new, _new_rx) = mpsc::channel(QUEUE);
        let (outgoing, _out_rx) = mpsc::channel(QUEUE);
        // Входящий пакет уже увидел закрытую старую очередь. Между отпусканием
        // DashMap guard и очисткой параллельный handshake заменил поколение.
        socket.peers.insert(
            peer,
            Peer {
                ready: Arc::new(AtomicBool::new(false)),
                quic: None,
                rtc: None,
                incoming: new.clone(),
                outgoing,
            },
        );
        socket.retire_closed_peer(peer, &old);
        assert!(socket
            .peers
            .get(&peer)
            .is_some_and(|current| current.incoming.same_channel(&new)));
    }

    #[tokio::test]
    async fn rtc_actor_releases_slot_after_owning_session_disappears() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = raw.local_addr().unwrap();
        let server = MaskSocket::new(raw);
        let peer: SocketAddr = "127.0.0.1:30000".parse().unwrap();
        let owner = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        let engine = RtcMask::new(false, peer, address, address, Instant::now()).unwrap();
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        owner.lock().mask = Some(mask.clone());
        let offer = MaskState {
            offer_id: [7; 16],
            answer: false,
            mask_id: mask.mask_id,
            mask_version: mask.version,
            parameters: engine.parameters(),
        };
        server.accept_rtc_offer(&offer, &owner, peer).unwrap();
        assert_eq!(server.permits.available_permits(), PEERS - 1);
        drop(owner);
        tokio::time::timeout(std::time::Duration::from_millis(1500), async {
            while server.is_stateful(peer) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("RTC живет отдельно от удаленной сессии");
        assert_eq!(server.permits.available_permits(), PEERS);
    }

    #[tokio::test]
    async fn full_actor_pool_allows_authenticated_generation_replacement() {
        for change_version in [false, true] {
            let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = raw.local_addr().unwrap();
            let socket = MaskSocket::new(raw);
            let peer = "127.0.0.1:30000".parse().unwrap();
            let owner = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
                [7; 16],
                peer,
                aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
                [9; 32],
            )));
            let mut mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
            owner.lock().mask = Some(mask.clone());
            let engine = RtcMask::new(false, peer, address, address, Instant::now()).unwrap();
            let mut offer = MaskState {
                offer_id: [7; 16],
                answer: false,
                mask_id: mask.mask_id.clone(),
                mask_version: mask.version,
                parameters: engine.parameters(),
            };
            socket.accept_rtc_offer(&offer, &owner, peer).unwrap();
            let occupied = socket
                .permits
                .clone()
                .acquire_many_owned((PEERS - 1) as u32)
                .await
                .unwrap();
            assert_eq!(socket.accept_rtc_offer(&offer, &owner, peer).unwrap(), {
                socket
                    .peers
                    .get(&peer)
                    .unwrap()
                    .rtc
                    .as_ref()
                    .unwrap()
                    .answer
                    .clone()
            });
            let retired_offer = offer.clone();
            if change_version {
                mask.version += 1;
            } else {
                mask.signature[0] ^= 1;
            }
            owner.lock().mask = Some(mask.clone());
            offer.mask_version = mask.version;
            offer.offer_id = [8; 16];
            offer.parameters = RtcMask::new(false, peer, address, address, Instant::now())
                .unwrap()
                .parameters();
            assert!(socket.accept_rtc_offer(&offer, &owner, peer).is_err());
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while socket.permits.available_permits() == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            socket.accept_rtc_offer(&offer, &owner, peer).unwrap();
            assert!(socket
                .accept_rtc_offer(&retired_offer, &owner, peer)
                .is_err());
            assert_eq!(socket.permits.available_permits(), 0);
            drop(occupied);
            socket.use_plain_mask(peer);
        }
    }

    #[tokio::test]
    async fn rtc_uses_existing_socket_and_repeated_offer_does_not_restart_keys() {
        exercise_rtc_socket("webrtc_zoom_v3").await;
    }

    #[tokio::test]
    async fn turn_rtc_uses_existing_socket_and_repeated_offer_does_not_restart_keys() {
        exercise_rtc_socket("webrtc_sberjazz_v1").await;
        exercise_rtc_socket("telegram_calls_v1").await;
    }

    #[tokio::test]
    async fn sdes_srtp_uses_existing_socket_and_repeated_offer_does_not_restart_keys() {
        exercise_rtc_socket("whatsapp_voip_v1").await;
    }

    async fn exercise_rtc_socket(id: &str) {
        use aivpn_common::{mask_io, transport::udp_transport};
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = raw.local_addr().unwrap();
        let server = MaskSocket::new(raw.clone());
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let peer = udp.local_addr().unwrap();
        let mask = aivpn_common::mask::preset_masks::by_id(id).unwrap();
        let client =
            mask_io::client(udp_transport(udp), &mask, address, "localhost".into()).unwrap();
        let offer = client.mask_state_offer(&mask).await.unwrap().unwrap();
        let owner = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        owner.lock().mask = Some(mask);
        let answer = server.accept_rtc_offer(&offer, &owner, peer).unwrap();
        {
            let rtc = server.peers.get(&peer).unwrap();
            assert_eq!(rtc.incoming.max_capacity(), 64);
            assert_eq!(rtc.outgoing.max_capacity(), 64);
        }
        // Потерянный ответ: повтор должен вернуть те же ключи и не занять слот.
        assert_eq!(
            server.accept_rtc_offer(&offer, &owner, peer).unwrap(),
            answer
        );
        assert_eq!(server.permits.available_permits(), PEERS - 1);
        let mut changed = offer.clone();
        changed.offer_id[0] ^= 1;
        assert!(server.accept_rtc_offer(&changed, &owner, peer).is_err());
        client.accept_mask_state(&answer).await.unwrap();
        let socket = server.clone();
        let dispatch = tokio::spawn(async move {
            let mut buffer = [0; 2048];
            loop {
                let (length, source) = raw.recv_from(&mut buffer).await.unwrap();
                socket.route_incoming(&buffer[..length], source);
            }
        });
        let packet_length = client.max_datagram();
        let send_client = client.clone();
        let send = tokio::spawn(async move {
            loop {
                send_client.send(&vec![0x11; packet_length]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });
        let decoded = tokio::time::timeout(std::time::Duration::from_secs(5), server.decoded())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded.peer, peer);
        assert!(!decoded.quic);
        assert_eq!(decoded.payload, vec![0x11; packet_length]);
        send.abort();
        if id == "webrtc_zoom_v3" {
            let changed =
                aivpn_common::mask::preset_masks::by_id("webrtc_yandex_telemost_v1").unwrap();
            client.set_mask_profile(&changed);
            assert!(client
                .send_data(b"new profile before RTC offer")
                .await
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
            let original = aivpn_common::mask::preset_masks::by_id(id).unwrap();
            client.set_mask_profile(&original);
            let fresh_offer = client.mask_state_offer(&original).await.unwrap().unwrap();
            assert_ne!(fresh_offer.offer_id, offer.offer_id);
            let fresh_answer = server.accept_rtc_offer(&fresh_offer, &owner, peer).unwrap();
            client.accept_mask_state(&fresh_answer).await.unwrap();
            assert!(server.accept_rtc_offer(&offer, &owner, peer).is_err());
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !client.mask_data_ready() || !server.rtc_data_ready(peer) {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        server
            .send_with_mask("ответ по тому же сокету".as_bytes(), peer, false)
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        let length =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], "ответ по тому же сокету".as_bytes());
        client.close().await.unwrap();
        server.use_plain_mask(peer);
        dispatch.abort();
    }

    fn cold_initial(peer: SocketAddr) -> Vec<u8> {
        let now = Instant::now();
        QuicMask::client(b"inner-bootstrap", peer, "localhost", now)
            .unwrap()
            .poll(now)
            .unwrap()
            .wire
            .remove(0)
    }

    #[tokio::test]
    async fn pending_quic_is_bounded_per_peer_and_expires_without_vpn_admission() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30000".parse().unwrap();
        for _ in 0..PENDING_PER_PEER {
            socket.start_initial(peer, &cold_initial(peer)).unwrap();
        }
        assert!(socket.start_initial(peer, &cold_initial(peer)).is_err());
        assert_eq!(
            socket.quic_transports.get(&peer).unwrap().len(),
            PENDING_PER_PEER
        );
        assert!(!socket.is_stateful(peer));
        assert_eq!(
            socket.pending_permits.available_permits(),
            PENDING_QUIC - PENDING_PER_PEER
        );
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            while !socket.quic_transports.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(socket.pending_permits.available_permits(), PENDING_QUIC);
        assert_eq!(socket.permits.available_permits(), PEERS);
        assert_eq!(socket.decoded.capacity(), 4096);
    }

    #[tokio::test]
    async fn unauthenticated_nat_restart_cannot_replace_active_generation() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30001".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let old = socket.quic_transports.get(&peer).unwrap()[0]
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        socket.authenticate(peer, &old, &session).unwrap();
        let restart = cold_initial(peer);
        socket.start_initial(peer, &restart).unwrap();
        let pending = socket
            .quic_transports
            .get(&peer)
            .unwrap()
            .iter()
            .find(|current| current.quic.as_ref().unwrap().context.owner().is_none())
            .unwrap()
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        assert!(socket
            .peers
            .get(&peer)
            .unwrap()
            .quic
            .as_ref()
            .unwrap()
            .context
            .same_generation(&old));
        assert!(socket.context_valid(peer, &old));
        assert!(socket.context_valid(peer, &pending));
        // Только gate после AEAD+replay может вызвать authenticate с этим context.
        socket.authenticate(peer, &pending, &session).unwrap();
        assert!(!socket.context_valid(peer, &old));
        assert!(socket.context_valid(peer, &pending));
        assert!(socket.authenticate(peer, &old, &session).is_err());
        assert_eq!(socket.quic_transports.get(&peer).unwrap().len(), 1);
        assert!(socket.route_incoming(&restart, peer));
        assert!(!socket.route_incoming(&initial, peer));
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn authenticated_ingress_requires_the_live_admitted_quic_generation_and_owner() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30004".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        let context = socket.quic_transports.get(&peer).unwrap()[0]
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        socket.authenticate(peer, &context, &session).unwrap();
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        session.lock().client_admitted = true;
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        session.lock().is_ratcheted = true;
        assert!(socket.authenticated_quic_ingress(&initial, peer));
        let mut rates = crate::source_rates::UdpIngressRates::default();
        let now = Instant::now();
        for _ in 0..5001 {
            assert!(rates.allow(
                peer.ip(),
                now,
                16,
                [5000, 100_000],
                socket.authenticated_quic_ingress(&initial, peer)
            ));
        }
        let unknown_cid = cold_initial(peer);
        assert!(!socket.authenticated_quic_ingress(&unknown_cid, peer));
        assert!(!socket.authenticated_quic_ingress(&initial, "127.0.0.1:30005".parse().unwrap()));
        assert!(!socket.authenticated_quic_ingress(b"plain-or-rtc", peer));
        let pending_initial = cold_initial(peer);
        socket.start_initial(peer, &pending_initial).unwrap();
        assert!(!socket.authenticated_quic_ingress(&pending_initial, peer));
        assert!(socket.authenticated_quic_ingress(&initial, peer));
        session.lock().client_admitted = false;
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        session.lock().client_admitted = true;
        session.lock().client_addr = "127.0.0.2:30004".parse().unwrap();
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        session.lock().client_addr = peer;
        context.retired.store(true, Ordering::Release);
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        context.retired.store(false, Ordering::Release);
        let pending = socket
            .quic_transports
            .get(&peer)
            .unwrap()
            .iter()
            .find_map(|p| {
                p.quic
                    .as_ref()
                    .filter(|q| q.context.pending())
                    .map(|q| q.context.clone())
            })
            .unwrap();
        socket.authenticate(peer, &pending, &session).unwrap();
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        assert!(socket.authenticated_quic_ingress(&pending_initial, peer));
        drop(session);
        assert!(!socket.authenticated_quic_ingress(&pending_initial, peer));
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn ingress_owner_contention_does_not_fall_back_or_hold_route_maps() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30006".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let context = socket.quic_transports.get(&peer).unwrap()[0]
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        session.lock().client_admitted = true;
        session.lock().is_ratcheted = true;
        socket.authenticate(peer, &context, &session).unwrap();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let thread_ready = ready.clone();
        *context.before_ingress_owner.lock() = Some(Arc::new(move || {
            thread_ready.wait();
        }));
        let held = session.lock();
        let (tx, rx) = std::sync::mpsc::channel();
        let classifier = socket.clone();
        let thread = std::thread::spawn(move || {
            tx.send(classifier.authenticated_quic_ingress(&initial, peer))
                .unwrap();
        });
        ready.wait();
        assert!(matches!(
            socket.quic_transports.try_get_mut(&peer),
            dashmap::try_result::TryResult::Present(_)
        ));
        assert!(matches!(
            socket.peers.try_get_mut(&peer),
            dashmap::try_result::TryResult::Present(_)
        ));
        assert!(matches!(
            rx.recv_timeout(std::time::Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap());
        thread.join().unwrap();
        *context.before_ingress_owner.lock() = None;
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn removed_owner_loses_authenticated_ingress_before_actor_cleanup() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30007".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let context = socket.quic_transports.get(&peer).unwrap()[0]
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        let manager = crate::session::SessionManager::new(
            aivpn_common::crypto::KeyPair::generate(),
            ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
            aivpn_common::mask::preset_masks::quic_https_v2(),
        );
        let session = manager.create_session(peer, [7; 32], None, None).unwrap();
        session.lock().client_admitted = true;
        session.lock().is_ratcheted = true;
        socket.authenticate(peer, &context, &session).unwrap();
        assert!(socket.authenticated_quic_ingress(&initial, peer));
        let sid = session.lock().session_id;
        manager.remove_session(&sid);
        assert!(context.active.load(Ordering::Acquire));
        assert!(!socket.authenticated_quic_ingress(&initial, peer));
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn admitted_quic_keeps_two_receive_batches_and_has_a_finite_burst_queue() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30100".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let current = socket.quic_transports.get(&peer).unwrap()[0].clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        session.lock().client_admitted = true;
        session.lock().is_ratcheted = true;
        socket
            .authenticate(peer, &current.quic.as_ref().unwrap().context, &session)
            .unwrap();
        for _ in 0..2 * crate::batch_io::MAX_BATCH {
            assert!(socket.route_incoming(&initial, peer));
        }
        assert_eq!(
            current.incoming.max_capacity() - current.incoming.capacity(),
            128
        );
        for _ in 0..256 {
            assert!(socket.route_incoming(&initial, peer));
        }
        assert_eq!(current.incoming.max_capacity(), 256);
        assert_eq!(current.incoming.capacity(), 0);
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn pending_quic_flood_keeps_64_slots_across_route_and_initial_retry_paths() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30101".parse().unwrap();
        let initial = cold_initial(peer);
        assert!(!socket.route_incoming(&initial, peer));
        socket.start_initial(peer, &initial).unwrap();
        let current = socket.quic_transports.get(&peer).unwrap()[0].clone();
        for _ in 0..256 {
            assert!(socket.route_incoming(&initial, peer));
            socket.start_initial(peer, &initial).unwrap();
        }
        assert_eq!(
            current.incoming.max_capacity() - current.incoming.capacity(),
            64
        );
        assert_eq!(
            current.outgoing.max_capacity() - current.outgoing.capacity(),
            0
        );
        assert!(socket
            .send_data_with_mask(b"anonymous", peer, true)
            .await
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(socket.pending_permits.available_permits(), PENDING_QUIC - 1);
        assert_eq!(socket.permits.available_permits(), PEERS - 1);
    }

    #[tokio::test]
    async fn attached_quic_without_vpn_admission_keeps_64_rx_and_tx_slots() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30103".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let current = socket.quic_transports.get(&peer).unwrap()[0].clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        socket
            .authenticate(peer, &current.quic.as_ref().unwrap().context, &session)
            .unwrap();
        for _ in 0..128 {
            assert!(socket.route_incoming(&initial, peer));
        }
        assert_eq!(
            current.incoming.max_capacity() - current.incoming.capacity(),
            64
        );
        for _ in 0..64 {
            socket
                .send_with_mask(b"handshake", peer, true)
                .await
                .unwrap();
        }
        assert!(socket
            .send_with_mask(b"too many", peer, true)
            .await
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        socket.use_plain_mask(peer);
    }

    #[test]
    fn concurrent_pending_reservations_never_commit_more_than_64_payloads() {
        let (sender, receiver) = mpsc::channel(256);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let sender = sender.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..128 {
                    let _ = try_queue(&sender, 64, || vec![0u8; 1380]);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(receiver.len(), 64);
        assert_eq!(sender.capacity(), 256 - 64);
    }

    #[tokio::test]
    async fn admitted_quic_tx_burst_is_bounded_at_256() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30102".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let current = socket.quic_transports.get(&peer).unwrap()[0].clone();
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        session.lock().client_admitted = true;
        session.lock().is_ratcheted = true;
        socket
            .authenticate(peer, &current.quic.as_ref().unwrap().context, &session)
            .unwrap();
        for _ in 0..256 {
            socket
                .send_data_with_mask(b"bounded", peer, true)
                .await
                .unwrap();
        }
        assert_eq!(current.outgoing.max_capacity(), 256);
        assert_eq!(current.outgoing.capacity(), 0);
        assert!(socket
            .send_data_with_mask(b"one too many", peer, true)
            .await
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn global_pending_quic_budget_stops_a_multi_peer_flood() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let hold = socket
            .pending_permits
            .clone()
            .acquire_many_owned((PENDING_QUIC - 1) as u32)
            .await
            .unwrap();
        let peer = "127.0.0.1:30002".parse().unwrap();
        socket.start_initial(peer, &cold_initial(peer)).unwrap();
        let other = "127.0.0.1:30003".parse().unwrap();
        assert!(socket.start_initial(other, &cold_initial(other)).is_err());
        assert!(!socket.is_stateful(peer));
        assert!(!socket.is_stateful(other));
        drop(hold);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pending_quic_replies_from_the_initial_destination_without_vpn_binding() {
        let raw = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        crate::udp_source::enable(&raw).unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 2], raw.local_addr().unwrap().port()));
        let socket = MaskSocket::new(raw.clone());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(destination).await.unwrap();
        client.send(&cold_initial(destination)).await.unwrap();
        let mut buffer = [0; 2048];
        let (length, peer, local) = crate::udp_source::recv_from(&raw, &mut buffer)
            .await
            .unwrap();
        assert_eq!(local.unwrap().ip, destination.ip());
        socket
            .start_initial_with_source(peer, &buffer[..length], local)
            .unwrap();
        let length =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert!(length > 0);
        assert!(!socket.is_stateful(peer));
        assert!(socket.reply_sources.get(peer).is_none());
        assert_eq!(socket.decoded.capacity(), 4096);
    }

    async fn receive_tls_bootstrap(
        socket: &Arc<MaskSocket>,
        client: &UdpSocket,
        bootstrap: &[u8],
    ) -> DecodedPacket {
        let mut server = socket.raw.local_addr().unwrap();
        if server.ip().is_unspecified() {
            server.set_ip("127.0.0.2".parse().unwrap());
        }
        receive_tls_bootstrap_at(socket, client, bootstrap, server).await
    }

    async fn receive_tls_bootstrap_at(
        socket: &Arc<MaskSocket>,
        client: &UdpSocket,
        bootstrap: &[u8],
        server: SocketAddr,
    ) -> DecodedPacket {
        receive_tls_bootstrap_at_with_probe(socket, client, bootstrap, server)
            .await
            .0
    }

    async fn receive_tls_bootstrap_at_with_probe(
        socket: &Arc<MaskSocket>,
        client: &UdpSocket,
        bootstrap: &[u8],
        server: SocketAddr,
    ) -> (DecodedPacket, Vec<u8>) {
        let mut engine = QuicMask::client(bootstrap, server, "localhost", Instant::now()).unwrap();
        let mut probe = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut server_buffer = [0; 2048];
            let mut client_buffer = [0; 2048];
            loop {
                for packet in engine.poll(Instant::now()).unwrap().wire {
                    if probe.is_empty() { probe = packet.clone(); }
                    client.send_to(&packet, server).await.unwrap();
                }
                let deadline = engine.deadline();
                tokio::select! {
                    packet = socket.decoded() => break (packet.unwrap(), probe),
                    received = crate::udp_source::recv_from(&socket.raw, &mut server_buffer) => {
                        let (length, peer, local) = received.unwrap();
                        let packet = &server_buffer[..length];
                        if !socket.route_incoming(packet, peer) && QuicMask::initial_token(packet).is_some() {
                            socket.start_initial_with_source(peer, packet, local).unwrap();
                        }
                    }
                    received = client.recv_from(&mut client_buffer) => {
                        let (length, peer) = received.unwrap();
                        engine.receive(&client_buffer[..length], peer, Instant::now()).unwrap();
                    }
                    _ = async {
                        if let Some(deadline) = deadline {
                            tokio::time::sleep_until(deadline.into()).await;
                        } else { std::future::pending::<()>().await; }
                    } => {}
                }
            }
        })
        .await
        .expect("TLS/CONNECT-UDP не доставил внутренний bootstrap")
    }

    #[tokio::test]
    async fn quic_admission_preserves_source_for_plain_reply_after_switch() {
        let fixture = authenticated_quic_fixture(true).await;
        let peer = fixture.client.local_addr().unwrap();
        let local = fixture
            .socket
            .reply_sources
            .get(peer)
            .expect("После admission нет ReplySources binding");
        assert_eq!(local.ip, "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
        fixture.socket.use_plain_mask(peer);
        fixture
            .socket
            .send_with_mask(b"plain-after-quic", peer, false)
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        let source = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let (length, source) = fixture.client.recv_from(&mut buffer).await.unwrap();
                if &buffer[..length] == b"plain-after-quic" {
                    break source;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(source.ip(), local.ip);
    }

    #[tokio::test]
    async fn stale_quic_cleanup_before_commit_cannot_consume_a_valid_nonce() {
        use aivpn_common::client_wire::{build_inner_packet, build_shaped_mdh_packet};
        use aivpn_common::protocol::InnerType;
        let fixture = authenticated_quic_fixture(false).await;
        let peer = fixture.client.local_addr().unwrap();
        let next_keys = aivpn_common::crypto::derive_session_keys(&[17; 32], None, &[18; 32]);
        let sid = fixture.session.lock().session_id;
        {
            let mut state = fixture.session.lock();
            state.is_ratcheted = false;
            state.ratcheted_keys = Some(next_keys.clone());
            state.update_ratcheted_tag_window();
        }
        fixture.gateway.session_manager.refresh_session_tags(&sid);
        let inner = build_inner_packet(InnerType::Ack, 0, &[]);
        let packet = build_shaped_mdh_packet(
            &next_keys,
            &mut 7,
            &inner,
            None,
            fixture.mask.mdh_len(),
            &fixture.mask,
        )
        .unwrap();
        let decoded = receive_tls_bootstrap(&fixture.socket, &fixture.client, &packet).await;
        let context = decoded.context.clone().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let hook_barrier = barrier.clone();
        *context.before_commit.lock() = Some(Arc::new(move || {
            hook_barrier.wait();
            hook_barrier.wait();
        }));
        let socket = fixture.socket.clone();
        let stale = context.clone();
        let cleanup = std::thread::spawn(move || {
            barrier.wait();
            retire_quic_generation(&socket.peers, &socket.quic_transports, peer, &stale);
            barrier.wait();
        });
        let source_before = fixture.socket.reply_sources.get(peer);
        let before = {
            let state = fixture.session.lock();
            (
                state.keys.session_key,
                state.counter,
                state.send_counter,
                state.received_bitmap,
                state.client_addr,
                state.is_ratcheted,
                state.ratcheted_keys.as_ref().map(|keys| keys.session_key),
            )
        };
        let _ = fixture.gateway.handle_decoded_packet(decoded).await;
        cleanup.join().unwrap();
        let after = {
            let state = fixture.session.lock();
            (
                state.keys.session_key,
                state.counter,
                state.send_counter,
                state.received_bitmap,
                state.client_addr,
                state.is_ratcheted,
                state.ratcheted_keys.as_ref().map(|keys| keys.session_key),
            )
        };
        assert_eq!(
            after, before,
            "Stale generation списало nonce или изменило VPN"
        );
        assert_eq!(fixture.socket.reply_sources.get(peer), source_before);
        assert!(fixture.socket.context_valid(peer, &fixture.active));
        fixture
            .gateway
            .handle_decoded_packet(DecodedPacket {
                payload: packet,
                peer,
                quic: true,
                context: Some(fixture.active.clone()),
            })
            .await
            .unwrap();
        assert_eq!(fixture.session.lock().counter, 7);
        assert!(fixture.session.lock().is_ratcheted);
        assert_eq!(
            fixture.session.lock().keys.session_key,
            next_keys.session_key
        );
    }

    #[tokio::test]
    async fn exhausted_pending_cpu_budget_skips_protocol_work_but_keeps_active_running() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = "127.0.0.1:30005".parse().unwrap();
        let initial = cold_initial(peer);
        socket.start_initial(peer, &initial).unwrap();
        let context = socket.quic_transports.get(&peer).unwrap()[0]
            .quic
            .as_ref()
            .unwrap()
            .context
            .clone();
        assert!(context.work_budget.lock().try_begin(Instant::now()));
        for _ in 0..64 {
            assert!(socket.route_incoming(&initial, peer));
        }
        while context.work_attempts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            context.work_calls.load(Ordering::SeqCst),
            0,
            "Pending выполнил crypto/H3 без бюджета"
        );
        let session = Arc::new(parking_lot::Mutex::new(crate::session::Session::new(
            [7; 16],
            peer,
            aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]),
            [9; 32],
        )));
        socket.authenticate(peer, &context, &session).unwrap();
        assert!(socket.route_incoming(&initial, peer));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while context.work_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        socket.use_plain_mask(peer);
    }

    struct QuicFixture {
        _directory: tempfile::TempDir,
        gateway: super::super::Gateway,
        socket: Arc<MaskSocket>,
        client: UdpSocket,
        session: Arc<parking_lot::Mutex<crate::session::Session>>,
        keys: aivpn_common::crypto::SessionKeys,
        mask: aivpn_common::mask::MaskProfile,
        active: QuicContext,
        wire_probe: Vec<u8>,
    }

    async fn authenticated_quic_fixture(wildcard: bool) -> QuicFixture {
        use aivpn_common::client_wire::{build_inner_packet, build_shaped_mdh_packet};
        use aivpn_common::protocol::InnerType;
        let directory = tempfile::tempdir().unwrap();
        let mask_dir = directory.path().join("masks");
        std::fs::create_dir(&mask_dir).unwrap();
        let mut mask = aivpn_common::mask::preset_masks::quic_https_v2();
        crate::test_masks::sign(&mut mask, &ed25519_dalek::SigningKey::from_bytes(&[71; 32]));
        std::fs::write(
            mask_dir.join(format!("{}.json", mask.mask_id)),
            serde_json::to_vec(&mask).unwrap(),
        )
        .unwrap();
        let database = Arc::new(
            crate::client_db::ClientDatabase::load(
                &directory.path().join("clients.json"),
                aivpn_common::network_config::VpnNetworkConfig::default(),
            )
            .unwrap(),
        );
        let mut gateway = super::super::Gateway::new(super::super::GatewayConfig {
            mask_dir,
            client_db: Some(database),
            mask_signing_key: Some([71; 32]),
            enable_nat: false,
            enable_neural: false,
            ..Default::default()
        })
        .unwrap();
        let raw = Arc::new(
            UdpSocket::bind(if wildcard { "0.0.0.0:0" } else { "127.0.0.1:0" })
                .await
                .unwrap(),
        );
        crate::udp_source::enable(&raw).unwrap();
        let socket = MaskSocket::new(raw);
        gateway.udp_socket = Some(socket.clone());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client.local_addr().unwrap();
        let session = gateway
            .session_manager
            .create_session(peer, [7; 32], None, None)
            .unwrap();
        let keys = aivpn_common::crypto::derive_session_keys(&[8; 32], None, &[9; 32]);
        let sid = session.lock().session_id;
        {
            let mut state = session.lock();
            state.keys = keys.clone();
            state.mask = Some(mask.clone());
            state.is_ratcheted = true;
            state.client_admitted = true;
            state.update_tag_window();
        }
        gateway.session_manager.refresh_session_tags(&sid);
        let inner = build_inner_packet(InnerType::Ack, 0, &[]);
        let initial =
            build_shaped_mdh_packet(&keys, &mut 6, &inner, None, mask.mdh_len(), &mask).unwrap();
        let mut destination = socket.raw.local_addr().unwrap();
        if destination.ip().is_unspecified() {
            destination.set_ip("127.0.0.2".parse().unwrap());
        }
        let (decoded, wire_probe) =
            receive_tls_bootstrap_at_with_probe(&socket, &client, &initial, destination).await;
        let active = decoded.context.clone().unwrap();
        gateway.handle_decoded_packet(decoded).await.unwrap();
        assert!(socket.context_valid(peer, &active));
        QuicFixture {
            _directory: directory,
            gateway,
            socket,
            client,
            session,
            keys,
            mask,
            active,
            wire_probe,
        }
    }

    #[tokio::test]
    async fn tls_admitted_generation_exceeds_5000_but_known_cid_still_has_a_finite_ceiling() {
        let fixture = authenticated_quic_fixture(false).await;
        let peer = fixture.client.local_addr().unwrap();
        let mut rates = crate::source_rates::UdpIngressRates::default();
        let now = Instant::now();
        for _ in 0..5001 {
            assert!(rates.allow(
                peer.ip(),
                now,
                16,
                [5000, 100_000],
                fixture
                    .socket
                    .authenticated_quic_ingress(&fixture.wire_probe, peer)
            ));
        }
        let mut forged = fixture.wire_probe.clone();
        *forged.last_mut().unwrap() ^= 1;
        // CID выбирает квоту, но не подтверждает пакет. Quinn AEAD проверяется дальше.
        assert!(fixture.socket.authenticated_quic_ingress(&forged, peer));
        for _ in 5001..100_000 {
            assert!(rates.allow(peer.ip(), now, 16, [5000, 100_000], true));
        }
        assert!(!rates.allow(
            peer.ip(),
            now,
            16,
            [5000, 100_000],
            fixture.socket.authenticated_quic_ingress(&forged, peer)
        ));
        fixture.socket.use_plain_mask(peer);
    }

    #[tokio::test]
    async fn forged_and_replayed_inner_packets_cannot_attach_a_pending_nat_generation() {
        use aivpn_common::client_wire::{build_inner_packet, build_shaped_mdh_packet};
        use aivpn_common::protocol::InnerType;
        let QuicFixture {
            _directory,
            gateway,
            socket,
            client,
            session,
            keys,
            mask,
            active,
            wire_probe: _,
        } = authenticated_quic_fixture(true).await;
        let peer = client.local_addr().unwrap();
        let inner = build_inner_packet(InnerType::Ack, 0, &[]);
        let snapshot = || {
            let state = session.lock();
            (
                state.keys.session_key,
                state.keys.tag_secret,
                state.counter,
                state.send_counter,
                state.received_bitmap,
                state.client_addr,
                state.last_seen,
            )
        };
        let source_before = socket.reply_sources.get(peer);
        let mut adversarial_destination = socket.raw.local_addr().unwrap();
        adversarial_destination.set_ip("127.0.0.3".parse().unwrap());
        let before = snapshot();
        assert_eq!(snapshot(), before);
        let packet =
            build_shaped_mdh_packet(&keys, &mut 7, &inner, None, mask.mdh_len(), &mask).unwrap();
        let mut forged = packet.clone();
        *forged.last_mut().unwrap() ^= 1;
        let (decoded, forged_wire) =
            receive_tls_bootstrap_at_with_probe(&socket, &client, &forged, adversarial_destination)
                .await;
        let pending = decoded.context.clone().unwrap();
        assert!(gateway.handle_decoded_packet(decoded).await.is_err());
        assert_eq!(snapshot(), before);
        assert_eq!(socket.reply_sources.get(peer), source_before);
        assert!(socket.context_valid(peer, &active));
        assert!(pending.owner().is_none());
        assert!(!socket.authenticated_quic_ingress(&forged_wire, peer));
        // Подделка не сожгла nonce: настоящий пакет по active принимается.
        gateway
            .handle_decoded_packet(DecodedPacket {
                payload: packet.clone(),
                peer,
                quic: true,
                context: Some(active.clone()),
            })
            .await
            .unwrap();
        let accepted = snapshot();
        assert_ne!(accepted.4, before.4);
        adversarial_destination.set_ip("127.0.0.4".parse().unwrap());
        let (replayed, replay_wire) =
            receive_tls_bootstrap_at_with_probe(&socket, &client, &packet, adversarial_destination)
                .await;
        let replay_context = replayed.context.clone().unwrap();
        let _ = gateway.handle_decoded_packet(replayed).await;
        assert_eq!(snapshot(), accepted);
        assert_eq!(socket.reply_sources.get(peer), source_before);
        assert!(socket.context_valid(peer, &active));
        assert!(pending.owner().is_none());
        assert!(replay_context.owner().is_none());
        assert!(!socket.authenticated_quic_ingress(&replay_wire, peer));
        assert_eq!(gateway.session_manager.session_count(), 1);
        socket.use_plain_mask(peer);
    }
}

pub(crate) struct MaskSocket {
    raw: Arc<UdpSocket>,
    reply_sources: Arc<crate::udp_source::ReplySources>,
    peers: Arc<DashMap<SocketAddr, Peer>>,
    quic_transports: Arc<DashMap<SocketAddr, Vec<Peer>>>,
    pending_permits: Arc<Semaphore>,
    #[cfg(test)]
    preauth_work: Arc<parking_lot::Mutex<super::preauth::PreauthBudget>>,
    decoded: mpsc::Sender<DecodedPacket>,
    received: Mutex<mpsc::Receiver<DecodedPacket>>,
    permits: Arc<Semaphore>,
    wire_observer: Option<WireObserver>,
}

impl std::ops::Deref for MaskSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &UdpSocket {
        &self.raw
    }
}

impl MaskSocket {
    pub fn accept_rtc_offer(
        &self,
        offer: &MaskState,
        session: &Arc<parking_lot::Mutex<crate::session::Session>>,
        peer: SocketAddr,
    ) -> Result<MaskState> {
        let mut session_guard = session.lock();
        if session_guard.rtc_retired_offers.contains(&offer.offer_id) {
            return Err(Error::InvalidPacket("Устаревшее предложение RTC"));
        }
        let retired_offers = session_guard.rtc_retired_offers.clone();
        let (session_id, kind, inner_budget) = {
            let session = &*session_guard;
            if session.is_removed() {
                return Err(Error::InvalidPacket("Сессия RTC уже удалена"));
            }
            let mask = session
                .mask
                .as_ref()
                .filter(|mask| {
                    aivpn_common::mask_io::uses_rtc(mask)
                        && mask.mask_id == offer.mask_id
                        && mask.version == offer.mask_version
                })
                .ok_or(Error::InvalidPacket(
                    "Предложение RTC не соответствует маске сессии",
                ))?;
            (
                session.session_id,
                RtcKind::from_mask(mask)?,
                aivpn_common::mask_io::rtc_inner_budget(mask),
            )
        };
        offer.validate()?;
        if offer.answer {
            return Err(Error::InvalidPacket("Предложение RTC помечено ответом"));
        }
        let existing = |current: &Peer| -> Result<Option<MaskState>> {
            if let Some(previous) = current
                .rtc
                .as_ref()
                .filter(|previous| previous.session_id == session_id)
            {
                if previous.offer == *offer {
                    return Ok(Some(previous.answer.clone()));
                }
                if retired_offers.contains(&offer.offer_id)
                    || previous.offer.offer_id == offer.offer_id
                    || previous.offer.parameters == offer.parameters
                {
                    return Err(Error::InvalidPacket(
                        "Устаревшее или повторно использованное предложение RTC",
                    ));
                }
            }
            Ok(None)
        };
        if let Some(current) = self.peers.get(&peer) {
            if let Some(answer) = existing(&current)? {
                return Ok(answer);
            }
        }
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
            // При заполнении старое поколение иначе навсегда удерживает
            // слот, необходимый для смены уже выбранной маски сессии.
            let removed = self.peers.remove_if(&peer, |_, current| {
                current.rtc.as_ref().is_some_and(|previous| {
                    previous.session_id == session_id
                        && previous.offer.offer_id != offer.offer_id
                        && !retired_offers.contains(&offer.offer_id)
                        && previous.offer.parameters != offer.parameters
                })
            });
            if let Some((_, previous)) = removed {
                if let Some(previous) = previous.rtc {
                    session_guard.retire_rtc_offer(previous.offer.offer_id);
                }
            }
            Error::Io(io::ErrorKind::WouldBlock.into())
        })?;
        // Адрес из защищенного предложения используется только в SansIO.
        // Физические отправки ниже всегда идут прежнему peer через raw.
        let mut engine = RtcMask::create(
            kind,
            true,
            offer.parameters.server_addr(),
            peer,
            offer.parameters.server_addr(),
            Instant::now(),
        )?;
        engine.negotiate(&offer.parameters, Instant::now())?;
        let answer = MaskState {
            answer: true,
            parameters: engine.parameters(),
            ..offer.clone()
        };
        let (incoming, receiver) = mpsc::channel(QUEUE);
        let (outgoing, outgoing_rx) = mpsc::channel(QUEUE);
        let generation = outgoing.downgrade();
        let owner = Arc::downgrade(session);
        let ready = Arc::new(AtomicBool::new(false));
        let created = Peer {
            ready: ready.clone(),
            quic: None,
            incoming,
            outgoing,
            rtc: Some(Arc::new(RtcAdmission {
                session_id,
                offer: offer.clone(),
                answer: answer.clone(),
                inner_budget,
            })),
        };
        // Session и DashMap guard не удерживаются при ожидании lifecycle gate.
        drop(session_guard);
        let mut created = Some(created);
        loop {
            let previous_quic = self
                .peers
                .get(&peer)
                .and_then(|current| current.quic.clone());
            let generation_guard = previous_quic
                .as_ref()
                .map(|quic| quic.context.commit_gate.lock());
            let mut latest_session = session.lock();
            if latest_session.is_removed()
                || latest_session.rtc_retired_offers.contains(&offer.offer_id)
                || !latest_session.mask.as_ref().is_some_and(|mask| {
                    aivpn_common::mask_io::uses_rtc(mask)
                        && mask.mask_id == offer.mask_id
                        && mask.version == offer.mask_version
                })
            {
                return Err(Error::InvalidPacket(
                    "Сессия или предложение RTC уже изменились",
                ));
            }
            let previous = match self.peers.entry(peer) {
                Entry::Occupied(mut entry) => {
                    if entry.get().quic.as_ref().is_some_and(|current| {
                        previous_quic.as_ref().is_none_or(|previous| {
                            !Arc::ptr_eq(
                                &previous.context.commit_gate,
                                &current.context.commit_gate,
                            )
                        })
                    }) {
                        // Пока брали gate, другое допустимое поколение могло
                        // завершить attach. Повторяем без блокировки DashMap.
                        drop(entry);
                        drop(latest_session);
                        drop(generation_guard);
                        continue;
                    }
                    if let Some(answer) = existing(entry.get())? {
                        return Ok(answer);
                    }
                    Some(entry.insert(created.take().unwrap()))
                }
                Entry::Vacant(entry) => {
                    entry.insert(created.take().unwrap());
                    None
                }
            };
            if let Some(previous) = previous
                .as_ref()
                .and_then(|previous| previous.rtc.as_ref())
                .filter(|previous| previous.session_id == session_id)
            {
                latest_session.retire_rtc_offer(previous.offer.offer_id);
            }
            drop(latest_session);
            if let Some(previous) = previous
                .as_ref()
                .and_then(|previous| previous.quic.as_ref())
            {
                previous.context.retire_locked();
                remove_quic_route(&self.quic_transports, peer, &previous.context);
            }
            drop(generation_guard);
            break;
        }
        let raw = self.raw.clone();
        let reply_sources = self.reply_sources.clone();
        let peers = self.peers.clone();
        let decoded = self.decoded.clone();
        let observer = self.wire_observer.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = drive(
                MaskEngine::Rtc(engine),
                raw,
                reply_sources,
                receiver,
                outgoing_rx,
                decoded,
                peer,
                VecDeque::new(),
                Some(owner),
                ready,
                observer,
                None,
            )
            .await
            {
                tracing::debug!("Движок RTC завершен: {}", error);
            }
            peers.remove_if(&peer, |_, current| {
                generation
                    .upgrade()
                    .is_some_and(|old| current.outgoing.same_channel(&old))
            });
        });
        Ok(answer)
    }
    pub fn needs_wrapping(&self, packet: &[u8], peer: SocketAddr) -> bool {
        self.is_stateful(peer) || Self::is_inner_quic(packet)
    }

    fn is_inner_quic(packet: &[u8]) -> bool {
        packet.len() >= 14 && packet[0] & 0xc0 == 0xc0 && packet[1..5] == [0, 0, 0, 1]
    }
    #[cfg(test)]
    pub fn new(raw: Arc<UdpSocket>) -> Arc<Self> {
        Self::with_wire_observer(raw, None)
    }

    pub fn with_wire_observer(
        raw: Arc<UdpSocket>,
        wire_observer: Option<WireObserver>,
    ) -> Arc<Self> {
        let (decoded, received) = mpsc::channel(4096);
        Arc::new(Self {
            raw,
            reply_sources: Arc::new(crate::udp_source::ReplySources::default()),
            peers: Arc::new(DashMap::new()),
            quic_transports: Arc::new(DashMap::new()),
            pending_permits: Arc::new(Semaphore::new(PENDING_QUIC)),
            #[cfg(test)]
            preauth_work: Arc::new(parking_lot::Mutex::new(super::preauth::PreauthBudget::new(
                Instant::now(),
            ))),
            decoded,
            received: Mutex::new(received),
            permits: Arc::new(Semaphore::new(PEERS)),
            wire_observer,
        })
    }

    pub fn raw(&self) -> Arc<UdpSocket> {
        self.raw.clone()
    }

    pub(crate) fn reply_sources(&self) -> Arc<crate::udp_source::ReplySources> {
        self.reply_sources.clone()
    }

    pub(crate) async fn send_raw(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        crate::udp_source::send_to(&self.raw, &self.reply_sources, packet, peer).await
    }

    #[cfg(any(feature = "neural", test))]
    pub fn observe_plain_wire(
        &self,
        session: &Arc<parking_lot::Mutex<crate::session::Session>>,
        wire: &[u8],
    ) {
        if let Some(observer) = &self.wire_observer {
            let mut session = session.lock();
            if session.client_admitted && session.is_ratcheted && !session.is_removed() {
                let sample = session.plain_wire_seen.is_multiple_of(16);
                session.plain_wire_seen = session.plain_wire_seen.wrapping_add(1);
                // Удаление сессии и очистка окна ждут завершения записи.
                if sample {
                    observer(session.session_id, wire);
                }
            }
        }
    }

    pub async fn decoded(&self) -> Option<DecodedPacket> {
        self.received.lock().await.recv().await
    }

    /// Выбирает только конечную внешнюю квоту. Проверка Quinn AEAD остается обязательной.
    pub(super) fn authenticated_quic_ingress(&self, packet: &[u8], peer: SocketAddr) -> bool {
        if packet.len() > 1380 {
            return false;
        }
        let Some(current) = self.quic_transports.get(&peer).and_then(|transports| {
            transports
                .iter()
                .find(|current| {
                    current
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.routing.matches(packet))
                })
                .cloned()
        }) else {
            return false;
        };
        let Some(quic) = current.quic.as_ref() else {
            return false;
        };
        let context = &quic.context;
        if !context.active.load(Ordering::Acquire)
            || context.retired.load(Ordering::Acquire)
            || current.incoming.is_closed()
        {
            return false;
        }
        let Some(owner) = context.owner().and_then(|owner| owner.upgrade()) else {
            return false;
        };
        #[cfg(test)]
        {
            let hook = context.before_ingress_owner.lock().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        // Нельзя ждать Session с удержанным guard карты: worker обновляет
        // transport mapping, пока работает с этой же сессией.
        let admitted = {
            let owner = owner.lock();
            owner.client_admitted
                && owner.is_ratcheted
                && !owner.is_removed()
                && owner.client_addr == peer
        };
        admitted
            && self.peers.get(&peer).is_some_and(|active| {
                active
                    .quic
                    .as_ref()
                    .is_some_and(|active| active.context.same_generation(context))
            })
            && context.active.load(Ordering::Acquire)
            && !context.retired.load(Ordering::Acquire)
            && !current.incoming.is_closed()
    }

    pub fn route_incoming(&self, packet: &[u8], peer: SocketAddr) -> bool {
        let quic = self.quic_transports.get(&peer).and_then(|transports| {
            transports
                .iter()
                .find(|sender| {
                    sender
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.routing.matches(packet))
                })
                .cloned()
        });
        if let Some(sender) = quic {
            self.queue_quic_rx(&sender, packet, peer);
            return true;
        }
        if let Some(sender) = self.peers.get(&peer) {
            if sender.rtc.is_none() || !aivpn_common::rtc_mask::is_wire_packet(packet) {
                return false;
            }
            if sender.incoming.is_closed() {
                let old = sender.incoming.clone();
                drop(sender);
                self.retire_closed_peer(peer, &old);
                return false;
            }
            if packet.len() <= 1380 {
                let _ = sender.incoming.try_send(packet.to_vec());
            }
            return true;
        }
        false
    }

    fn queue_quic_rx(&self, sender: &Peer, packet: &[u8], peer: SocketAddr) {
        let Some(quic) = &sender.quic else {
            return;
        };
        if packet.len() > 1380 || quic.context.retired.load(Ordering::Acquire) {
            return;
        }
        if matches!(
            try_queue(&sender.incoming, quic.context.queue_limit(peer), || packet
                .to_vec()),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            let dropped = QUIC_RECEIVE_DROPS
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if dropped.is_power_of_two() {
                tracing::debug!(dropped, "Переполнена входная очередь QUIC");
            }
        }
    }

    fn retire_closed_peer(&self, peer: SocketAddr, previous: &mpsc::Sender<Vec<u8>>) {
        self.peers.remove_if(&peer, |_, current| {
            current.incoming.same_channel(previous) && current.incoming.is_closed()
        });
    }

    /// До VPN admission принимается только ограниченный стандартный QUIC transport.
    #[cfg(test)]
    pub fn start_initial(self: &Arc<Self>, peer: SocketAddr, first: &[u8]) -> Result<()> {
        self.start_initial_with_source(peer, first, None)
    }

    #[cfg(test)]
    pub fn start_initial_with_source(
        self: &Arc<Self>,
        peer: SocketAddr,
        first: &[u8],
        local: Option<crate::udp_source::LocalEndpoint>,
    ) -> Result<()> {
        self.start_initial_with_budget(peer, first, local, self.preauth_work.clone())
    }

    pub(super) fn start_initial_with_budget(
        self: &Arc<Self>,
        peer: SocketAddr,
        first: &[u8],
        local: Option<crate::udp_source::LocalEndpoint>,
        work_budget: Arc<parking_lot::Mutex<super::preauth::PreauthBudget>>,
    ) -> Result<()> {
        if first.len() > 1380 || QuicMask::initial_token(first).is_none() {
            return Err(Error::InvalidPacket("Некорректный QUIC Initial"));
        }
        let current = self.quic_transports.get(&peer).and_then(|transports| {
            transports
                .iter()
                .find(|current| {
                    current
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.routing.matches(first))
                })
                .cloned()
        });
        if let Some(current) = current {
            self.queue_quic_rx(&current, first, peer);
            return Ok(());
        }
        if let Some(transports) = self.quic_transports.get(&peer) {
            if transports
                .iter()
                .filter(|current| {
                    current
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.context.pending())
                })
                .count()
                >= PENDING_PER_PEER
            {
                return Err(Error::Io(io::ErrorKind::WouldBlock.into()));
            }
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Io(io::ErrorKind::WouldBlock.into()))?;
        let pending_permit = self
            .pending_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Io(io::ErrorKind::WouldBlock.into()))?;
        let engine = QuicMask::server(first, peer, Instant::now())?;
        let routing = engine.routing().expect("Сервер QUIC имеет маршрут");
        // Entry сериализует создание поколений одного peer; неизвестный CID
        // не заменяет действующее состояние и не занимает более двух pending.
        let mut transports = self.quic_transports.entry(peer).or_default();
        if let Some(current) = transports
            .iter()
            .find(|current| {
                current
                    .quic
                    .as_ref()
                    .is_some_and(|quic| quic.routing.matches(first))
            })
            .cloned()
        {
            drop(transports);
            self.queue_quic_rx(&current, first, peer);
            return Ok(());
        }
        if transports
            .iter()
            .filter(|current| {
                current
                    .quic
                    .as_ref()
                    .is_some_and(|quic| quic.context.pending())
            })
            .count()
            >= PENDING_PER_PEER
        {
            return Err(Error::Io(io::ErrorKind::WouldBlock.into()));
        }
        let context = QuicContext {
            generation: Arc::new(()),
            local,
            admission: Arc::new(parking_lot::Mutex::new(QuicAdmission {
                owner: None,
                pending_permit: Some(pending_permit),
            })),
            work_budget,
            commit_gate: transports
                .first()
                .and_then(|current| current.quic.as_ref())
                .map(|quic| quic.context.commit_gate.clone())
                .unwrap_or_default(),
            retired: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            before_commit: Default::default(),
            #[cfg(test)]
            before_ingress_owner: Default::default(),
            #[cfg(test)]
            work_attempts: Default::default(),
            #[cfg(test)]
            work_calls: Default::default(),
        };
        let (incoming, receiver) = mpsc::channel(QUIC_QUEUE);
        let (outgoing, outgoing_rx) = mpsc::channel(QUIC_QUEUE);
        let ready = Arc::new(AtomicBool::new(false));
        transports.push(Peer {
            ready: ready.clone(),
            quic: Some(QuicPeer {
                routing,
                context: context.clone(),
            }),
            rtc: None,
            incoming,
            outgoing,
        });
        drop(transports);
        let raw = self.raw.clone();
        let reply_sources = self.reply_sources.clone();
        let peers = self.peers.clone();
        let transports = self.quic_transports.clone();
        let decoded = self.decoded.clone();
        let observer = self.wire_observer.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = drive(
                MaskEngine::Quic(engine),
                raw,
                reply_sources,
                receiver,
                outgoing_rx,
                decoded,
                peer,
                VecDeque::new(),
                None,
                ready,
                observer,
                Some(context.clone()),
            )
            .await
            {
                tracing::debug!("Движок QUIC завершен: {}", error);
            }
            retire_quic_generation(&peers, &transports, peer, &context);
        });
        Ok(())
    }

    pub fn context_valid(&self, peer: SocketAddr, context: &QuicContext) -> bool {
        let exists = self.quic_transports.get(&peer).is_some_and(|transports| {
            transports.iter().any(|current| {
                current
                    .quic
                    .as_ref()
                    .is_some_and(|quic| quic.context.same_generation(context))
            })
        });
        exists
            && !context.retired.load(Ordering::Acquire)
            && (!context.active.load(Ordering::Acquire)
                || self.peers.get(&peer).is_some_and(|current| {
                    current
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.context.same_generation(context))
                }))
    }

    /// Lifecycle guard защищает ratchet, replay и attach от cleanup поколения.
    /// Вызывающий код освобождает guard до первого await.
    pub(super) fn begin_quic_commit<'a>(
        &'a self,
        peer: SocketAddr,
        context: &'a QuicContext,
        session: &Arc<parking_lot::Mutex<crate::session::Session>>,
    ) -> Result<QuicCommitGuard<'a>> {
        let current = self
            .quic_transports
            .get(&peer)
            .and_then(|transports| {
                transports
                    .iter()
                    .find(|current| {
                        current
                            .quic
                            .as_ref()
                            .is_some_and(|quic| quic.context.same_generation(context))
                    })
                    .cloned()
            })
            .ok_or(Error::InvalidPacket("Поколение QUIC уже закрыто"))?;
        #[cfg(test)]
        {
            let hook = context.before_commit.lock().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        let guard = context.commit_gate.lock();
        if context.retired.load(Ordering::Acquire) || current.incoming.is_closed() {
            return Err(Error::InvalidPacket("Поколение QUIC уже закрыто"));
        }
        if let Some(owner) = context.owner() {
            if !owner.ptr_eq(&Arc::downgrade(session))
                || !self.peers.get(&peer).is_some_and(|current| {
                    current
                        .quic
                        .as_ref()
                        .is_some_and(|quic| quic.context.same_generation(context))
                })
            {
                return Err(Error::InvalidPacket("Поколение QUIC больше не активно"));
            }
        }
        if session.lock().is_removed() {
            return Err(Error::InvalidPacket("Сессия QUIC уже удалена"));
        }
        Ok(QuicCommitGuard {
            socket: self,
            peer,
            context,
            current,
            _guard: guard,
        })
    }

    #[cfg(test)]
    pub fn authenticate(
        &self,
        peer: SocketAddr,
        context: &QuicContext,
        session: &Arc<parking_lot::Mutex<crate::session::Session>>,
    ) -> Result<()> {
        self.begin_quic_commit(peer, context, session)?
            .authenticate(session);
        Ok(())
    }

    pub fn use_plain_mask(&self, peer: SocketAddr) {
        let previous = self.peers.get(&peer).map(|current| current.clone());
        if let Some(previous) = previous {
            if let Some(quic) = &previous.quic {
                let _guard = quic.context.commit_gate.lock();
                if self
                    .peers
                    .remove_if(&peer, |_, current| {
                        current.incoming.same_channel(&previous.incoming)
                    })
                    .is_some()
                {
                    quic.context.retire_locked();
                    remove_quic_route(&self.quic_transports, peer, &quic.context);
                }
            } else {
                self.peers.remove_if(&peer, |_, current| {
                    current.incoming.same_channel(&previous.incoming)
                });
            }
        }
    }

    pub fn retire_other_rtc_session(&self, peer: SocketAddr, session_id: [u8; 16]) {
        self.peers.remove_if(&peer, |_, current| {
            current
                .rtc
                .as_ref()
                .is_some_and(|rtc| rtc.session_id != session_id)
        });
    }

    pub async fn send_with_mask(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        stateful: bool,
    ) -> io::Result<usize> {
        self.send_packet(packet, peer, stateful, false).await
    }

    pub async fn send_data_with_mask(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        stateful: bool,
    ) -> io::Result<usize> {
        self.send_packet(packet, peer, stateful, true).await
    }

    async fn send_packet(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        stateful: bool,
        data: bool,
    ) -> io::Result<usize> {
        let sender = self.peers.get(&peer).map(|entry| entry.clone());
        if let Some(sender) = sender {
            let maximum = if let Some(rtc) = &sender.rtc {
                rtc.inner_budget
            } else {
                aivpn_common::mask_io::MAX_QUIC_INNER
            };
            if packet.len() > maximum {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if let Some(quic) = &sender.quic {
                if quic.context.retired.load(Ordering::Acquire) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                try_queue(&sender.outgoing, quic.context.queue_limit(peer), || {
                    (packet.to_vec(), data)
                })
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            } else {
                sender
                    .outgoing
                    .try_send((packet.to_vec(), data))
                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            }
            return Ok(packet.len());
        }
        if stateful {
            // Внутренний заголовок QUIC не является готовым UDP payload.
            // До появления состояния маски пакет лучше потерять, чем раскрыть.
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.send_raw(packet, peer).await
    }

    pub async fn send_packets_to(
        &self,
        packets: &(Vec<Vec<u8>>, bool),
        peer: SocketAddr,
    ) -> io::Result<usize> {
        let mut sent = 0;
        for (index, packet) in packets.0.iter().enumerate() {
            if index > 0 && index % 16 == 0 {
                tokio::task::yield_now().await;
            }
            sent += self.send_with_mask(packet, peer, packets.1).await?;
        }
        Ok(sent)
    }

    pub fn is_stateful(&self, peer: SocketAddr) -> bool {
        self.peers.contains_key(&peer)
    }

    pub fn rtc_data_ready(&self, peer: SocketAddr) -> bool {
        self.peers
            .get(&peer)
            .is_some_and(|current| current.rtc.is_some() && current.ready.load(Ordering::Acquire))
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    mut engine: MaskEngine,
    raw: Arc<UdpSocket>,
    reply_sources: Arc<crate::udp_source::ReplySources>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    mut outgoing: mpsc::Receiver<(Vec<u8>, bool)>,
    decoded: mpsc::Sender<DecodedPacket>,
    peer: SocketAddr,
    replies: VecDeque<Vec<u8>>,
    owner: Option<SessionOwner>,
    ready: Arc<AtomicBool>,
    observer: Option<WireObserver>,
    context: Option<QuicContext>,
) -> Result<()> {
    let quic = matches!(engine, MaskEngine::Quic(_));
    let pending_deadline = Instant::now() + PENDING_TIMEOUT;
    let mut preauth_payloads = 0usize;
    if observer.is_some() {
        engine.observe_verified_wire();
    }
    for reply in replies {
        if !engine.send(&reply, Instant::now())? {
            crate::udp_source::send_to(&raw, &reply_sources, &reply, peer).await?;
        }
    }
    let mut lease_check = tokio::time::interval(std::time::Duration::from_secs(1));
    lease_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let now = Instant::now();
        let owner = context
            .as_ref()
            .and_then(QuicContext::owner)
            .or_else(|| owner.clone());
        if context
            .as_ref()
            .is_some_and(|context| context.retired.load(Ordering::Acquire))
            || (context.is_some() && owner.is_none() && now >= pending_deadline)
        {
            break;
        }
        let output = match &context {
            Some(context) => context.protocol_work(|| engine.poll(now))?,
            None => Some(engine.poll(now)?),
        };
        let budget_blocked = output.is_none();
        let output = output.unwrap_or_else(|| QuicMaskOutput {
            wire: Vec::new(),
            payloads: Vec::new(),
            connected: ready.load(Ordering::Acquire),
        });
        let verified = engine.take_verified_wire();
        if !verified.is_empty() {
            if let (Some(observer), Some(owner)) =
                (&observer, owner.as_ref().and_then(|owner| owner.upgrade()))
            {
                let session = owner.lock();
                if session.client_admitted && session.is_ratcheted && !session.is_removed() {
                    for wire in verified {
                        observer(session.session_id, &wire);
                    }
                }
            }
        }
        ready.store(output.connected, Ordering::Release);
        for packet in output.wire {
            if let Err(error) = crate::udp_source::send_from(
                &raw,
                &packet,
                peer,
                context
                    .as_ref()
                    .and_then(|context| context.local)
                    .or_else(|| reply_sources.get(peer)),
            )
            .await
            {
                if quic && aivpn_common::quic_mask::mtu_probe_error(&error, packet.len()) {
                    continue;
                }
                if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::NetworkDown
                        | io::ErrorKind::AddrNotAvailable
                        | io::ErrorKind::PermissionDenied
                ) {
                    return Err(error.into());
                }
            }
        }
        for payload in output.payloads {
            if context.is_some() && owner.is_none() {
                if preauth_payloads >= 8 {
                    continue;
                }
                preauth_payloads += 1;
            }
            if decoded
                .try_send(DecodedPacket {
                    payload,
                    peer,
                    quic,
                    context: context.clone(),
                })
                .is_err()
                && decoded.is_closed()
            {
                return Ok(());
            }
        }
        let deadline = if budget_blocked {
            Some(now + std::time::Duration::from_millis(10))
        } else {
            engine.deadline()
        }
        .into_iter()
        .chain((context.is_some() && owner.is_none()).then_some(pending_deadline))
        .min();
        tokio::select! {
            _ = lease_check.tick(), if owner.is_some() || context.is_some() => {
                if owner.as_ref().is_some_and(|owner| owner.upgrade().is_none_or(|session| session.lock().is_removed())) {
                    break;
                }
            }
            packet = incoming.recv() => match packet {
                Some(packet) => {
                    // Отдельные очереди RX и TX необходимы: входящий пакет
                    // никогда не должен трактоваться как исходящий payload.
                    if let Some(context) = &context {
                        context.protocol_work(|| engine.receive(&packet, peer, Instant::now()))?;
                    } else {
                        engine.receive(&packet, peer, Instant::now())?;
                    }
                }
                None => break,
            },
            packet = outgoing.recv() => match packet {
                Some((packet, data)) => {
                    match engine.send(&packet, Instant::now()) {
                        Ok(false) if !data => { let _ = crate::udp_source::send_to(&raw, &reply_sources, &packet, peer).await; }
                        Ok(false) => {},
                        Ok(true) => {},
                        Err(error) => tracing::debug!("Пакет маски не принят в очередь: {}", error),
                    }
                },
                None => break,
            },
            _ = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline.into()).await;
                } else { std::future::pending::<()>().await; }
            } => {}
        }
    }
    let closing = match &context {
        Some(context) if context.retired.load(Ordering::Acquire) => Vec::new(),
        Some(context) => context
            .protocol_work(|| engine.close(Instant::now()))?
            .unwrap_or_default(),
        None => engine.close(Instant::now())?,
    };
    for packet in closing {
        let _ = crate::udp_source::send_from(
            &raw,
            &packet,
            peer,
            context
                .as_ref()
                .and_then(|context| context.local)
                .or_else(|| reply_sources.get(peer)),
        )
        .await;
    }
    Ok(())
}
