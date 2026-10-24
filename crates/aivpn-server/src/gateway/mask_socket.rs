//! Протокольное состояние маски поверх общего UDP-сокета.

use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::VecDeque, io, net::SocketAddr, sync::Arc, time::Instant};

use aivpn_common::{
    error::Result,
    mask_state::MaskState,
    quic_mask::{QuicMask, QuicMaskOutput},
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
pub(crate) type WireObserver = Arc<dyn Fn([u8; 16], &[u8]) + Send + Sync>;
type SessionOwner = std::sync::Weak<parking_lot::Mutex<crate::session::Session>>;

#[derive(Clone)]
struct Peer {
    ready: Arc<AtomicBool>,
    bootstrap: Vec<u8>,
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

struct Admission {
    generation: Arc<()>,
    authenticated: bool,
    replies: VecDeque<Vec<u8>>,
    first: Vec<u8>,
    engine: Option<QuicMask>,
    permit: OwnedSemaphorePermit,
    owner: Option<SessionOwner>,
}

pub(crate) struct InitialGuard {
    socket: Arc<MaskSocket>,
    peer: SocketAddr,
    generation: Arc<()>,
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
                bootstrap: vec![],
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
        let (payload, source, quic) =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.decoded())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, peer);
        assert!(!quic);
        assert_eq!(payload, vec![0x11; packet_length]);
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

    #[tokio::test]
    async fn cancelled_admission_releases_slot_and_never_answers() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket = MaskSocket::new(raw);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let guard = socket.begin_initial(address, &[0; 1200]).unwrap();
        assert_eq!(socket.permits.available_permits(), PEERS - 1);
        assert!(socket.begin_initial(address, &[0; 1200]).is_none());
        socket
            .send_with_mask(b"queued, not public", address, false)
            .await
            .unwrap();
        assert!(peer.try_recv_from(&mut [0; 128]).is_err());
        drop(guard);
        assert!(socket.admissions.is_empty());
        assert_eq!(socket.permits.available_permits(), PEERS);
        assert!(socket.begin_initial(address, &[0; 1200]).is_some());
    }
}
impl Drop for InitialGuard {
    fn drop(&mut self) {
        self.socket.admissions.remove_if(&self.peer, |_, pending| {
            Arc::ptr_eq(&pending.generation, &self.generation)
        });
    }
}

pub(crate) struct MaskSocket {
    raw: Arc<UdpSocket>,
    reply_sources: Arc<crate::udp_source::ReplySources>,
    peers: Arc<DashMap<SocketAddr, Peer>>,
    admissions: DashMap<SocketAddr, Admission>,
    decoded: mpsc::Sender<(Vec<u8>, SocketAddr, bool)>,
    received: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr, bool)>>,
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
            bootstrap: vec![],
            incoming,
            outgoing,
            rtc: Some(Arc::new(RtcAdmission {
                session_id,
                offer: offer.clone(),
                answer: answer.clone(),
                inner_budget,
            })),
        };
        match self.peers.entry(peer) {
            Entry::Occupied(mut entry) => {
                if let Some(answer) = existing(entry.get())? {
                    return Ok(answer);
                }
                if let Some(previous) = entry
                    .get()
                    .rtc
                    .as_ref()
                    .filter(|previous| previous.session_id == session_id)
                {
                    session_guard.retire_rtc_offer(previous.offer.offer_id);
                }
                entry.insert(created);
            }
            Entry::Vacant(entry) => {
                entry.insert(created);
            }
        }
        drop(session_guard);
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
            admissions: DashMap::new(),
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

    pub async fn decoded(&self) -> Option<(Vec<u8>, SocketAddr, bool)> {
        self.received.lock().await.recv().await
    }

    pub fn route_incoming(&self, packet: &[u8], peer: SocketAddr) -> bool {
        // STUN оставляем обычному декодеру: смена протокола допускается только
        // после проверки внутреннего AEAD, не по внешнему заголовку.
        if let Some(sender) = self.peers.get(&peer) {
            if sender.rtc.is_some() {
                if !aivpn_common::rtc_mask::is_wire_packet(packet) {
                    return false;
                }
            } else if packet.first().is_none_or(|first| first & 0x40 == 0) {
                return false;
            } else if QuicMask::bootstrap(packet).is_some_and(|token| token != sender.bootstrap) {
                // Новая попытка за тем же NAT проходит AEAD и replay заново.
                // Старое состояние меняется только после ее аутентификации.
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

    fn retire_closed_peer(&self, peer: SocketAddr, previous: &mpsc::Sender<Vec<u8>>) {
        self.peers.remove_if(&peer, |_, current| {
            current.incoming.same_channel(previous) && current.incoming.is_closed()
        });
    }

    pub fn begin_initial(self: &Arc<Self>, peer: SocketAddr, first: &[u8]) -> Option<InitialGuard> {
        if first.len() > 1380 {
            return None;
        }
        let permit = self.permits.clone().try_acquire_owned().ok()?;
        match self.admissions.entry(peer) {
            Entry::Vacant(entry) => {
                let generation = Arc::new(());
                entry.insert(Admission {
                    generation: generation.clone(),
                    authenticated: false,
                    replies: VecDeque::new(),
                    first: first.to_vec(),
                    engine: None,
                    permit,
                    owner: None,
                });
                Some(InitialGuard {
                    socket: self.clone(),
                    peer,
                    generation,
                })
            }
            Entry::Occupied(_) => None,
        }
    }

    /// AEAD уже проверен, replay еще не захвачен. Битый внешний пакет
    /// не должен сжечь nonce настоящего клиентского Initial.
    pub fn prepare_authenticated_initial(&self, peer: SocketAddr) -> Result<()> {
        if let Some(mut pending) = self.admissions.get_mut(&peer) {
            if pending.engine.is_none() {
                pending.engine = Some(QuicMask::server(&pending.first, peer, Instant::now())?);
            }
        }
        Ok(())
    }

    pub fn authenticate(
        &self,
        peer: SocketAddr,
        session: &Arc<parking_lot::Mutex<crate::session::Session>>,
    ) {
        if let Some(mut pending) = self.admissions.get_mut(&peer) {
            pending.authenticated = true;
            pending.owner = Some(Arc::downgrade(session));
        }
    }

    pub fn use_plain_mask(&self, peer: SocketAddr) {
        self.peers.remove(&peer);
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
        if let Some(mut pending) = self.admissions.get_mut(&peer) {
            if data || pending.replies.len() >= QUEUE {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            pending.replies.push_back(packet.to_vec());
            return Ok(packet.len());
        }
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
            sender
                .outgoing
                .try_send((packet.to_vec(), data))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
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

    pub fn finish_initial(&self, peer: SocketAddr) -> Result<()> {
        let Entry::Occupied(mut entry) = self.admissions.entry(peer) else {
            return Ok(());
        };
        if !entry.get().authenticated {
            entry.remove();
            return Ok(());
        }
        let Some(engine) = entry.get_mut().engine.take() else {
            return Ok(());
        };
        let (sender, receiver) = mpsc::channel(QUEUE);
        let (outgoing, outgoing_rx) = mpsc::channel(QUEUE);
        // Один слот является верхней границей памяти и числа таймеров.
        let generation = outgoing.downgrade();
        let ready = Arc::new(AtomicBool::new(false));
        self.peers.insert(
            peer,
            Peer {
                ready: ready.clone(),
                rtc: None,
                bootstrap: QuicMask::bootstrap(&entry.get().first)
                    .expect("Initial уже проверен")
                    .to_vec(),
                incoming: sender,
                outgoing,
            },
        );
        let admission = entry.remove();
        let raw = self.raw.clone();
        let reply_sources = self.reply_sources.clone();
        let peers = self.peers.clone();
        let decoded = self.decoded.clone();
        let observer = self.wire_observer.clone();
        tokio::spawn(async move {
            let _permit = admission.permit;
            if let Err(error) = drive(
                MaskEngine::Quic(engine),
                raw,
                reply_sources,
                receiver,
                outgoing_rx,
                decoded,
                peer,
                admission.replies,
                admission.owner,
                ready,
                observer,
            )
            .await
            {
                tracing::debug!("Движок маски завершен: {}", error);
            }
            peers.remove_if(&peer, |_, current| {
                generation
                    .upgrade()
                    .is_some_and(|old| current.outgoing.same_channel(&old))
            });
        });
        Ok(())
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
    decoded: mpsc::Sender<(Vec<u8>, SocketAddr, bool)>,
    peer: SocketAddr,
    replies: VecDeque<Vec<u8>>,
    owner: Option<SessionOwner>,
    ready: Arc<AtomicBool>,
    observer: Option<WireObserver>,
) -> Result<()> {
    let quic = matches!(engine, MaskEngine::Quic(_));
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
        let output = engine.poll(Instant::now())?;
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
            if let Err(error) =
                crate::udp_source::send_to(&raw, &reply_sources, &packet, peer).await
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
            if decoded.try_send((payload, peer, quic)).is_err() && decoded.is_closed() {
                return Ok(());
            }
        }
        let deadline = engine.deadline();
        tokio::select! {
            _ = lease_check.tick(), if owner.is_some() => {
                if owner.as_ref().is_some_and(|owner| owner.upgrade().is_none_or(|session| session.lock().is_removed())) {
                    break;
                }
            }
            packet = incoming.recv() => match packet {
                Some(packet) => {
                    // Отдельные очереди RX и TX необходимы: входящий пакет
                    // никогда не должен трактоваться как исходящий payload.
                    engine.receive(&packet, peer, Instant::now())?;
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
    for packet in engine.close(Instant::now())? {
        let _ = crate::udp_source::send_to(&raw, &reply_sources, &packet, peer).await;
    }
    Ok(())
}
