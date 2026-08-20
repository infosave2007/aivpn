//! Datagram-transport abstraction.
//!
//! The AIVPN protocol is datagram-shaped end to end: resonance tags, the AEAD
//! nonce counter, MDH framing, the mask/mimicry layer and the FEC group all
//! operate on *one logical packet*. Everything above "send one datagram /
//! receive one datagram" is therefore transport-agnostic already — it just
//! happened to be written directly against `tokio::net::UdpSocket`.
//!
//! This module introduces that seam explicitly:
//!
//! ```text
//!   AIVPN protocol (crypto, tags, MDH, ratchet, enrollment, masks)  ← unchanged
//!  ──────────────────── trait DatagramTransport ─────────────────────
//!   UdpTransport (today)          │  alternative transports (later)
//! ```
//!
//! **This module adds no behaviour.** `UdpTransport` is a thin wrapper over the
//! very same connected `UdpSocket` the client already owned, calling the very
//! same `send()` / `recv()` methods. Not a byte on the wire changes.
//!
//! # Why `&self` and not `&mut self`
//!
//! The obvious sketch of this trait takes `&mut self`. That does not
//! survive contact with the client: the connected socket is shared by two
//! concurrently running tasks — the RX task parked in `recv()` and the upload
//! task calling `send()`. `tokio::net::UdpSocket` supports exactly that through
//! `&self`. Taking `&mut self` would force an `Arc<Mutex<..>>` around the
//! transport, and the RX task holds its borrow across an `await` that only
//! completes when a packet arrives — i.e. it would deadlock the uplink. So the
//! trait takes `&self`, and implementations are responsible for their own
//! interior synchronisation (a stream-oriented transport will need a send-side
//! mutex; UDP needs none).
//!
//! # Why `std::io::Result`
//!
//! The upload pipeline classifies send failures by `std::io::ErrorKind`
//! (`is_transient_send_error`: `NetworkUnreachable`, `PermissionDenied`, …) to
//! decide "drop this packet" vs "tear the session down". Returning the raw
//! `io::Error` keeps that classification byte-identical instead of flattening
//! it into a stringly-typed crate error.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

/// Largest payload a single IPv4 UDP datagram can carry (65535 minus the 20-byte
/// IP and 8-byte UDP headers). The ceiling of the transport, not of the tunnel:
/// what the client actually sends is bounded by the tunnel MTU, far below this.
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// Which concrete transport is carrying the datagrams.
///
/// `#[non_exhaustive]`: further variants may be added as transports are
/// registered, and adding them must not be a breaking change for downstream
/// `match`es.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// Connected UDP socket — the only transport that exists today.
    Udp,
}

impl TransportKind {
    /// Stable lowercase identifier, for logs and status files.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bidirectional channel for AIVPN protocol datagrams.
///
/// Implementations preserve *message boundaries*: one `send()` is one logical
/// AIVPN packet, and one `recv()` yields exactly one. For UDP that is free; a
/// stream transport must restore the framing itself.
///
/// `Send + Sync` so it can live behind `Arc<dyn DatagramTransport>` shared by
/// the RX and TX tasks.
#[async_trait]
pub trait DatagramTransport: Send + Sync {
    /// Send one logical AIVPN datagram. Returns the number of bytes accepted.
    async fn send(&self, datagram: &[u8]) -> std::io::Result<usize>;

    /// Receive one logical AIVPN datagram into `buf`. Returns its length.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Which transport this is.
    fn kind(&self) -> TransportKind;

    /// Remote endpoint, when the transport has a meaningful single peer.
    /// `None` for transports where the notion does not apply.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Local endpoint, when the transport has one.
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Largest single datagram this transport will carry.
    ///
    /// Deliberately has no default: a transport that silently inherits UDP's
    /// ceiling while actually being unable to carry it would fail as truncated
    /// or dropped packets far from the cause. Callers use this to size the
    /// tunnel MTU; how a transport copes with a payload that would exceed its
    /// own limit is entirely its own business and invisible here.
    fn max_datagram(&self) -> usize;

    /// Release the transport's resources. Idempotent: calling it twice, or on a
    /// transport that already failed, must not panic.
    ///
    /// The default is a no-op, which is correct for anything whose teardown is
    /// just dropping a socket.
    async fn close(&self) -> Result<()> {
        Ok(())
    }

    /// Raw socket descriptor, for kernel-offload paths that must hook the
    /// socket itself (Linux `aivpn.ko` UDP hook, XDP). `None` means "this
    /// transport cannot be offloaded" and callers must stay on the user-space
    /// path — which is always correct, only slower.
    #[cfg(unix)]
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

/// The transport in use today: a thin wrapper over a **connected**
/// `tokio::net::UdpSocket`.
///
/// Connected-socket semantics are load-bearing and preserved exactly:
/// `send()`/`recv()` (not `send_to`/`recv_from`), so the kernel keeps filtering
/// inbound datagrams to the server endpoint and the client never has to check
/// the source address itself.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    /// Wrap an already-connected UDP socket. The socket must have had
    /// `connect()` called on it — `send`/`recv` fail otherwise.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    /// Escape hatch to the underlying socket, for UDP-specific fast paths
    /// (batch I/O, socket options) that have no meaning on other transports.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

impl From<Arc<UdpSocket>> for UdpTransport {
    fn from(socket: Arc<UdpSocket>) -> Self {
        Self::new(socket)
    }
}

#[async_trait]
impl DatagramTransport for UdpTransport {
    async fn send(&self, datagram: &[u8]) -> std::io::Result<usize> {
        self.socket.send(datagram).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv(buf).await
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Udp
    }

    fn max_datagram(&self) -> usize {
        MAX_UDP_PAYLOAD
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.socket.peer_addr().ok()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    #[cfg(unix)]
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.socket.as_raw_fd())
    }
}

/// Convenience alias for the shared handle the client passes around.
pub type SharedTransport = Arc<dyn DatagramTransport>;

/// Wrap a connected UDP socket as a `SharedTransport`.
pub fn udp_transport(socket: Arc<UdpSocket>) -> SharedTransport {
    Arc::new(UdpTransport::new(socket))
}

/// Keeps a transport's own sockets out of the tunnel that transport feeds.
///
/// Without this a transport's packets are routed back into the very tunnel they
/// are carrying, and the connection dies the moment it starts working. Every
/// socket a transport creates is passed through `protect` before its first
/// byte.
///
/// The default implementations are no-ops, so a platform that needs nothing
/// (and the public build, which only ever speaks direct UDP through a socket it
/// did not create here) implements nothing.
///
/// # Why this is a separate type and not an existing platform hook
///
/// `Send + Sync` is required: the guard is shared (`Arc`) for the lifetime of a
/// transport that may create sockets from several tasks. The mobile run loop's
/// `PlatformIo` hook looks similar but is deliberately **not** `Sync` — it
/// carries iOS's raw Swift context pointer, which nothing synchronises — so it
/// cannot be reused here. Platforms construct a small guard alongside it.
pub trait SocketGuard: Send + Sync {
    /// Exempt one socket from the tunnel. Called before the socket's first
    /// byte, once per socket.
    ///
    /// On `Err` the caller closes the socket; an implementation must not close
    /// it itself.
    #[cfg(unix)]
    fn protect(&self, _fd: RawFd) -> Result<()> {
        Ok(())
    }

    /// Windows counterpart. Split by `cfg` rather than unified behind a newtype
    /// because there is no descriptor type common to both, and a seam that only
    /// names `RawFd` simply fails to compile on Windows the day a transport
    /// there needs it.
    #[cfg(windows)]
    fn protect(&self, _sock: std::os::windows::io::RawSocket) -> Result<()> {
        Ok(())
    }
}

/// Guard for the case where no exemption is needed — iOS (the extension
/// process is already outside the tunnel) and any transport whose sockets the
/// platform routes correctly on its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSocketGuard;

impl SocketGuard for NoSocketGuard {}

/// Shared handle to the platform's guard.
pub type SharedGuard = Arc<dyn SocketGuard>;

/// Linux guard: stamps every socket with an `SO_MARK` value.
///
/// The tunnel's own routing sends everything into the tunnel device. A
/// transport that opens sockets to addresses the client does not (and cannot)
/// enumerate in advance needs its packets kept out of that path, and a mark is
/// the only mechanism that does not require knowing the destinations: one
/// `ip rule` matching the mark and pointing at the main table covers every
/// address the transport will ever use, present and future.
///
/// A host route per destination — which is how the direct UDP path exempts
/// itself, since it has exactly one — cannot do this: the set of addresses is
/// discovered at runtime and changes during a session, and every gap between
/// discovering an address and installing its route is a leak.
///
/// Marking alone is not enough: the matching `ip rule` must exist, and
/// installing it is the routing layer's job, not the guard's. Without the rule
/// the mark is inert and the sockets route normally — which is why the tunnel
/// installs the rule before a marked transport is opened.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct MarkGuard {
    mark: u32,
}

#[cfg(target_os = "linux")]
impl MarkGuard {
    /// Guard stamping `mark` on each socket. `0` clears the mark, which is
    /// indistinguishable from no guard at all — callers should pass a real
    /// value.
    pub fn new(mark: u32) -> Self {
        Self { mark }
    }

    /// The mark this guard applies, so the routing and firewall layers can be
    /// configured against the same value instead of duplicating a constant.
    pub fn mark(&self) -> u32 {
        self.mark
    }
}

#[cfg(target_os = "linux")]
impl SocketGuard for MarkGuard {
    fn protect(&self, fd: RawFd) -> Result<()> {
        let mark = self.mark;
        // SAFETY: `fd` is a socket the caller has just created and still owns;
        // `SO_MARK` takes a `u32` by pointer, and the size is passed exactly.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // Failing open here would route the transport's own packets into
            // the tunnel it is carrying, which does not degrade — it deadlocks
            // the connection in a way that looks like an unrelated network
            // fault. Fail loudly instead.
            return Err(Error::Session(format!(
                "SO_MARK={mark} on fd {fd} failed: {err} \
                 (CAP_NET_ADMIN is required to mark sockets)"
            )));
        }
        Ok(())
    }
}

/// A guard that protects nothing.
pub fn no_socket_guard() -> SharedGuard {
    Arc::new(NoSocketGuard)
}

/// Which transport to open, and the parameters it needs.
///
/// The parameters are an **opaque blob**: this crate neither parses nor
/// validates their contents, it only hands them to the factory that claimed the
/// name. That keeps transport-specific configuration — whatever a given
/// transport happens to need — out of the shared code entirely.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportConfig {
    name: String,
    params: Vec<u8>,
}

impl TransportConfig {
    /// Name of the transport to open, matching `TransportFactory::name`.
    pub fn new(name: impl Into<String>, params: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            params,
        }
    }

    /// Name the registry looks up.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Uninterpreted parameters for the chosen transport.
    pub fn params(&self) -> &[u8] {
        &self.params
    }
}

/// Builds one kind of transport on demand.
///
/// Registering a factory is the whole extension mechanism: a module that
/// implements this trait can be plugged in from `main` without the rest of the
/// codebase referring to it.
#[async_trait]
pub trait TransportFactory: Send + Sync {
    /// Stable identifier used in configuration. Must match
    /// `TransportConfig::name` exactly.
    fn name(&self) -> &str;

    /// Human-readable label, if this transport is ever surfaced in an
    /// interface.
    ///
    /// It comes from the factory rather than from the application's own
    /// translation files on purpose: a factory that is not part of a given
    /// build should contribute no strings to that build.
    fn display_name(&self) -> &str {
        self.name()
    }

    /// Open a transport. `guard` must be applied to every socket the transport
    /// creates, before its first byte (see [`SocketGuard`]).
    async fn open(&self, cfg: &TransportConfig, guard: SharedGuard) -> Result<SharedTransport>;
}

/// The set of transports available to this build.
///
/// Registration order is preserved, so a caller listing the registry gets a
/// stable order rather than a hash order.
#[derive(Default)]
pub struct TransportRegistry {
    factories: Vec<Arc<dyn TransportFactory>>,
}

impl TransportRegistry {
    /// An empty registry. A build that registers nothing can still only reach
    /// direct UDP, which is the default path.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a factory. A later registration under an existing name replaces the
    /// earlier one, keeping its position.
    pub fn register(&mut self, factory: Arc<dyn TransportFactory>) {
        match self
            .factories
            .iter()
            .position(|f| f.name() == factory.name())
        {
            Some(i) => self.factories[i] = factory,
            None => self.factories.push(factory),
        }
    }

    /// Look up a factory by configured name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn TransportFactory>> {
        self.factories.iter().find(|f| f.name() == name)
    }

    /// `(name, display_name)` for every registered transport, in registration
    /// order — enough to drive a selector without knowing what any entry is.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.factories.iter().map(|f| (f.name(), f.display_name()))
    }

    /// Whether anything is registered at all.
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    /// Open the transport named by `cfg`.
    ///
    /// An unknown name is an error rather than a silent fallback to direct UDP:
    /// a configuration asking for a transport this build does not have is a
    /// misconfiguration, and quietly sending the traffic another way would be
    /// both wrong and, on a network where the configured transport was chosen
    /// for a reason, conspicuous.
    pub async fn open(&self, cfg: &TransportConfig, guard: SharedGuard) -> Result<SharedTransport> {
        match self.get(cfg.name()) {
            Some(factory) => factory.open(cfg, guard).await,
            None => Err(Error::Session(format!(
                "no transport registered under the name {:?}",
                cfg.name()
            ))),
        }
    }
}

impl std::fmt::Debug for TransportRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportRegistry")
            .field(
                "registered",
                &self.factories.iter().map(|x| x.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{mpsc, Mutex};

    /// In-memory stand-in for a transport, and the reason it exists.
    ///
    /// The seam has one real implementation (`UdpTransport`) and is otherwise
    /// only used from outside this repository. A seam with no local second
    /// implementation rots quietly: signatures around it drift and nothing
    /// notices until something far away fails to compile. This double is that
    /// second implementation — it exercises every part of the contract
    /// (`send`/`recv`/`kind`/`max_datagram`/`close`) with no sockets involved.
    struct LoopbackTransport {
        outbound: mpsc::UnboundedSender<Vec<u8>>,
        inbound: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        limit: usize,
        closes: AtomicUsize,
    }

    impl LoopbackTransport {
        /// A connected pair: what one sends, the other receives.
        fn pair(limit: usize) -> (Arc<Self>, Arc<Self>) {
            let (a_tx, b_rx) = mpsc::unbounded_channel();
            let (b_tx, a_rx) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    outbound: a_tx,
                    inbound: Mutex::new(a_rx),
                    limit,
                    closes: AtomicUsize::new(0),
                }),
                Arc::new(Self {
                    outbound: b_tx,
                    inbound: Mutex::new(b_rx),
                    limit,
                    closes: AtomicUsize::new(0),
                }),
            )
        }
    }

    #[async_trait]
    impl DatagramTransport for LoopbackTransport {
        async fn send(&self, datagram: &[u8]) -> std::io::Result<usize> {
            if datagram.len() > self.limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "datagram exceeds transport limit",
                ));
            }
            self.outbound
                .send(datagram.to_vec())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(datagram.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let msg = self
                .inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            let n = msg.len().min(buf.len());
            buf[..n].copy_from_slice(&msg[..n]);
            Ok(n)
        }

        fn kind(&self) -> TransportKind {
            TransportKind::Udp
        }

        fn max_datagram(&self) -> usize {
            self.limit
        }

        async fn close(&self) -> Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Factory over the double, so the registry path is exercised too.
    struct LoopbackFactory;

    #[async_trait]
    impl TransportFactory for LoopbackFactory {
        fn name(&self) -> &str {
            "loopback"
        }

        fn display_name(&self) -> &str {
            "In-memory loopback"
        }

        async fn open(&self, cfg: &TransportConfig, guard: SharedGuard) -> Result<SharedTransport> {
            // A real factory protects every socket it creates; this one creates
            // none, but still exercises the call so the guard type stays used.
            #[cfg(unix)]
            guard.protect(-1)?;
            let limit = if cfg.params().is_empty() {
                1200
            } else {
                cfg.params()[0] as usize * 100
            };
            let (a, _b) = LoopbackTransport::pair(limit);
            Ok(a)
        }
    }

    /// The double must satisfy the same contract as the real transport:
    /// datagrams keep their boundaries and their bytes.
    #[tokio::test]
    async fn test_double_roundtrip_preserves_boundaries() {
        let (a, b) = LoopbackTransport::pair(1200);
        let a: SharedTransport = a;
        let b: SharedTransport = b;

        for len in [1usize, 64, 1200] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(a.send(&payload).await.unwrap(), len);
        }

        for len in [1usize, 64, 1200] {
            let mut buf = vec![0u8; 4096];
            let n = b.recv(&mut buf).await.unwrap();
            assert_eq!(n, len, "message boundary lost");
            assert_eq!(
                &buf[..n],
                &(0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>()[..]
            );
        }
    }

    /// `max_datagram` is the contract callers size the tunnel MTU against, so a
    /// transport must report its own limit rather than inherit UDP's.
    #[tokio::test]
    async fn test_double_reports_its_own_ceiling() {
        let (a, _b) = LoopbackTransport::pair(1200);
        assert_eq!(a.max_datagram(), 1200);
        assert!(a.send(&vec![0u8; 1201]).await.is_err());
    }

    /// `close` is idempotent — the default contract every implementation
    /// promises.
    #[tokio::test]
    async fn close_is_idempotent() {
        let (a, _b) = LoopbackTransport::pair(1200);
        a.close().await.unwrap();
        a.close().await.unwrap();
        assert_eq!(a.closes.load(Ordering::SeqCst), 2);
    }

    /// The registry resolves a configured name to its factory and hands back a
    /// working transport.
    #[tokio::test]
    async fn registry_opens_the_named_transport() {
        let mut reg = TransportRegistry::new();
        assert!(reg.is_empty());
        reg.register(Arc::new(LoopbackFactory));

        assert_eq!(
            reg.entries().collect::<Vec<_>>(),
            vec![("loopback", "In-memory loopback")]
        );

        let cfg = TransportConfig::new("loopback", vec![12]);
        let t = reg.open(&cfg, no_socket_guard()).await.unwrap();
        assert_eq!(t.max_datagram(), 1200);
    }

    /// An unknown transport name must fail loudly. Falling back to direct UDP
    /// would silently ignore a deliberate configuration choice.
    #[tokio::test]
    async fn registry_rejects_unknown_transport_instead_of_falling_back() {
        let reg = TransportRegistry::new();
        let cfg = TransportConfig::new("absent", Vec::new());
        // `unwrap_err` would demand `Debug` on `dyn DatagramTransport`; the
        // trait deliberately does not require it, so match instead.
        let msg = match reg.open(&cfg, no_socket_guard()).await {
            Ok(_) => panic!("unknown transport name must not resolve"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("absent"),
            "error should name the missing transport, got: {msg}"
        );
    }

    /// Re-registering a name replaces the factory and keeps its position, so a
    /// build cannot end up with two transports answering to one name.
    #[test]
    fn re_registering_a_name_replaces_in_place() {
        struct Other;
        #[async_trait]
        impl TransportFactory for Other {
            fn name(&self) -> &str {
                "loopback"
            }
            fn display_name(&self) -> &str {
                "replacement"
            }
            async fn open(&self, _c: &TransportConfig, _g: SharedGuard) -> Result<SharedTransport> {
                unreachable!()
            }
        }

        let mut reg = TransportRegistry::new();
        reg.register(Arc::new(LoopbackFactory));
        reg.register(Arc::new(Other));
        assert_eq!(
            reg.entries().collect::<Vec<_>>(),
            vec![("loopback", "replacement")]
        );
    }

    /// The default guard protects nothing and must never fail — the public
    /// build relies on it being a true no-op.
    #[cfg(unix)]
    #[test]
    fn default_guard_is_a_noop() {
        let g = no_socket_guard();
        assert!(g.protect(-1).is_ok());
    }

    /// The mark guard must actually set `SO_MARK` on the socket, and the value
    /// read back must be the one asked for — a guard that silently marks
    /// nothing routes the transport into the tunnel it carries.
    ///
    /// Marking requires `CAP_NET_ADMIN`; unprivileged runs (ordinary CI) skip
    /// the assertion rather than fail, but still exercise the call path.
    #[cfg(target_os = "linux")]
    #[test]
    fn mark_guard_sets_so_mark_when_permitted() {
        use std::os::unix::io::AsRawFd;

        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = sock.as_raw_fd();
        let guard = MarkGuard::new(0x4149);
        assert_eq!(guard.mark(), 0x4149);

        match guard.protect(fd) {
            Err(_) => {
                // No CAP_NET_ADMIN. The error must name the capability, so the
                // failure is actionable rather than a bare errno.
                let msg = guard.protect(fd).unwrap_err().to_string();
                assert!(msg.contains("CAP_NET_ADMIN"), "unhelpful error: {msg}");
            }
            Ok(()) => {
                let mut got: u32 = 0;
                let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
                // SAFETY: reading back the option we just set on a live fd.
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mut got as *mut u32 as *mut libc::c_void,
                        &mut len,
                    )
                };
                assert_eq!(rc, 0, "getsockopt(SO_MARK) failed");
                assert_eq!(got, 0x4149, "mark was not applied");
            }
        }
    }

    /// A closed descriptor must produce an error, not a silent success: the
    /// caller closes the socket on `Err`, and a guard that reports success for
    /// an unmarked socket would let the transport run unprotected.
    #[cfg(target_os = "linux")]
    #[test]
    fn mark_guard_rejects_a_bad_descriptor() {
        let guard = MarkGuard::new(0x4149);
        assert!(guard.protect(-1).is_err());
    }

    /// The wrapper must be a pure pass-through: a datagram sent through
    /// `DatagramTransport::send` arrives byte-identical, and `recv` returns it
    /// whole — same as calling the socket directly.
    #[tokio::test]
    async fn udp_transport_roundtrip_is_byte_identical() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        server.connect(client_addr).await.unwrap();

        let client_t = udp_transport(Arc::new(client));
        let server_t = udp_transport(Arc::new(server));

        assert_eq!(client_t.kind(), TransportKind::Udp);
        assert_eq!(client_t.kind().as_str(), "udp");
        assert_eq!(client_t.peer_addr(), Some(server_addr));
        assert_eq!(client_t.local_addr(), Some(client_addr));

        let payload: Vec<u8> = (0u16..1200).map(|i| (i % 251) as u8).collect();
        assert_eq!(client_t.send(&payload).await.unwrap(), payload.len());

        let mut buf = vec![0u8; 2048];
        let n = server_t.recv(&mut buf).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], &payload[..]);
    }

    /// `raw_fd` must expose the real descriptor — the Linux kernel-offload path
    /// hooks it, and a wrong/absent fd silently disables acceleration.
    #[cfg(unix)]
    #[tokio::test]
    async fn udp_transport_exposes_raw_fd() {
        use std::os::unix::io::AsRawFd;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let expected = socket.as_raw_fd();
        let t = UdpTransport::new(socket);
        assert_eq!(t.raw_fd(), Some(expected));
    }

    /// Concurrent `send` while another task is parked in `recv` must work —
    /// this is exactly the client's RX-task/upload-task split, and the reason
    /// the trait takes `&self` rather than `&mut self`.
    #[tokio::test]
    async fn concurrent_send_and_recv_over_shared_handle() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        a.connect(b_addr).await.unwrap();
        b.connect(a_addr).await.unwrap();

        let a_t = udp_transport(Arc::new(a));
        let b_t = udp_transport(Arc::new(b));

        let rx = {
            let a_t = a_t.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64];
                let n = a_t.recv(&mut buf).await.unwrap();
                buf.truncate(n);
                buf
            })
        };

        // Sends from this task while the spawned task holds `recv` on the same
        // shared handle family.
        a_t.send(b"ping").await.unwrap();
        b_t.send(b"pong").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = b_t.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(rx.await.unwrap(), b"pong");
    }
}
