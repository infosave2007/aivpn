//! Кадры приватного byte pipe сохраняют границы при отмене и смене сеанса.
use std::{io, num::NonZeroU64, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};
const MAX_PACKET: usize = 65535;
const HEADER_BYTES: usize = 12;
type Wake = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

pub struct Channel<T> {
    reader: Arc<Mutex<ReadState<ReadHalf<T>>>>,
    writer: Arc<Mutex<WriteState<WriteHalf<T>>>>,
}
impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}
impl<T: AsyncRead + AsyncWrite + Unpin> Channel<T> {
    pub fn new(stream: T) -> Self {
        Self::with_wakeup(stream, None)
    }
    pub fn with_wakeup(stream: T, wake: Option<Wake>) -> Self {
        Self::with_wakeup_capacity(stream, wake, 0)
    }
    pub fn with_wakeup_capacity(stream: T, wake: Option<Wake>, capacity: usize) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Arc::new(Mutex::new(ReadState {
                stream: reader,
                header: [0; HEADER_BYTES],
                header_filled: 0,
                packet: Vec::new(),
                packet_filled: 0,
            })),
            writer: Arc::new(Mutex::new(WriteState {
                stream: writer,
                frame: Vec::new(),
                written: 0,
                wake,
                capacity,
            })),
        }
    }
    pub fn reader(&self, generation: NonZeroU64) -> Reader<T> {
        Reader {
            state: self.reader.clone(),
            generation,
        }
    }
    pub async fn write(&self, generation: NonZeroU64, packet: &[u8]) -> io::Result<usize> {
        if !(20..=MAX_PACKET).contains(&packet.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.writer.lock().await;
        // Отмененный write завершается со старой меткой, а не с новой lease.
        state.flush_frame().await?;
        state.frame.clear();
        state
            .frame
            .extend_from_slice(&(packet.len() as u32).to_le_bytes());
        state
            .frame
            .extend_from_slice(&generation.get().to_le_bytes());
        state.frame.extend_from_slice(packet);
        state.written = 0;
        state.flush_frame().await?;
        Ok(packet.len())
    }
}
struct WriteState<W> {
    stream: W,
    frame: Vec<u8>,
    written: usize,
    wake: Option<Wake>,
    capacity: usize,
}
impl<W: AsyncWrite + Unpin> WriteState<W> {
    async fn flush_frame(&mut self) -> io::Result<()> {
        while self.written < self.frame.len() {
            // Малый кадр помещается целиком; крупный сначала будит читателя заголовком.
            let end = if self.wake.is_some()
                && self.written < HEADER_BYTES
                && self.frame.len() > self.capacity
            {
                HEADER_BYTES
            } else {
                self.frame.len()
            };
            let header_pending = self.written < HEADER_BYTES;
            let size = self.stream.write(&self.frame[self.written..end]).await?;
            if size == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.written += size;
            if header_pending && self.written >= HEADER_BYTES {
                if let Some(wake) = &self.wake {
                    wake()?;
                }
            }
        }
        Ok(())
    }
}
pub struct Reader<T> {
    state: Arc<Mutex<ReadState<ReadHalf<T>>>>,
    generation: NonZeroU64,
}
impl<T: AsyncRead + AsyncWrite + Unpin> Reader<T> {
    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.state.lock().await.read(self.generation, buffer).await
    }
}
struct ReadState<R> {
    stream: R,
    header: [u8; HEADER_BYTES],
    header_filled: usize,
    packet: Vec<u8>,
    packet_filled: usize,
}
impl<R: AsyncRead + Unpin> ReadState<R> {
    async fn read(&mut self, generation: NonZeroU64, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            while self.header_filled < HEADER_BYTES {
                let size = self
                    .stream
                    .read(&mut self.header[self.header_filled..])
                    .await?;
                if size == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.header_filled += size;
            }
            let size = u32::from_le_bytes(self.header[..4].try_into().unwrap()) as usize;
            let received = u64::from_le_bytes(self.header[4..].try_into().unwrap());
            if !(20..=MAX_PACKET).contains(&size) || size > buffer.len() || received == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.packet.resize(size, 0);
            while self.packet_filled < size {
                let count = self
                    .stream
                    .read(&mut self.packet[self.packet_filled..])
                    .await?;
                if count == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.packet_filled += count;
            }
            self.header_filled = 0;
            self.packet_filled = 0;
            if received > generation.get() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if received == generation.get() {
                buffer[..size].copy_from_slice(&self.packet);
                return Ok(size);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
        time::Duration,
    };

    struct CountedStream {
        stream: tokio::io::DuplexStream,
        writes: Arc<AtomicUsize>,
    }
    impl AsyncRead for CountedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
        }
    }
    impl AsyncWrite for CountedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let result = Pin::new(&mut this.stream).poll_write(cx, buffer);
            if matches!(result, Poll::Ready(Ok(size)) if size != 0) {
                this.writes.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
        }
    }
    fn generation(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }
    fn frame(generation: u64, packet: &[u8]) -> Vec<u8> {
        [
            (packet.len() as u32).to_le_bytes().as_slice(),
            generation.to_le_bytes().as_slice(),
            packet,
        ]
        .concat()
    }
    #[tokio::test]
    async fn packet_fitting_the_known_pipe_capacity_needs_one_write_and_one_wakeup() {
        let (stream, mut peer) = tokio::io::duplex(65536);
        let writes = Arc::new(AtomicUsize::new(0));
        let wakes = Arc::new(AtomicUsize::new(0));
        let notified = wakes.clone();
        let channel = Channel::with_wakeup_capacity(
            CountedStream {
                stream,
                writes: writes.clone(),
            },
            Some(Arc::new(move || {
                notified.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })),
            65536,
        );
        let packet = [0x45; 1280];
        assert_eq!(
            channel.write(generation(7), &packet).await.unwrap(),
            packet.len()
        );
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        let mut received = vec![0; HEADER_BYTES + packet.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, frame(7, &packet));
        assert_eq!(writes.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn canceled_coalesced_write_preserves_wakeup_and_generation() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let wakes = Arc::new(AtomicUsize::new(0));
        let notified = wakes.clone();
        let channel = Channel::with_wakeup_capacity(
            stream,
            Some(Arc::new(move || {
                notified.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })),
            64,
        );
        channel.write(generation(1), &[0x45; 20]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            channel.write(generation(1), &[0x46; 40])
        )
        .await
        .is_err());
        assert_eq!(wakes.load(Ordering::Relaxed), 2);
        let (written, received) = tokio::join!(channel.write(generation(2), &[0x47; 20]), async {
            let mut bytes = vec![0; 32 + 52 + 32];
            peer.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        assert_eq!(written.unwrap(), 20);
        assert_eq!(
            received,
            [
                frame(1, &[0x45; 20]),
                frame(1, &[0x46; 40]),
                frame(2, &[0x47; 20])
            ]
            .concat()
        );
        assert_eq!(wakes.load(Ordering::Relaxed), 3);
    }
    #[tokio::test]
    async fn writer_wakes_reader_before_a_body_larger_than_the_pipe_buffer() {
        let (stream, mut peer) = tokio::io::duplex(HEADER_BYTES);
        let (notification, mut notified) = tokio::sync::mpsc::unbounded_channel();
        let channel = Channel::with_wakeup_capacity(
            stream,
            Some(Arc::new(move || {
                notification
                    .send(())
                    .map_err(|_| io::ErrorKind::BrokenPipe.into())
            })),
            HEADER_BYTES,
        );
        let writer = tokio::spawn(async move {
            assert_eq!(
                channel.write(generation(7), &[0x45; 1024]).await.unwrap(),
                1024
            );
            channel
        });
        tokio::time::timeout(Duration::from_secs(2), notified.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!writer.is_finished());
        let mut received = vec![0; HEADER_BYTES + 1024];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, frame(7, &[0x45; 1024]));
        let channel = writer.await.unwrap();
        let writer = tokio::spawn(async move { channel.write(generation(8), &[0x46; 20]).await });
        tokio::time::timeout(Duration::from_secs(2), notified.recv())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; HEADER_BYTES + 20];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(writer.await.unwrap().unwrap(), 20);
        assert_eq!(received, frame(8, &[0x46; 20]));
    }
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn native_pipe_wakes_before_a_large_frame_and_after_a_small_frame() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let name = format!(r"\\.\pipe\aivpn-framed-capacity-{}", std::process::id());
        let mut peer = ServerOptions::new()
            .first_pipe_instance(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            .create(&name)
            .unwrap();
        let client = ClientOptions::new().open(&name).unwrap();
        peer.connect().await.unwrap();
        let capacity = client.info().unwrap().in_buffer_size as usize;
        assert!((HEADER_BYTES..MAX_PACKET + HEADER_BYTES).contains(&capacity));
        let (notification, mut notified) = tokio::sync::mpsc::unbounded_channel();
        let channel = Channel::with_wakeup_capacity(
            client,
            Some(Arc::new(move || {
                notification
                    .send(())
                    .map_err(|_| io::ErrorKind::BrokenPipe.into())
            })),
            capacity,
        );
        let writer = tokio::spawn(async move {
            channel
                .write(generation(7), &vec![0x45; MAX_PACKET])
                .await
                .unwrap();
            channel
        });
        tokio::time::timeout(Duration::from_secs(2), notified.recv())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; HEADER_BYTES + MAX_PACKET];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, frame(7, &vec![0x45; MAX_PACKET]));
        let channel = writer.await.unwrap();
        channel.write(generation(8), &[0x46; 1280]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), notified.recv())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; HEADER_BYTES + 1280];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, frame(8, &[0x46; 1280]));
        assert!(notified.try_recv().is_err());
    }
    #[tokio::test]
    async fn reconnect_keeps_partial_frame_and_discards_old_generation() {
        let (stream, mut peer) = tokio::io::duplex(256);
        let channel = Channel::new(stream);
        let old = frame(1, &[0x45; 20]);
        peer.write_all(&old[..7]).await.unwrap();
        let mut reader = channel.reader(generation(1));
        let mut buffer = [0; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.read(&mut buffer))
                .await
                .is_err()
        );
        drop(reader);
        peer.write_all(&old[7..]).await.unwrap();
        peer.write_all(&frame(2, &[0x46; 24])).await.unwrap();
        let mut next = channel.reader(generation(2));
        assert_eq!(next.read(&mut buffer).await.unwrap(), 24);
        assert_eq!(&buffer[..24], &[0x46; 24]);
        peer.write_all(&frame(2, &[0x45; 20])).await.unwrap();
        assert_eq!(next.read(&mut buffer).await.unwrap(), 20);
        assert_eq!(&buffer[..20], &[0x45; 20]);
    }
    #[tokio::test]
    async fn canceled_write_finishes_old_frame_before_next_generation() {
        let (stream, mut peer) = tokio::io::duplex(8);
        let channel = Channel::new(stream);
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            channel.write(generation(1), &[0x45; 20])
        )
        .await
        .is_err());
        let (written, received) = tokio::join!(channel.write(generation(2), &[0x46; 24]), async {
            let mut bytes = vec![0; 32 + 36];
            peer.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        assert_eq!(written.unwrap(), 24);
        assert_eq!(
            received,
            [frame(1, &[0x45; 20]), frame(2, &[0x46; 24])].concat()
        );
    }
    #[tokio::test]
    async fn future_generation_is_rejected_before_later_current_packet() {
        let (stream, mut peer) = tokio::io::duplex(256);
        let channel = Channel::new(stream);
        peer.write_all(&frame(3, &[0x45; 20])).await.unwrap();
        peer.write_all(&frame(2, &[0x46; 24])).await.unwrap();
        let mut reader = channel.reader(generation(2));
        let mut buffer = [0; 128];
        assert_eq!(
            reader.read(&mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(reader.read(&mut buffer).await.unwrap(), 24);
        assert_eq!(&buffer[..24], &[0x46; 24]);
    }
}
