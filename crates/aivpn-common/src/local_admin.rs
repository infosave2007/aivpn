//! Локальные запросы управления с ограниченной длиной сообщения.

use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::time::Duration;

pub const MAX_FRAME: usize = 1024 * 1024;

pub fn request(addr: SocketAddrV4, line: &str, timeout: Duration) -> io::Result<String> {
    if !addr.ip().is_loopback() || line.is_empty() || line.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid local admin request",
        ));
    }
    let mut socket = TcpStream::connect_timeout(&addr.into(), Duration::from_secs(2))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.write_all(&(line.len() as u32).to_be_bytes())?;
    socket.write_all(line.as_bytes())?;
    read_frame(&mut socket)
}

fn read_frame(socket: &mut impl Read) -> io::Result<String> {
    let mut header = [0; 4];
    socket.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid local admin reply size",
        ));
    }
    let mut data = vec![0; len];
    socket.read_exact(&mut data)?;
    String::from_utf8(data).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid local admin reply encoding",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_fragmented_reply_and_invalid_frames() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut socket).unwrap(), "token:role");
            let body = "x".repeat(350_000);
            for byte in (body.len() as u32).to_be_bytes() {
                socket.write_all(&[byte]).unwrap();
            }
            for part in body.as_bytes().chunks(701) {
                socket.write_all(part).unwrap();
            }
        });
        assert_eq!(
            request(addr, "token:role", Duration::from_secs(5)).unwrap(),
            "x".repeat(350_000)
        );
        task.join().unwrap();
        assert!(read_frame(&mut &u32::MAX.to_be_bytes()[..]).is_err());
        assert!(read_frame(&mut &b"\0\0\0\x04ab"[..]).is_err());
    }
}
