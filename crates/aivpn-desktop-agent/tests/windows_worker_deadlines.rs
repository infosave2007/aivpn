#![cfg(target_os = "windows")]

use aivpn_desktop_agent::{
    windows::worker::WorkerChannel,
    worker_protocol::{InterfaceAssignment, WorkerEvent},
};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};

fn pair() -> (WorkerChannel, File) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let name: Vec<u16> = format!(
        "\\\\.\\pipe\\aivpn-worker-deadline-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            ptr::null(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
    let server = unsafe { OwnedHandle::from_raw_handle(raw) };
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            ptr::null_mut(),
        )
    };
    assert_ne!(
        client,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    let connected = unsafe { ConnectNamedPipe(raw, ptr::null_mut()) };
    assert!(
        connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED,
        "{}",
        io::Error::last_os_error()
    );
    (
        WorkerChannel::from_owned(client).unwrap(),
        File::from(server),
    )
}

fn packet_frame(generation: u64, value: u8, size: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + size);
    frame.extend_from_slice(&(size as u32).to_le_bytes());
    frame.extend_from_slice(&generation.to_le_bytes());
    frame.resize(12 + size, value);
    frame
}

#[test]
fn complete_packet_uses_one_pipe_read_and_preserves_the_next_frame() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "packet_read_counter_child", "--nocapture"])
        .env("AIVPN_PACKET_READ_COUNTER_CHILD", "1")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
}

#[test]
fn packet_read_counter_child() {
    if std::env::var_os("AIVPN_PACKET_READ_COUNTER_CHILD").is_none() {
        return;
    }
    let (mut channel, mut service) = pair();
    let mut frames = packet_frame(7, 0x5a, 1500);
    frames.extend_from_slice(&packet_frame(7, 0xa5, 1400));
    service.write_all(&frames).unwrap();
    let counters = || {
        let mut value: IO_COUNTERS = unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe { GetProcessIoCounters(GetCurrentProcess(), &mut value) },
            0
        );
        value.ReadOperationCount
    };
    let mut packet = [0; 65535];
    let before = counters();
    let first = channel.packet_receive(7, &mut packet).unwrap();
    let reads = counters() - before;
    assert_eq!(first, Some(1500));
    assert!(packet[..1500].iter().all(|value| *value == 0x5a));
    assert_eq!(
        reads, 1,
        "Готовый пакет не требует отдельных чтений заголовка"
    );
    assert_eq!(channel.packet_receive(7, &mut packet).unwrap(), Some(1400));
    assert!(packet[..1400].iter().all(|value| *value == 0xa5));
}

#[test]
fn partial_packet_header_and_body_keep_the_generation_boundary() {
    let (mut channel, mut service) = pair();
    let writer = thread::spawn(move || {
        let frame = packet_frame(6, 0x5a, 1500);
        service.write_all(&frame[..3]).unwrap();
        thread::sleep(Duration::from_millis(30));
        service.write_all(&frame[3..16]).unwrap();
        thread::sleep(Duration::from_millis(30));
        service.write_all(&frame[16..]).unwrap();
        service.write_all(&packet_frame(7, 0xa5, 1400)).unwrap();
    });
    let mut packet = [0; 65535];
    assert_eq!(channel.packet_receive(7, &mut packet).unwrap(), None);
    assert_eq!(channel.packet_receive(7, &mut packet).unwrap(), Some(1400));
    assert!(packet[..1400].iter().all(|value| *value == 0xa5));
    writer.join().unwrap();
}

#[test]
fn packet_reader_rejects_invalid_sizes_and_generations() {
    for (generation, size) in [(0, 20), (8, 20), (7, 19), (7, 65536)] {
        let (mut channel, mut service) = pair();
        let mut frame = packet_frame(generation, 0x5a, 20);
        frame[..4].copy_from_slice(&(size as u32).to_le_bytes());
        service.write_all(&frame[..12]).unwrap();
        assert!(channel.packet_receive(7, &mut [0; 65535]).is_err());
    }
}

#[test]
fn largest_packet_does_not_wait_for_a_frame_larger_than_the_pipe_buffer() {
    let (mut channel, mut service) = pair();
    let writer = thread::spawn(move || {
        service.write_all(&packet_frame(7, 0x5a, 65535)).unwrap();
    });
    let mut packet = [0; 65535];
    assert_eq!(channel.packet_receive(7, &mut packet).unwrap(), Some(65535));
    assert!(packet.iter().all(|value| *value == 0x5a));
    writer.join().unwrap();
}

#[test]
fn confirmed_assignment_accepts_a_reply_after_slow_policy_installation() {
    let event = WorkerEvent::Assignment {
        generation: 7,
        network: InterfaceAssignment {
            client_ip: "10.77.0.2".parse().unwrap(),
            server_vpn_ip: "10.77.0.1".parse().unwrap(),
            prefix_len: 24,
            mtu: 1280,
            mdh_len: 8,
            ipv6: None,
        },
    };
    let (channel, mut service) = pair();
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_secs(6));
        service.write_all(b"\0\0\0\x03ACK").unwrap();
    });
    let result = channel.receive(event.response_timeout());
    sender.join().unwrap();
    assert_eq!(result.unwrap(), b"ACK");
}

#[test]
fn slow_reply_body_cannot_use_the_operation_waiting_deadline() {
    let (channel, mut service) = pair();
    let sender = thread::spawn(move || {
        service.write_all(&[0]).unwrap();
        thread::sleep(Duration::from_secs(6));
        let _ = service.write_all(b"\0\0\x03ACK");
    });
    let started = Instant::now();
    let result = channel.receive(Duration::from_secs(30));
    let elapsed = started.elapsed();
    sender.join().unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[test]
fn worker_frame_wakes_a_waiting_service_before_it_reads_the_body() {
    let (channel, mut service) = pair();
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!raw.is_null(), "{}", io::Error::last_os_error());
    let event = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw) });
    let notify = event.clone();
    let channel = channel.with_wakeup(Arc::new(move || {
        if unsafe { SetEvent(notify.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }));
    assert_eq!(
        unsafe { WaitForSingleObject(event.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    let writer = thread::spawn(move || channel.send(&vec![0x5a; 65536], Duration::from_secs(5)));
    assert_eq!(
        unsafe { WaitForSingleObject(event.as_raw_handle(), 2000) },
        WAIT_OBJECT_0
    );
    let mut header = [0; 4];
    service.read_exact(&mut header).unwrap();
    assert_eq!(u32::from_be_bytes(header), 65536);
    let mut payload = vec![0; 65536];
    service.read_exact(&mut payload).unwrap();
    assert_eq!(payload, vec![0x5a; 65536]);
    writer.join().unwrap().unwrap();
}
