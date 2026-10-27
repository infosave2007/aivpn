//! Управление текущей сессией через локальные TCP и UDP.

use crate::record_cmd::{self, AdminCommand};
use aivpn_common::{local_admin::MAX_FRAME, mgmt::MgmtClient, ControlPayload};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

async fn command(
    raw: &str,
    token: &str,
    mgmt: &MgmtClient,
    control: &mpsc::Sender<ControlPayload>,
    recording: &mpsc::Sender<String>,
) -> Option<String> {
    let (candidate, rest) = raw.split_once(':')?;
    if !record_cmd::tokens_match(candidate, token) {
        return None;
    }
    match record_cmd::parse_admin_command(rest)? {
        AdminCommand::RecordStart(_) | AdminCommand::RecordStop | AdminCommand::RecordStatus => {
            recording.send(rest.to_string()).await.ok()?;
            Some("ok".into())
        }
        AdminCommand::Role => Some(mgmt.cached_role().to_string()),
        AdminCommand::Qr(text) => crate::qr::png_for(&text)
            .ok()
            .map(|png| record_cmd::encode_body_b64(&png)),
        AdminCommand::Bench(seconds) => {
            let result = aivpn_common::diagnostics::run(
                mgmt.clone(),
                control.clone(),
                Duration::from_secs(seconds),
            )
            .await;
            Some(
                match result {
                    Ok(result) => serde_json::to_value(result).unwrap_or_default(),
                    Err(error) => serde_json::json!({"error":error.to_string()}),
                }
                .to_string(),
            )
        }
        AdminCommand::Mgmt { method, path, body } => Some(
            match mgmt
                .mgmt_call(control, method, &path, body, Duration::from_secs(10))
                .await
            {
                Ok((status, body)) => record_cmd::format_mgmt_reply(status, &body),
                Err(error) => {
                    tracing::warn!("Admin management request failed: {error}");
                    record_cmd::format_mgmt_reply(0, &[])
                }
            },
        ),
    }
}

async fn read_request(socket: &mut TcpStream) -> io::Result<String> {
    let len = socket.read_u32().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::other("Invalid admin request size"));
    }
    let mut bytes = vec![0; len];
    socket.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| io::Error::other("Invalid admin request encoding"))
}

pub async fn serve(
    udp: UdpSocket,
    tcp: TcpListener,
    token: String,
    mgmt: MgmtClient,
    control: mpsc::Sender<ControlPayload>,
    recording: mpsc::Sender<String>,
) {
    let udp = std::sync::Arc::new(udp);
    let mut jobs = tokio::task::JoinSet::new();
    let mut buffer = [0; 65536];
    loop {
        tokio::select! {
            Some(_) = jobs.join_next(), if !jobs.is_empty() => {},
            accepted = tcp.accept() => {
                let Ok((mut socket, _)) = accepted else { break; };
                if jobs.len() >= 32 { continue; }
                let (token, mgmt, control, recording) = (token.clone(), mgmt.clone(), control.clone(), recording.clone());
                jobs.spawn(async move {
                    let Ok(Ok(raw)) = tokio::time::timeout(Duration::from_secs(5), read_request(&mut socket)).await else { return; };
                    let Some(reply) = command(&raw, &token, &mgmt, &control, &recording).await else { return; };
                    if reply.is_empty() || reply.len() > MAX_FRAME { return; }
                    let _ = tokio::time::timeout(Duration::from_secs(5), async {
                        socket.write_u32(reply.len() as u32).await?;
                        socket.write_all(reply.as_bytes()).await
                    }).await;
                });
            },
            received = udp.recv_from(&mut buffer) => {
                let Ok((len, peer)) = received else { break; };
                if jobs.len() >= 32 { continue; }
                let Ok(raw) = std::str::from_utf8(&buffer[..len]) else { continue; };
                let (raw, token, mgmt, control, recording, udp) = (raw.to_string(), token.clone(), mgmt.clone(), control.clone(), recording.clone(), udp.clone());
                jobs.spawn(async move {
                    if let Some(reply) = command(&raw, &token, &mgmt, &control, &recording).await {
                        if reply.len() <= 65507 { let _ = udp.send_to(reply.as_bytes(), peer).await; }
                        else { let _ = udp.send_to(b"0:", peer).await; }
                    }
                });
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn tcp_auth_large_request_and_recording_share_the_live_dispatcher() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(addr) = tcp.local_addr().unwrap() else {
            unreachable!()
        };
        let udp = UdpSocket::bind(addr).await.unwrap();
        let token = "a".repeat(64);
        let (control, mut control_rx) = mpsc::channel(8);
        let (record, mut record_rx) = mpsc::channel(8);
        let mgmt = MgmtClient::new();
        let task = tokio::spawn(serve(
            udp,
            tcp,
            token.clone(),
            mgmt.clone(),
            control,
            record,
        ));
        let line = format!("{token}:record_start:fixture");
        let query = tokio::task::spawn_blocking(move || {
            aivpn_common::local_admin::request(addr, &line, Duration::from_secs(5))
        });
        assert_eq!(record_rx.recv().await.unwrap(), "record_start:fixture");
        assert_eq!(query.await.unwrap().unwrap(), "ok");
        let line = format!(
            "{token}:mgmt:1:/api/v1/fixture:{}",
            record_cmd::encode_body_b64(&vec![7; aivpn_common::protocol::MAX_MGMT_BODY_SIZE])
        );
        let query = tokio::task::spawn_blocking(move || {
            aivpn_common::local_admin::request(addr, &line, Duration::from_secs(5))
        });
        let ControlPayload::MgmtRequest { req_id, body, .. } = control_rx.recv().await.unwrap()
        else {
            unreachable!()
        };
        assert_eq!(body, vec![7; aivpn_common::protocol::MAX_MGMT_BODY_SIZE]);
        mgmt.on_mgmt_response(
            req_id,
            200,
            vec![9; aivpn_common::protocol::MAX_MGMT_BODY_SIZE],
        );
        assert_eq!(
            record_cmd::parse_mgmt_reply(&query.await.unwrap().unwrap()),
            Some((200, vec![9; aivpn_common::protocol::MAX_MGMT_BODY_SIZE]))
        );
        let rejected = tokio::task::spawn_blocking(move || {
            aivpn_common::local_admin::request(addr, "wrong:role", Duration::from_secs(5))
        })
        .await
        .unwrap();
        assert!(rejected.is_err());
        assert!(record_rx.try_recv().is_err());
        assert!(control_rx.try_recv().is_err());
        task.abort();
    }
}
