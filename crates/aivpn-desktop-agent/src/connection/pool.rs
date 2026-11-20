//! Служба выбирает endpoint прежним алгоритмом и отдельно подтверждает каждый сокет.
use super::parse_endpoint;
use aivpn_common::transport::server_pool::{PoolMode, ServerEntry, ServerPool};
use std::{io, sync::Arc};

#[derive(Clone)]
pub(super) struct Selection {
    pool: Arc<ServerPool<String>>,
    selected: Option<String>,
    connected: bool,
}
impl Selection {
    pub(super) fn from_profile(profile: &serde_json::Value) -> io::Result<Option<Self>> {
        let Some(value) = profile.get("pool").filter(|v| !v.is_null()) else {
            return Ok(None);
        };
        let peers: Vec<ServerEntry> = serde_json::from_value(value.clone()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Некорректный пул серверов")
        })?;
        if peers.len() > 31 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for peer in &peers {
            parse_endpoint(&peer.endpoint)?;
        }
        if peers.is_empty() {
            return Ok(None);
        }
        let primary = profile["s"].as_str().ok_or(io::ErrorKind::InvalidInput)?;
        Ok(Some(Self {
            pool: ServerPool::from_endpoints(primary, peers, PoolMode::Failover),
            selected: None,
            connected: false,
        }))
    }
    pub(super) fn next(&mut self, excluded: &[String]) -> io::Result<String> {
        let endpoint = self
            .pool
            .next_server_excluding(excluded)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.selected = Some(endpoint.clone());
        self.connected = false;
        Ok(endpoint)
    }
    pub(super) fn connected(&mut self) {
        if let Some(endpoint) = &self.selected {
            self.pool.report_success(endpoint.clone());
        }
        self.connected = true;
    }
    pub(super) fn finish(&mut self) {
        if !self.connected {
            if let Some(endpoint) = self.selected.take() {
                self.pool.report_failure(endpoint);
            }
        }
        self.connected = false;
    }
}
