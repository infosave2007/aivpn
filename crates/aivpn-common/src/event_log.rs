//! Structured event logging — shared event types for server and client.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AivpnEvent {
    Connection {
        client_id: String,
        vpn_ip: String,
        action: ConnectionAction,
        server_node: Option<String>,
    },
    MaskRotation {
        old_mask: String,
        new_mask: String,
        reason: RotationReason,
    },
    KillSwitch {
        action: KillSwitchAction,
        platform: String,
    },
    Anomaly {
        mse: f32,
        threshold: f32,
        mask_id: String,
    },
    XdpDrop {
        reason: XdpDropReason,
        count: u64,
    },
    PeerSync {
        peer: String,
        action: PeerSyncAction,
        clients_synced: u32,
    },
    Bench {
        latency_p50_ms: f64,
        latency_p95_ms: f64,
        throughput_up_mbps: f64,
        throughput_down_mbps: f64,
        packet_loss_pct: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionAction {
    Connect,
    Disconnect,
    Failover {
        from_server: String,
        to_server: String,
    },
    Reconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Neural,
    Manual,
    Scheduled,
    PeerSync,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchAction {
    Enabled,
    Disabled,
    Cleared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpDropReason {
    TooShort,
    WindowExpired,
    Malformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerSyncAction {
    Connected,
    Disconnected,
    FullSync,
    Delta,
}

/// Wrapper carrying an event with a UTC timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedEvent {
    pub ts: DateTime<Utc>,
    #[serde(flatten)]
    pub event: AivpnEvent,
}

/// Sink configuration parsed from environment.
#[derive(Debug, Clone)]
pub struct EventSinkConfig {
    pub stdout: bool,
    pub webhook_url: Option<String>,
}

impl Default for EventSinkConfig {
    fn default() -> Self {
        Self {
            stdout: true,
            webhook_url: None,
        }
    }
}

impl EventSinkConfig {
    pub fn from_env() -> Self {
        Self {
            stdout: true,
            webhook_url: std::env::var("AIVPN_EVENT_WEBHOOK").ok(),
        }
    }
}

/// Thread-safe event bus.  Clone-cheap (Arc inside).
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

/// Optional downstream sink for serialized (JSON-lines) events. The common
/// crate deliberately stays transport-agnostic — the HTTP/webhook delivery
/// itself lives in `aivpn-server` (which owns an HTTP client); it installs a
/// closure here via [`EventBus::set_event_sink`].
pub type EventSink = Arc<dyn Fn(&str) + Send + Sync>;

struct EventBusInner {
    stdout: bool,
    stdout_lock: Mutex<()>,
    /// The configured `AIVPN_EVENT_WEBHOOK` URL, if any. The bus itself does
    /// not POST — it only advertises the URL so the embedding binary can wire
    /// a sink (see [`EventBus::set_event_sink`]); without an installed sink
    /// the URL has no effect.
    webhook_url: Option<String>,
    sink: Mutex<Option<EventSink>>,
}

impl EventBus {
    pub fn new(cfg: EventSinkConfig) -> Self {
        Self {
            inner: Arc::new(EventBusInner {
                stdout: cfg.stdout,
                stdout_lock: Mutex::new(()),
                webhook_url: cfg.webhook_url,
                sink: Mutex::new(None),
            }),
        }
    }

    pub fn disabled() -> Self {
        Self::new(EventSinkConfig {
            stdout: false,
            webhook_url: None,
        })
    }

    /// The configured webhook URL (`AIVPN_EVENT_WEBHOOK`), if any.
    pub fn webhook_url(&self) -> Option<&str> {
        self.inner.webhook_url.as_deref()
    }

    /// Install the downstream sink invoked with each serialized event line
    /// (JSON). Called once at startup by the embedding binary (the server
    /// uses it to forward events to the configured webhook). Replacing an
    /// existing sink is allowed but not expected.
    pub fn set_event_sink(&self, sink: EventSink) {
        *self.inner.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    }

    pub fn emit(&self, event: AivpnEvent) {
        let sink = self
            .inner
            .sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !self.inner.stdout && sink.is_none() {
            return;
        }
        let logged = LoggedEvent {
            ts: Utc::now(),
            event,
        };
        if let Ok(line) = serde_json::to_string(&logged) {
            if self.inner.stdout {
                let _guard = self.inner.stdout_lock.lock();
                let _ = writeln!(std::io::stdout(), "{}", line);
            }
            if let Some(sink) = sink {
                sink(&line);
            }
        }
    }
}
