//! Приватный byte pipe регистрируется один раз на срок жизни работника.
use aivpn_common::{error::Result, network_config::ClientNetworkConfig};
use std::{io, num::NonZeroU64, sync::Arc};
use tokio::net::windows::named_pipe::NamedPipeClient;
pub type ManagedChannel = super::framed::Channel<NamedPipeClient>;
pub type Reader = super::framed::Reader<NamedPipeClient>;
pub trait ConfirmedAssignment: Send + Sync {
    fn confirmed_assignment(&self, config: &ClientNetworkConfig) -> Result<()>;
}
pub struct ManagedEndpoint {
    pub(super) name: String,
    pub(super) reader: Option<Reader>,
    channel: ManagedChannel,
    generation: NonZeroU64,
    pub(super) assignment: Arc<dyn ConfirmedAssignment>,
    pub(super) last_assignment: Option<ClientNetworkConfig>,
}
impl ManagedEndpoint {
    pub fn new(
        channel: ManagedChannel,
        generation: NonZeroU64,
        name: String,
        assignment: Arc<dyn ConfirmedAssignment>,
    ) -> Self {
        Self {
            name,
            reader: Some(channel.reader(generation)),
            channel,
            generation,
            assignment,
            last_assignment: None,
        }
    }
    pub(super) async fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.channel.write(self.generation, packet).await
    }
}
