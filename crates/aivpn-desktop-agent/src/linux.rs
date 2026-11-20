//! Ресурсы Linux-службы. Имена и дескрипторы интерфейсов создает сама служба.

mod command;
pub use command::system_network_command;

mod tunnel;
pub use tunnel::{InterfaceIdentity, OwnedTunnel};
mod executable;
pub use executable::ExecutableFile;
mod filesystem;
pub use filesystem::{LocatedExecutable, MountSnapshot};

mod worker;
pub mod worker_protocol;
pub use worker::{administration_stream, initialize_packet_worker, restrict_packet_worker};

#[cfg(feature = "linux-kernel")]
mod backend;
#[cfg(feature = "linux-kernel")]
pub mod kernel;
#[cfg(feature = "linux-kernel")]
pub use backend::LinuxRoutingBackend;
#[cfg(feature = "linux-kernel")]
mod coordinator;
#[cfg(feature = "linux-kernel")]
pub use coordinator::{LinuxCoordinator, WorkerConfiguration, WorkerProgress};
#[cfg(feature = "linux-kernel")]
pub(crate) mod dns;
#[cfg(feature = "linux-kernel")]
mod transport;
