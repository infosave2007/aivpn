//! CLI management-command handlers, grouped by domain. `main.rs`'s dispatch
//! chain in `main()` calls into these after clap parses `ServerArgs` — the
//! dispatch structure itself (flat `if let Some(...)`/`if ... { return; }`
//! chain) is unchanged; only the handler bodies moved here.

pub(crate) mod backup;
pub(crate) mod cert;
pub(crate) mod client;
pub(crate) mod mask;
pub(crate) mod node;
