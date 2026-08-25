// SPDX-License-Identifier: GPL-2.0
//! aivpn kernel module — entry point (Rust control plane)

#![no_std]

use kernel::prelude::*;

mod dev;

extern "C" {
    fn aivpn_session_table_init() -> i32;
    fn aivpn_session_table_fini();
}

module! {
    type: AivpnModule,
    name: "aivpn",
    authors: ["AIVPN contributors"],
    description: "AIVPN kernel data-plane accelerator (optional, auto-detected)",
    license: "GPL",
    params: {},
}

struct AivpnModule {
    /// `Option` so `Drop` can deregister the misc device (drop the
    /// registration) BEFORE tearing down the session table — plain struct
    /// fields would only drop AFTER the `Drop::drop` body runs.
    dev: Option<Pin<KBox<dev::AivpnDev>>>,
}

impl kernel::Module for AivpnModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        // SAFETY: called once at module load before any ioctl can arrive.
        let ret = unsafe { aivpn_session_table_init() };
        if ret != 0 {
            pr_err!("aivpn: session table init failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }
        let dev = dev::AivpnDev::new()?;
        pr_info!("aivpn: module loaded — /dev/aivpn ready\n");
        Ok(Self { dev: Some(dev) })
    }
}

impl Drop for AivpnModule {
    fn drop(&mut self) {
        // Deregister /dev/aivpn FIRST. The Rust-for-Linux miscdevice vtable
        // does not set file_operations.owner (verified: the fops table is
        // zero-filled apart from open/release/ioctl and carries no
        // __this_module relocation), so nothing pins this module while the
        // device node exists — the ioctl dispatcher must be gone before the
        // session table it dispatches into is torn down. Field drops would
        // otherwise run only AFTER this body, i.e. after fini.
        self.dev = None;
        // SAFETY: called once at module unload, after the misc device above
        // is deregistered, so no new ioctl can reach the session table.
        unsafe { aivpn_session_table_fini() };
        pr_info!("aivpn: module unloaded\n");
    }
}
