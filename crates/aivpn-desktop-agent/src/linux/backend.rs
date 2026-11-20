//! Конкретный writer Linux. Полный DNS gate здесь не заявляется.
pub(super) mod path;
use super::worker_protocol::InterfaceAssignment;
use super::{
    kernel::{KernelWriter, ProfilePath},
    ExecutableFile, MountSnapshot, OwnedTunnel,
};
use crate::{
    control::{ControlState, InstalledState, RoutingBackend},
    state::{StateDirectory, StateFile},
};
use aivpn_desktop_policy::{Authority, Owner, ProfileCatalog, Selector};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
};

pub struct LinuxRoutingBackend {
    writer: KernelWriter,
    paths: path::DataPaths,
    namespace: [u8; 16],
    publication: Option<(u64, u64, u32, [u8; 32])>,
    transports: BTreeMap<String, (super::transport::ValidatedTransport, u64)>,
    transports_refreshed_at: std::time::Instant,
    dns_profile: Option<String>,
    transport_epoch: u64,
    last_failure: Option<String>,
    sweep: super::kernel::CacheSweep,
    swept_at: std::time::Instant,
    dns: Option<super::dns::SystemProvider>,
}
impl LinuxRoutingBackend {
    pub fn open(
        namespace: [u8; 16],
        slots: StateDirectory,
        bindings: StateDirectory,
        resources: StateDirectory,
    ) -> io::Result<Self> {
        let mut writer = if slots.load(StateFile::Committed)?.is_some() {
            KernelWriter::open_existing_snapshot(namespace, slots)?
        } else {
            KernelWriter::install_new_snapshot(namespace, slots)?
        };
        writer.block_profiles()?;
        writer.open_verified_bindings(bindings)?;
        let paths = path::DataPaths::open(namespace, resources)?;
        paths.verify_kernel(&writer)?;
        writer.revoke_all_transport_leases()?;
        Ok(Self {
            writer,
            paths,
            namespace,
            publication: None,
            transports: BTreeMap::new(),
            transports_refreshed_at: std::time::Instant::now(),
            dns_profile: None,
            transport_epoch: 0,
            last_failure: None,
            sweep: Default::default(),
            swept_at: std::time::Instant::now(),
            dns: None,
        })
    }
    pub(crate) fn last_failure(&self) -> Option<&str> {
        self.last_failure.as_deref()
    }
    pub fn publication(&self) -> Option<(u64, u64, u32, [u8; 32])> {
        self.publication
    }
    pub(crate) fn dns_relay_uses_ipv6(&self) -> io::Result<bool> {
        self.dns
            .as_ref()
            .map(super::dns::SystemProvider::relay_uses_ipv6)
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    pub(crate) fn system_dns_epoch(&mut self) -> io::Result<Option<u64>> {
        self.dns
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .epoch()
    }
    /// Применяется только к обычному файлу. Symlink и сетевой менеджер требуют своего адаптера.
    pub fn configure_unmanaged_system_dns(&mut self) -> io::Result<()> {
        use crate::dns::journal::Provider;
        if self.dns.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut provider = super::dns::file::FileProvider::open(Path::new("/etc"), self.namespace)?;
        provider.snapshot()?;
        self.dns = Some(super::dns::SystemProvider::File(provider));
        Ok(())
    }
    pub fn configure_network_manager_system_dns(&mut self) -> io::Result<()> {
        use crate::dns::journal::Provider;
        if self.dns.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut provider = super::dns::nm::NetworkManager::open(self.namespace)?;
        if provider.uses_resolved() {
            // Настройка физического подключения исчезает при смене сети.
            let mut resolved = super::dns::standalone::Resolved::open(self.namespace)?;
            resolved.use_managed_configuration(self.namespace)?;
            resolved.snapshot()?;
            self.dns = Some(super::dns::SystemProvider::Resolved(resolved));
            return Ok(());
        }
        provider.snapshot()?;
        self.dns = Some(super::dns::SystemProvider::NetworkManager(provider));
        Ok(())
    }
    pub fn configure_resolved_system_dns(&mut self) -> io::Result<()> {
        use crate::dns::journal::Provider;
        if self.dns.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut provider = super::dns::standalone::Resolved::open(self.namespace)?;
        match provider.snapshot() {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                provider.use_managed_configuration(self.namespace)?;
                provider.snapshot()?;
            }
            Err(error) => return Err(error),
        }
        self.dns = Some(super::dns::SystemProvider::Resolved(provider));
        Ok(())
    }
    pub fn configure_automatic_system_dns(&mut self) -> io::Result<()> {
        if super::dns::network_manager_manages_dns()? {
            match self.configure_network_manager_system_dns() {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind() == io::ErrorKind::Unsupported
                        && super::dns::resolvconf::Resolvconf::manages_resolv_conf()? =>
                {
                    return self.configure_resolvconf_system_dns();
                }
                Err(error) => return Err(error),
            }
        }
        let path = Path::new("/etc/resolv.conf");
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            let target = std::fs::canonicalize(path)?;
            if [
                Path::new("/run/systemd/resolve/stub-resolv.conf"),
                Path::new("/run/systemd/resolve/resolv.conf"),
                Path::new("/usr/lib/systemd/resolv.conf"),
            ]
            .contains(&target.as_path())
            {
                return self.configure_resolved_system_dns();
            }
            if super::dns::resolvconf::Resolvconf::manages_resolv_conf()? {
                return self.configure_resolvconf_system_dns();
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Не определен менеджер системного DNS",
            ));
        }
        if super::dns::resolvconf::Resolvconf::manages_resolv_conf()? {
            return self.configure_resolvconf_system_dns();
        }
        self.configure_unmanaged_system_dns()
    }
    pub fn configure_resolvconf_system_dns(&mut self) -> io::Result<()> {
        use crate::dns::journal::Provider;
        if self.dns.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut provider = super::dns::resolvconf::Resolvconf::open(self.namespace)?;
        provider.snapshot()?;
        self.dns = Some(super::dns::SystemProvider::Resolvconf(provider));
        Ok(())
    }
    pub(crate) fn begin_path(
        &mut self,
        state: &ControlState,
        profile: &str,
    ) -> io::Result<&OwnedTunnel> {
        let slot = self.writer.profile_slot(state, profile)?;
        self.writer.block_profile(slot)?;
        let matcher = self
            .writer
            .profile_matcher(slot)
            .map_err(|e| io::Error::new(e.kind(), format!("Загрузка matcher профиля: {e}")))?;
        let tunnel = self.paths.begin(&self.writer, profile, slot, matcher)?;
        self.writer.retire_profile_interfaces(slot)?;
        if let Some(provider) = &mut self.dns {
            provider.exclude_owned_tunnel(tunnel.verify()?);
        }
        Ok(tunnel)
    }
    pub(crate) fn tunnel(&self, profile: &str) -> io::Result<&OwnedTunnel> {
        self.paths.get(profile)?.tunnel()
    }
    pub(crate) fn register_transport(
        &mut self,
        profile: &str,
        transport: super::transport::ValidatedTransport,
    ) -> io::Result<()> {
        if self.paths.contains_device(transport.device)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.revoke_transport(profile)?;
        self.transport_epoch = self
            .transport_epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Исчерпана lease транспорта"))?;
        let slot = self.paths.get(profile)?.slot();
        self.writer
            .register_transport(&transport, slot, self.transport_epoch)?;
        self.transports
            .insert(profile.into(), (transport, self.transport_epoch));
        Ok(())
    }
    pub(crate) fn revoke_transport(&mut self, profile: &str) -> io::Result<()> {
        let slot = self.paths.get(profile)?.slot();
        self.writer.revoke_transport_lease(slot)?;
        self.transports.remove(profile);
        if self.dns_profile.as_deref() == Some(profile) {
            self.writer.revoke_dns_epoch()?;
            self.dns_profile = None;
        }
        Ok(())
    }
    pub(crate) fn end_path(&mut self, profile: &str) -> io::Result<()> {
        let slot = self.paths.get(profile)?.slot();
        self.writer.block_profile(slot)?;
        self.paths.end(profile)?;
        self.writer.retire_profile_interfaces(slot)
    }
    pub(crate) fn maintain(&mut self) -> io::Result<()> {
        if self.swept_at.elapsed() >= std::time::Duration::from_millis(250) {
            self.writer.sweep_cache(&mut self.sweep)?;
            self.swept_at = std::time::Instant::now();
        }
        Ok(())
    }
    pub(crate) fn refresh_transport(&mut self) -> io::Result<()> {
        // Регистрация действует 10 секунд. Начальная установка и отзыв выполняются сразу.
        if self.transports_refreshed_at.elapsed() < std::time::Duration::from_millis(250) {
            return Ok(());
        }
        for (profile, (transport, epoch)) in &self.transports {
            self.writer
                .register_transport(transport, self.paths.get(profile)?.slot(), *epoch)?;
        }
        self.transports_refreshed_at = std::time::Instant::now();
        Ok(())
    }
    pub(crate) fn prepare_dns_route(&mut self, profile: &str, epoch: u64) -> io::Result<()> {
        let path = self.paths.get(profile)?;
        path.tunnel()?.verify()?;
        self.writer.publish_dns_epoch(epoch, path.slot())?;
        self.dns_profile = Some(profile.into());
        Ok(())
    }
    pub(crate) fn begin_bootstrap_dns(&mut self, epoch: u64) -> io::Result<()> {
        self.writer.begin_bootstrap_dns(epoch)
    }
    pub(crate) fn end_bootstrap_dns(&mut self) -> io::Result<()> {
        self.writer.end_bootstrap_dns()
    }
    pub(crate) fn register_bootstrap_dns(
        &mut self,
        socket: std::os::fd::OwnedFd,
        peer: std::net::SocketAddr,
        epoch: u64,
    ) -> io::Result<crate::dns::DnsSocketLease> {
        let netns = super::dns::network_namespace()?;
        let device = super::transport::system_device(peer, 0, None)?;
        if self.paths.contains_device(device)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.writer
            .register_bootstrap_dns_socket(&socket, peer, netns, device, epoch)?;
        Ok(crate::dns::DnsSocketLease::new(socket))
    }
    pub(crate) fn protect_system_dns(
        &mut self,
        listeners: Vec<std::os::fd::OwnedFd>,
    ) -> io::Result<Vec<crate::dns::DnsSocketLease>> {
        if listeners.len() > 4 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let netns = super::dns::network_namespace()?;
        if let Some(provider) = &self.dns {
            // Дубликаты закрываются сразу: перезапуск resolved не удерживает старый порт.
            for listener in provider.stub_sockets()? {
                self.writer
                    .register_resolved_dns_listener(&listener, netns)?;
            }
        }
        let mut leases = Vec::new();
        for listener in listeners {
            self.writer.register_dns_listener(&listener, netns)?;
            leases.push(crate::dns::DnsSocketLease::new(listener));
        }
        self.writer.set_system_dns_guard(netns, true)?;
        Ok(leases)
    }
    pub(crate) fn register_dns_socket(
        &mut self,
        socket: std::os::fd::OwnedFd,
        peer: std::net::SocketAddr,
        generation: u64,
        epoch: u64,
    ) -> io::Result<crate::dns::DnsSocketLease> {
        let profile = self
            .dns_profile
            .as_deref()
            .ok_or(io::ErrorKind::NotConnected)?;
        let path = self.paths.get(profile)?;
        let identity = path.tunnel()?.verify()?;
        self.writer.register_dns_socket(
            &socket,
            peer,
            path.slot(),
            generation,
            epoch,
            identity.network_namespace.get(),
        )?;
        Ok(crate::dns::DnsSocketLease::new(socket))
    }
    pub(crate) fn confirm_assignment(
        &mut self,
        profile: &str,
        network: InterfaceAssignment,
    ) -> io::Result<()> {
        let path = self.paths.get_mut(profile)?;
        self.writer.block_profile(path.slot())?;
        path.stage_network(network)
    }
    fn install_target(
        &mut self,
        store: &mut StateDirectory,
        desired: &ControlState,
        live: &ProfileCatalog,
    ) -> io::Result<()> {
        if desired.profiles().namespace() != self.namespace {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if desired.serial() == 0 {
            self.writer.block_profiles()?;
            return Ok(());
        }
        let target = desired.durable_linux_target(store)?;
        self.writer.recover_durable_bindings(&target)?;
        let authority = Authority {
            user: Owner::LinuxUser { uid: 0 },
            machine_admin: true,
        };
        let request = self.writer.selected_executables(
            desired.policies(),
            desired.profiles(),
            &authority,
            desired.serial(),
        )?;
        let paths: BTreeSet<_> = desired
            .policies()
            .policies()
            .flat_map(|p| &p.effective_document().rules)
            .filter_map(|rule| match &rule.application {
                Selector::Executable { path } => Some(path),
                _ => None,
            })
            .collect();
        let mounts = MountSnapshot::read_current()?;
        let files = paths
            .into_iter()
            .map(|path| mounts.locate(ExecutableFile::resolve_selected(Path::new(path))?))
            .collect::<io::Result<_>>()?;
        // Capture core работает до открытия selected executable и его удержания.
        let set = unsafe { self.writer.stage_verified_bindings(&request, files) }?;
        self.paths.verify_kernel(&self.writer)?;
        self.paths.prepare(desired, live, &authority).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Подготовка собственного сетевого пути: {e}"),
            )
        })?;
        let published = self
            .writer
            .publish_durable_bindings(&target, &request, &set)?;
        self.writer.complete_snapshot_installation()?;
        self.paths
            .publish(&mut self.writer, desired, live, &authority)?;
        self.publication = Some((
            published.epoch(),
            published.serial(),
            published.map_id(),
            published.bundle_digest(),
        ));
        drop(target);
        if let Some(provider) = &mut self.dns {
            let mut guard = super::dns::KernelGuard {
                writer: &mut self.writer,
                netns: super::dns::network_namespace()?,
            };
            match desired.dns_scope()? {
                Some(scope) => crate::dns::journal::activate(store, scope, provider, &mut guard)?,
                None => crate::dns::journal::restore(store, self.namespace, provider, &mut guard)?,
            }
        } else if store.load(StateFile::DnsJournal)?.is_some() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok(())
    }
}
impl RoutingBackend<StateDirectory> for LinuxRoutingBackend {
    fn begin_transport_dns(&mut self, epoch: u64) -> io::Result<()> {
        self.begin_bootstrap_dns(epoch)
    }
    fn transport_dns_registrar(
        &mut self,
        epoch: u64,
    ) -> io::Result<crate::dns::BootstrapDnsRegistrar<'_>> {
        let backend = std::sync::Mutex::new(self);
        Ok(Box::new(move |socket, peer| {
            backend
                .lock()
                .map_err(|_| io::Error::other("Служебный DNS прерван"))?
                .register_bootstrap_dns(socket, peer, epoch)
        }))
    }
    fn end_transport_dns(&mut self) -> io::Result<()> {
        self.end_bootstrap_dns()
    }
    fn transport_dns_servers(
        &mut self,
        store: &StateDirectory,
    ) -> io::Result<Vec<std::net::SocketAddr>> {
        let provider = self.dns.as_mut().ok_or(io::ErrorKind::Unsupported)?;
        crate::dns::journal::transport_servers(store, self.namespace, provider)
    }
    fn supported(&self) -> bool {
        true
    }
    fn installed_state(&self) -> InstalledState {
        InstalledState::Guarded
    }
    fn install(
        &mut self,
        store: &mut StateDirectory,
        desired: &ControlState,
        live: &ProfileCatalog,
    ) -> io::Result<()> {
        let result = self.install_target(store, desired, live);
        if let Err(error) = &result {
            self.last_failure = Some(error.to_string());
            let _ = self.writer.block_profiles();
        } else {
            self.last_failure = None;
        }
        result
    }
    fn block(&mut self) -> io::Result<()> {
        self.writer.block_profiles()
    }
}
