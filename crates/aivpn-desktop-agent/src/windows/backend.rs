//! Установка политики через общий Control. До DNS gate публикуется только Guarded.
use super::{
    api::denied,
    driver::{DriverSession, PacketChannelConfig, ProfilePacket, ProfileRoute},
    filters,
    worker::{SharedTransport, WorkerProcess},
};
use crate::{
    bindings::BindingPlan,
    control::{ControlState, InstalledState, RoutingBackend},
    slots::{KernelSlotStore, KernelState},
    state::{StateDirectory, StateFile},
    worker_protocol::InterfaceAssignment,
};
use aivpn_desktop_policy::{Authority, KernelPolicy, Owner, ProfileCatalog, Selector};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::*},
    System::Threading::*,
};

struct ProfilePath {
    slot: NonZeroU32,
    generation: u64,
    network: Option<InterfaceAssignment>,
    transport: Option<SharedTransport>,
}
impl ProfilePath {
    fn route(&self) -> io::Result<ProfileRoute> {
        ProfileRoute::new(self.slot.get(), self.generation)
    }
}

pub struct WindowsRoutingBackend {
    driver: DriverSession,
    slots: KernelSlotStore<StateDirectory>,
    namespace: [u8; 16],
    event: OwnedHandle,
    interface: u32,
    luid: u64,
    compartment: u32,
    epoch: u64,
    publication: Option<(u64, u64)>,
    paths: BTreeMap<String, ProfilePath>,
    dns_target: Option<String>,
    last_failure: Option<String>,
    filters: Option<filters::Installation>,
    binding_receipts: std::collections::BTreeSet<(u32, u32, u32, u32, u64)>,
    dns: Option<super::dns::InterfaceDns>,
    dns_epoch: u64,
    provenance: Option<super::ProvenanceVolume>,
}
fn owned(raw: windows_sys::Win32::Foundation::HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn system() -> Authority {
    Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    }
}

impl WindowsRoutingBackend {
    pub fn open(namespace: [u8; 16], slots: StateDirectory, interface: u32) -> io::Result<Self> {
        super::security::service_authority()?;
        let mut driver = DriverSession::open()?;
        driver.block_packet_channel()?;
        let mode = if slots.load(StateFile::Committed)?.is_some() {
            KernelState::Existing
        } else {
            KernelState::Fresh
        };
        let slots = KernelSlotStore::open(slots, namespace, mode)?;
        let event = owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut luid = NET_LUID_LH::default();
        let status = unsafe { ConvertInterfaceIndexToLuid(interface, &mut luid) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let result = Self {
            driver,
            slots,
            namespace,
            event,
            interface,
            luid: unsafe { luid.Value },
            compartment: unsafe { GetCurrentThreadCompartmentId() },
            epoch: 0,
            publication: None,
            paths: BTreeMap::new(),
            dns_target: None,
            last_failure: None,
            filters: None,
            binding_receipts: Default::default(),
            dns: None,
            dns_epoch: 0,
            provenance: None,
        };
        result.verify_interface_identity()?;
        Ok(result)
    }
    pub fn open_for_guid(
        namespace: [u8; 16],
        slots: StateDirectory,
        guid: &windows_sys::core::GUID,
    ) -> io::Result<Self> {
        super::security::service_authority()?;
        let mut luid = NET_LUID_LH::default();
        let status = unsafe { ConvertInterfaceGuidToLuid(guid, &mut luid) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut index = 0;
        let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let backend = Self::open(namespace, slots, index)?;
        if backend.luid != unsafe { luid.Value } {
            return Err(denied());
        }
        Ok(backend)
    }
    pub fn configure_provenance(&mut self, provenance: super::ProvenanceVolume) -> io::Result<()> {
        if self.provenance.is_some() || self.publication.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        provenance.verify()?;
        self.provenance = Some(provenance);
        Ok(())
    }
    // Отключение линка не меняет владельца адаптера и не мешает сохранять guard.
    fn verify_interface_identity(&self) -> io::Result<()> {
        let mut row = MIB_IF_ROW2::default();
        row.InterfaceIndex = self.interface;
        let status = unsafe { GetIfEntry2(&mut row) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if unsafe { row.InterfaceLuid.Value } != self.luid
            || unsafe { GetCurrentThreadCompartmentId() } != self.compartment
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Диагностика не публикует PI_RECORD, но может впервые claim provenance
    /// и обновить отрицательные наблюдения общего origin.
    pub(crate) fn diagnose_process(
        &mut self,
        process: &OwnedHandle,
        destination: std::net::IpAddr,
    ) -> io::Result<super::driver::IdentityDiagnostic> {
        self.driver.diagnose(process, destination)
    }
    #[cfg(feature = "windows-lab")]
    pub(crate) fn lab_injection_barrier(
        &self,
        started: &std::os::windows::io::OwnedHandle,
        release: &std::os::windows::io::OwnedHandle,
    ) -> io::Result<()> {
        self.driver.lab_injection_barrier(started, release)
    }
    pub(crate) fn packet_statistics(&self) -> io::Result<super::driver::PacketStatistics> {
        self.driver.packet_statistics()
    }
    #[cfg(feature = "windows-lab")]
    pub(crate) fn lab_counters(&self) -> io::Result<Vec<u32>> {
        self.driver.lab_counters()
    }
    pub fn publication(&self) -> Option<(u64, u64)> {
        self.publication
    }
    pub fn sublayer_weight(&self) -> Option<u16> {
        self.filters.map(|value| value.sublayer_weight)
    }
    pub fn transport_receipt(&self) -> io::Result<Option<super::driver::TransportReceipt>> {
        let mut paths = self.paths.iter().filter(|(_, path)| path.generation != 0);
        let Some((profile, _)) = paths.next() else {
            return Ok(None);
        };
        if paths.next().is_some() {
            return Ok(None);
        }
        self.profile_transport_receipt(profile)
    }
    pub(crate) fn profile_transport_receipt(
        &self,
        profile: &str,
    ) -> io::Result<Option<super::driver::TransportReceipt>> {
        let Some(path) = self.paths.get(profile).filter(|path| path.generation != 0) else {
            return Ok(None);
        };
        let receipt = self.driver.profile_transport_receipt(path.slot)?;
        if receipt.generation != path.generation {
            return Err(denied());
        }
        Ok(Some(receipt))
    }
    pub(crate) fn last_failure(&self) -> Option<&str> {
        self.last_failure.as_deref()
    }
    pub fn configure_system_dns(&mut self) -> io::Result<()> {
        use crate::dns::journal::Provider;
        if self.dns.is_some() || self.publication.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut provider = super::dns::InterfaceDns;
        provider.snapshot()?;
        self.dns = Some(provider);
        Ok(())
    }
    pub(crate) fn protect_system_dns(
        &mut self,
        listeners: Vec<std::os::windows::io::OwnedSocket>,
    ) -> io::Result<Vec<crate::dns::DnsSocketLease>> {
        if self.dns.is_none() || listeners.is_empty() || listeners.len() > 4 {
            return Err(denied());
        }
        let endpoints = listeners
            .iter()
            .map(|socket| super::driver::inspect_dns_socket(socket, true, None))
            .collect::<io::Result<Vec<_>>>()?;
        self.driver.dns_guard(self.compartment, true)?;
        for endpoint in &endpoints {
            self.driver.dns_endpoint(
                self.compartment,
                0,
                0,
                0,
                endpoint,
                endpoint.local.ok_or_else(denied)?,
                true,
            )?;
        }
        Ok(listeners
            .into_iter()
            .map(crate::dns::DnsSocketLease::new)
            .collect())
    }
    pub(crate) fn prepare_dns_route(&mut self, profile: &str, epoch: u64) -> io::Result<()> {
        let path = self.paths.get(profile).ok_or_else(denied)?;
        if self.dns.is_none()
            || path.network.is_none()
            || path.transport.is_none()
            || epoch <= self.dns_epoch
        {
            return Err(denied());
        }
        self.verify_interface_identity()?;
        self.driver
            .dns_route(self.compartment, path.slot.get(), path.generation, epoch)?;
        self.dns_epoch = epoch;
        self.dns_target = Some(profile.into());
        Ok(())
    }
    pub(crate) fn register_dns_socket(
        &mut self,
        socket: std::os::windows::io::OwnedSocket,
        peer: SocketAddr,
        epoch: u64,
    ) -> io::Result<crate::dns::DnsSocketLease> {
        let path = self
            .dns_target
            .as_ref()
            .and_then(|profile| self.paths.get(profile))
            .ok_or_else(denied)?;
        if self.dns.is_none()
            || path.network.is_none()
            || path.transport.is_none()
            || self.dns_epoch != epoch
        {
            return Err(denied());
        }
        let endpoint = super::driver::inspect_dns_socket(&socket, false, Some(peer.is_ipv4()))?;
        self.driver.dns_endpoint(
            self.compartment,
            path.slot.get(),
            path.generation,
            epoch,
            &endpoint,
            peer,
            false,
        )?;
        Ok(crate::dns::DnsSocketLease::new(socket))
    }

    pub(crate) fn binding_receipts(&self) -> serde_json::Value {
        serde_json::Value::Array(self.binding_receipts.iter().map(|&(kind, owner, selector, group, claim)|
            serde_json::json!({"owner_kind":kind,"owner":owner,"selector":selector,"group":group,"claim":claim})).collect())
    }
    pub(crate) fn begin_path(&mut self, state: &ControlState, profile: &str) -> io::Result<()> {
        let plan = BindingPlan::prepare_with(
            state.policies(),
            state.profiles(),
            &system(),
            &mut self.slots,
            true,
        )?;
        let slot = *plan.bindings().profiles.get(profile).ok_or_else(denied)?;
        if let Some(path) = self.paths.get(profile) {
            if path.slot != slot {
                return Err(denied());
            }
            self.revoke_transport(profile)?;
        } else {
            self.paths.insert(
                profile.into(),
                ProfilePath {
                    slot,
                    generation: 0,
                    network: None,
                    transport: None,
                },
            );
        }
        Ok(())
    }
    pub(crate) fn register_worker(
        &mut self,
        profile: &str,
        worker: &WorkerProcess,
        generation: u64,
    ) -> io::Result<()> {
        worker.verify().map_err(|error| {
            io::Error::new(error.kind(), format!("Проверка работника: {error}"))
        })?;
        filters::ensure_worker(worker.image_path())?;
        self.revoke_transport(profile)?;
        let path = self.paths.get_mut(profile).ok_or_else(denied)?;
        self.driver.register_profile_worker(
            path.slot,
            generation,
            worker.process(),
            worker.image(),
        )?;
        path.generation = generation;
        Ok(())
    }
    pub(crate) fn register_transport(
        &mut self,
        profile: &str,
        transport: SharedTransport,
        peer: SocketAddr,
    ) -> io::Result<()> {
        let path = self.paths.get_mut(profile).ok_or_else(denied)?;
        if path.transport.is_some() {
            return Err(denied());
        }
        self.driver
            .register_profile_transport(path.route()?, &transport, peer)?;
        path.transport = Some(transport);
        Ok(())
    }
    pub(crate) fn revoke_transport(&mut self, profile: &str) -> io::Result<()> {
        if let Some(path) = self.paths.get_mut(profile) {
            if path.generation != 0 {
                self.driver.block_profile_channel(path.route()?)?;
                self.driver.revoke_profile_transport(path.route()?)?;
            }
            path.transport = None;
            path.network = None;
        }
        if self.dns_target.as_deref() == Some(profile) {
            self.dns_target = None;
        }
        Ok(())
    }
    pub(crate) fn confirm_assignment(
        &mut self,
        profile: &str,
        network: InterfaceAssignment,
    ) -> io::Result<u64> {
        network.validate()?;
        let path = self.paths.get(profile).ok_or_else(denied)?;
        if path.transport.is_none()
            || network.prefix_len > 32
            || !(1280..=PacketChannelConfig::MAX_MTU).contains(&network.mtu)
            || network.mdh_len > network.mtu
            || network.client_ip.is_unspecified()
            || network.client_ip.is_loopback()
            || network.client_ip.is_multicast()
            || network.server_vpn_ip.is_unspecified()
            || network.client_ip == network.server_vpn_ip
        {
            return Err(denied());
        }
        let receipt = self
            .profile_transport_receipt(profile)?
            .ok_or_else(denied)?;
        if receipt.observed_owner.is_none()
            || path.transport.as_ref().map(|value| value.endpoint()) != Some(receipt.endpoint)
        {
            return Err(denied());
        }
        self.verify_interface_identity()?;
        self.driver.block_profile_channel(path.route()?)?;
        self.paths.get_mut(profile).ok_or_else(denied)?.network = Some(network);
        Ok(self.driver.channel_id())
    }
    pub(crate) fn receive_packet(&mut self, bytes: &mut [u8]) -> io::Result<Option<ProfilePacket>> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        match unsafe { WaitForSingleObject(self.event.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.driver.receive_profile_packet(bytes),
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub(crate) fn packet_event(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.event.as_raw_handle()
    }
    pub(crate) fn send_packet(&mut self, profile: &str, bytes: &mut [u8]) -> io::Result<()> {
        let route = self.paths.get(profile).ok_or_else(denied)?.route()?;
        self.driver.send_profile_packet(route, bytes)
    }
    pub(crate) fn packet_profile(&self, route: ProfileRoute) -> Option<&str> {
        self.paths
            .iter()
            .find(|(_, path)| {
                path.slot == route.profile && path.generation == route.generation.get()
            })
            .map(|(profile, _)| profile.as_str())
    }

    fn install_target(
        &mut self,
        store: &mut StateDirectory,
        desired: &ControlState,
        live: &ProfileCatalog,
    ) -> io::Result<()> {
        if let Some(provenance) = &self.provenance {
            provenance.verify()?;
        }
        if desired.profiles().namespace() != self.namespace {
            return Err(denied());
        }
        let policies = desired.policies().policies().collect::<Vec<_>>();
        if desired.serial() == 0 {
            self.driver.block_packet_channel()?;
            return Ok(());
        }
        let authority = system();
        let plan = BindingPlan::prepare_with(
            desired.policies(),
            desired.profiles(),
            &authority,
            &mut self.slots,
            true,
        )?;
        let transaction =
            self.driver
                .begin_runtime(self.namespace, desired.serial(), policies.len())?;
        let mut receipts = Vec::new();
        for (sid, slot) in &plan.bindings().windows_owners {
            self.driver.runtime_sid(transaction, 2, slot.get(), sid)?;
        }
        for (sid, slot) in &plan.bindings().packages {
            self.driver.runtime_sid(transaction, 3, slot.get(), sid)?;
        }
        for policy in &policies {
            let document = policy.document();
            let bytes = KernelPolicy::compile_registered(
                desired.policies(),
                &document.owner,
                desired.profiles(),
                &authority,
                plan.bindings(),
            )
            .map_err(io::Error::other)?
            .to_native_bytes();
            let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(document)?).into();
            let carried = self.driver.runtime_policy(transaction, &bytes, digest)?;
            if !carried {
                let (kind, owner) = match &document.owner {
                    Owner::Machine {} => (3, 0),
                    Owner::WindowsUser { sid } => (
                        2,
                        plan.bindings()
                            .windows_owners
                            .get(sid)
                            .ok_or_else(denied)?
                            .get(),
                    ),
                    _ => return Err(denied()),
                };
                let paths = policy
                    .effective_document()
                    .rules
                    .iter()
                    .filter_map(|rule| match &rule.application {
                        Selector::Executable { path } => Some(path),
                        _ => None,
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                for path in paths {
                    let selector = plan
                        .bindings()
                        .executables
                        .get(path)
                        .ok_or_else(denied)?
                        .get();
                    let (group, claim) = self
                        .driver
                        .runtime_claim(transaction, kind, owner, selector, path)
                        .map_err(|e| {
                            io::Error::new(e.kind(), format!("Проверка runtime file claim: {e}"))
                        })?;
                    receipts.push((kind, owner, selector, group, claim));
                }
            }
        }
        self.driver.seal_runtime(transaction)?;
        self.epoch = transaction.epoch;
        let target_profiles: BTreeMap<_, _> = desired
            .profiles()
            .runtime_profiles(&authority)
            .map_err(io::Error::other)?
            .into_iter()
            .map(|profile| (profile.id.clone(), profile))
            .collect();
        let live_profiles: BTreeMap<_, _> = live
            .runtime_profiles(&authority)
            .map_err(io::Error::other)?
            .into_iter()
            .map(|profile| (profile.id.clone(), profile))
            .collect();
        let removed: Vec<_> = self
            .paths
            .keys()
            .filter(|profile| !target_profiles.contains_key(*profile))
            .cloned()
            .collect();
        for profile in removed {
            self.revoke_transport(&profile)?;
            self.paths.remove(&profile);
        }
        let mut publications = Vec::new();
        for (profile, path) in &self.paths {
            if plan.bindings().profiles.get(profile) != Some(&path.slot) {
                return Err(denied());
            }
            let target = target_profiles.get(profile).ok_or_else(denied)?;
            let current = live_profiles.get(profile).ok_or_else(denied)?;
            let mut ready = false;
            if let (Some(network), Some(assignment)) = (path.network, target.assignment) {
                let exact = assignment.interface_id == self.driver.channel_id()
                    && assignment.ipv4 == network.client_ip
                    && assignment.ipv6 == network.ipv6.map(|network| network.address);
                if !exact
                    && (current.ready_ipv4
                        || target.assignment != current.assignment
                        || target.assignment_generation != current.assignment_generation)
                {
                    return Err(denied());
                }
                ready = exact
                    && current.ready_ipv4
                    && current.ready_ipv6 == network.ipv6.is_some()
                    && target.assignment == current.assignment
                    && path.transport.is_some();
            }
            if !ready && path.generation != 0 {
                self.driver.block_profile_channel(path.route()?)?;
            }
            publications.push((path.slot.get(), path.network, ready));
        }
        self.verify_interface_identity()?;
        // Общий снимок публикуется отдельно от ready конкретных профилей.
        self.driver.publish_runtime_channel(
            PacketChannelConfig {
                interface_index: self.interface,
                compartment: self.compartment,
                mtu: 1280,
                address: Ipv4Addr::UNSPECIFIED,
                ipv6: None,
            },
            &self.event,
            false,
            0,
        )?;
        self.filters = Some(
            filters::ensure_system(self.filters)
                .map_err(|e| io::Error::new(e.kind(), format!("Установка WFP: {e}")))?,
        );
        for policy in &policies {
            filters::ensure_owner(self.namespace, &policy.document().owner)?;
        }
        if let Some(provider) = &mut self.dns {
            let mut guard = super::dns::KernelGuard {
                driver: &self.driver,
                compartment: self.compartment,
            };
            match desired.dns_scope()? {
                Some(scope) => crate::dns::journal::activate(store, scope, provider, &mut guard)?,
                None => crate::dns::journal::restore(store, self.namespace, provider, &mut guard)?,
            }
        } else if desired.dns_scope()?.is_some() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        for (profile, network, ready) in publications {
            self.driver.publish_runtime_channel(
                PacketChannelConfig {
                    interface_index: self.interface,
                    compartment: self.compartment,
                    mtu: network.map_or(1280, |network| network.mtu),
                    address: network.map_or(Ipv4Addr::UNSPECIFIED, |network| network.client_ip),
                    ipv6: network.and_then(|network| network.ipv6.map(|network| network.address)),
                },
                &self.event,
                ready,
                profile,
            )?;
        }
        self.publication = Some((desired.serial(), self.epoch));
        self.binding_receipts.extend(receipts);
        Ok(())
    }
}
impl RoutingBackend<StateDirectory> for WindowsRoutingBackend {
    fn begin_transport_dns(&mut self, epoch: u64) -> io::Result<()> {
        self.verify_interface_identity()?;
        self.driver.begin_bootstrap_dns(self.compartment, epoch)
    }
    fn transport_dns_registrar(
        &mut self,
        epoch: u64,
    ) -> io::Result<crate::dns::BootstrapDnsRegistrar<'_>> {
        let driver = &self.driver;
        let compartment = self.compartment;
        Ok(Box::new(move |socket, peer| {
            crate::dns::journal::validate_bootstrap_servers(&[peer])?;
            let endpoint = super::driver::inspect_dns_socket(&socket, false, Some(peer.is_ipv4()))?;
            driver.bootstrap_dns_endpoint(compartment, epoch, &endpoint, peer)?;
            Ok(crate::dns::DnsSocketLease::new(socket))
        }))
    }
    fn end_transport_dns(&mut self) -> io::Result<()> {
        self.driver.end_bootstrap_dns(self.compartment)
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
        self.last_failure = result.as_ref().err().map(ToString::to_string);
        if result.is_err() {
            let _ = self.driver.block_packet_channel();
        }
        result
    }
    fn block(&mut self) -> io::Result<()> {
        self.driver.block_packet_channel()
    }
}
