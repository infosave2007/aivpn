use crate::{Policy, ProcessIdentity, Selector};
use std::net::IpAddr;

fn network_matches(policy: &Policy, index: usize, destination: IpAddr) -> bool {
    policy.networks[index]
        .as_ref()
        .is_none_or(|network| network.contains(destination))
}

fn application_matches(selector: &Selector, process: &ProcessIdentity) -> bool {
    match selector {
        Selector::Any {} => false,
        Selector::Executable { path } => path == &process.canonical_executable,
        Selector::WindowsPackage { sid } => process.package_sid.as_ref() == Some(sid),
    }
}

pub(crate) fn unresolved_identity(
    policy: &Policy,
    process: &ProcessIdentity,
    destination: IpAddr,
) -> bool {
    if !process.canonical_executable.is_empty() || process.package_sid.is_some() {
        return false;
    }
    requires_identity(policy, destination, false)
}

fn requires_identity(policy: &Policy, destination: IpAddr, inherited: bool) -> bool {
    for (index, rule) in policy.effective_document.rules.iter().enumerate() {
        if !network_matches(policy, index, destination) {
            continue;
        }
        if rule.application == (Selector::Any {}) {
            return false;
        }
        if !inherited || rule.inherit_children {
            return true;
        }
    }
    false
}

fn origin_matches(
    policy: &Policy,
    origin: &ProcessIdentity,
    depth: usize,
    destination: IpAddr,
) -> bool {
    policy
        .effective_document
        .rules
        .iter()
        .enumerate()
        .any(|(index, rule)| {
            (depth == 0 || rule.inherit_children)
                && application_matches(&rule.application, origin)
                && network_matches(policy, index, destination)
        })
}

fn nearest_origin<'a>(
    policy: &Policy,
    process: &'a ProcessIdentity,
    ancestors: &'a [ProcessIdentity],
    destination: IpAddr,
) -> Result<Option<(usize, &'a ProcessIdentity)>, ()> {
    if origin_matches(policy, process, 0, destination) {
        return Ok(Some((0, process)));
    }
    let inheritance_matters = requires_identity(policy, destination, true);
    for (index, origin) in ancestors
        .iter()
        .take_while(|parent| parent.owner == process.owner)
        .enumerate()
    {
        if unresolved_parent(origin, inheritance_matters) {
            return Err(());
        }
        let depth = index + 1;
        if origin_matches(policy, origin, depth, destination) {
            return Ok(Some((depth, origin)));
        }
    }
    Ok(None)
}

fn unresolved_parent(origin: &ProcessIdentity, inheritance_matters: bool) -> bool {
    inheritance_matters && origin.canonical_executable.is_empty() && origin.package_sid.is_none()
}

pub(crate) fn select(
    policy: &Policy,
    process: &ProcessIdentity,
    ancestors: &[ProcessIdentity],
    destination: IpAddr,
) -> Result<Option<(usize, usize)>, ()> {
    let origin = nearest_origin(policy, process, ancestors, destination)?;
    Ok(policy
        .effective_document
        .rules
        .iter()
        .enumerate()
        .find_map(|(index, rule)| {
            if !network_matches(policy, index, destination) {
                return None;
            }
            match (&rule.application, origin) {
                (Selector::Any {}, _) => Some((index, 0)),
                (_, Some((depth, origin)))
                    if (depth == 0 || rule.inherit_children)
                        && application_matches(&rule.application, origin) =>
                {
                    Some((index, depth))
                }
                _ => None,
            }
        }))
}
