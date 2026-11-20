use crate::*;
use std::collections::HashSet;

pub(crate) fn document(doc: &PolicyDocument, authority: &Authority) -> Result<(), PolicyError> {
    if doc.version != 1 {
        return Err(PolicyError::Invalid("версия документа не поддерживается"));
    }
    if doc.generation == 0 {
        return Err(PolicyError::Invalid("нулевое поколение"));
    }
    identifier(&doc.id)?;
    owner(&doc.owner, doc.platform)?;
    authorize(&doc.owner, authority, doc.platform)?;
    dns(&doc.dns)?;
    action(&doc.default_action)?;
    rules(&doc.rules, doc.platform)
}

fn rules(rules: &[RuleDocument], platform: Platform) -> Result<(), PolicyError> {
    if rules.len() > MAX_RULES {
        return Err(PolicyError::Invalid("слишком много правил"));
    }
    let mut ids = HashSet::new();
    for rule in rules {
        identifier(&rule.id)?;
        if !ids.insert(&rule.id) {
            return Err(PolicyError::Invalid("повторяется ID правила"));
        }
        selector(&rule.application, platform)?;
        action(&rule.action)?;
    }
    Ok(())
}

pub(crate) fn authorize(
    owner: &Owner,
    authority: &Authority,
    platform: Platform,
) -> Result<(), PolicyError> {
    self::owner(&authority.user, platform)?;
    if authority.machine_admin {
        return Ok(());
    }
    if owner == &(Owner::Machine {}) {
        return Err(PolicyError::Invalid(
            "нужны полномочия администратора машины",
        ));
    }
    if owner != &authority.user {
        return Err(PolicyError::Invalid(
            "нельзя управлять политикой другого пользователя",
        ));
    }
    Ok(())
}

pub(crate) fn owner(owner: &Owner, platform: Platform) -> Result<(), PolicyError> {
    match (owner, platform) {
        (Owner::LinuxUser { .. }, Platform::Linux) | (Owner::Machine {}, _) => Ok(()),
        (Owner::WindowsUser { sid }, Platform::Windows) if valid_sid(sid) => Ok(()),
        _ => Err(PolicyError::Invalid("владелец не соответствует платформе")),
    }
}

pub(crate) fn identifier(value: &str) -> Result<(), PolicyError> {
    let bytes = value.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b));
    if !valid {
        return Err(PolicyError::Invalid("неверный локальный идентификатор"));
    }
    Ok(())
}

fn action(value: &Action) -> Result<(), PolicyError> {
    if let Action::Vpn { profile } = value {
        identifier(profile)?;
    }
    Ok(())
}

fn dns(value: &DnsPolicy) -> Result<(), PolicyError> {
    match value {
        DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        } => identifier(profile),
        _ => Err(PolicyError::Invalid(
            "нужно подтвердить ограничение общего DNS через VPN",
        )),
    }
}

fn selector(value: &Selector, platform: Platform) -> Result<(), PolicyError> {
    match value {
        Selector::Any {} => Ok(()),
        Selector::Executable { path } => executable(path, platform),
        Selector::WindowsPackage { sid }
            if platform == Platform::Windows && valid_sid(sid) && sid.starts_with("S-1-15-2-") =>
        {
            Ok(())
        }
        _ => Err(PolicyError::Invalid(
            "селектор не поддерживается на этой платформе",
        )),
    }
}

fn executable(path: &str, platform: Platform) -> Result<(), PolicyError> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') {
        return Err(PolicyError::Invalid("неверный путь исполняемого файла"));
    }
    let separator = match platform {
        Platform::Linux if path.starts_with('/') => '/',
        Platform::Windows if path.starts_with("\\device\\") => '\\',
        _ => return Err(PolicyError::Invalid("нужен системный абсолютный путь")),
    };
    if path
        .split(separator)
        .skip(1)
        .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(PolicyError::Invalid("путь не приведен к системному виду"));
    }
    Ok(())
}

fn valid_sid(sid: &str) -> bool {
    if sid.len() > 184 {
        return false;
    }
    let parts: Vec<_> = sid.split('-').collect();
    if !(4..=18).contains(&parts.len()) || parts[0] != "S" || parts[1] != "1" {
        return false;
    }
    parts[2..].iter().all(|part| canonical_decimal(part))
        && parts[2]
            .parse::<u64>()
            .is_ok_and(|authority| authority <= 0xffff_ffff_ffff)
        && parts[3..].iter().all(|part| part.parse::<u32>().is_ok())
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}
