//! Сохраняет глобальный DNS NetworkManager без зависимости от порядка словарей D-Bus.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, collections::HashMap, io, net::SocketAddr};
use zbus::zvariant::{OwnedValue, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GlobalDns {
    searches: Vec<String>,
    options: Vec<String>,
    domains: BTreeMap<String, Domain>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    servers: Vec<String>,
    options: Option<Vec<String>>,
}
impl GlobalDns {
    pub(super) fn capture(mut values: HashMap<String, OwnedValue>) -> io::Result<Option<Self>> {
        if values.is_empty() {
            return Ok(None);
        }
        let searches = strings(
            values
                .remove("searches")
                .ok_or(io::ErrorKind::InvalidData)?,
        )?;
        let options = strings(values.remove("options").ok_or(io::ErrorKind::InvalidData)?)?;
        let raw = HashMap::<String, OwnedValue>::try_from(
            values.remove("domains").ok_or(io::ErrorKind::InvalidData)?,
        )
        .map_err(|_| io::ErrorKind::InvalidData)?;
        if !values.is_empty() || raw.len() > 256 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut domains = BTreeMap::new();
        for (name, value) in raw {
            if name.is_empty() || name.len() > 255 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut fields = HashMap::<String, OwnedValue>::try_from(value)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            let servers = strings(fields.remove("servers").ok_or(io::ErrorKind::InvalidData)?)?;
            let options = fields.remove("options").map(strings).transpose()?;
            if !fields.is_empty() {
                return Err(io::ErrorKind::Unsupported.into());
            }
            domains.insert(name, Domain { servers, options });
        }
        Ok(Some(Self {
            searches,
            options,
            domains,
        }))
    }
    pub(super) fn local_relay(original: Option<&Self>) -> Self {
        let domains = original
            .into_iter()
            .flat_map(|original| original.domains.keys().map(String::as_str))
            .chain(std::iter::once("*"))
            .map(|name| {
                (
                    name.to_owned(),
                    Domain {
                        servers: vec!["127.0.0.3".into()],
                        options: None,
                    },
                )
            })
            .collect();
        Self {
            searches: original.map(|v| v.searches.clone()).unwrap_or_default(),
            options: original.map(|v| v.options.clone()).unwrap_or_default(),
            domains,
        }
    }
    pub(super) fn restore(value: Option<&Self>) -> HashMap<String, Value<'_>> {
        let Some(value) = value else {
            return HashMap::new();
        };
        let domains: HashMap<_, _> = value
            .domains
            .iter()
            .map(|(name, domain)| {
                let mut fields = HashMap::from([("servers", Value::from(domain.servers.clone()))]);
                if let Some(options) = &domain.options {
                    fields.insert("options", Value::from(options.clone()));
                }
                (name.as_str(), Value::from(fields))
            })
            .collect();
        HashMap::from([
            ("searches".into(), Value::from(value.searches.clone())),
            ("options".into(), Value::from(value.options.clone())),
            ("domains".into(), Value::from(domains)),
        ])
    }
    pub(super) fn configuration(&self) -> io::Result<String> {
        let mut text = String::from("[global-dns]\n");
        configuration_list(&mut text, "searches", &self.searches);
        configuration_list(&mut text, "options", &self.options);
        for (name, domain) in &self.domains {
            if name.is_empty() || name.contains(['[', ']']) || name.chars().any(char::is_control) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            text.push_str("[global-dns-domain-");
            text.push_str(name);
            text.push_str("]\n");
            configuration_list(&mut text, "servers", &domain.servers);
            configuration_list(
                &mut text,
                "options",
                domain.options.as_deref().unwrap_or_default(),
            );
        }
        if text.len() > 65536 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        Ok(text)
    }
    pub(super) fn bootstrap_servers(&self) -> io::Result<Option<Vec<SocketAddr>>> {
        if !self.domains.contains_key("*") {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut servers = Vec::new();
        for domain in self.domains.values() {
            for name in &domain.servers {
                let server = crate::dns::journal::bootstrap_server(name, None)?;
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        crate::dns::journal::validate_bootstrap_servers(&servers)?;
        Ok(Some(servers))
    }
}
fn configuration_list(text: &mut String, key: &str, values: &[String]) {
    text.push_str(key);
    text.push('=');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            text.push(',');
        }
        for character in value.chars() {
            match character {
                '\\' => text.push_str("\\\\"),
                ',' => text.push_str("\\,"),
                '\n' => text.push_str("\\n"),
                '\r' => text.push_str("\\r"),
                '\t' => text.push_str("\\t"),
                ' ' => text.push_str("\\s"),
                _ => text.push(character),
            }
        }
    }
    text.push('\n');
}
fn strings(value: OwnedValue) -> io::Result<Vec<String>> {
    let values = Vec::<String>::try_from(value).map_err(|_| io::ErrorKind::InvalidData)?;
    if values.len() > 256 || values.iter().any(|v| v.len() > 2048 || v.contains('\0')) {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_relay_redirects_more_specific_domains_too() {
        let original = GlobalDns {
            searches: vec!["corp.example".into()],
            options: vec!["timeout:1".into()],
            domains: BTreeMap::from([
                (
                    "*".into(),
                    Domain {
                        servers: vec!["198.18.0.53".into()],
                        options: None,
                    },
                ),
                (
                    "corp.example".into(),
                    Domain {
                        servers: vec!["198.18.0.54".into()],
                        options: Some(vec!["old".into()]),
                    },
                ),
            ]),
        };
        let relay = GlobalDns::local_relay(Some(&original));
        assert_eq!(relay.domains.len(), 2);
        for domain in relay.domains.values() {
            assert_eq!(domain.servers, ["127.0.0.3"]);
            assert_eq!(domain.options, None);
        }
        assert_eq!(relay.searches, original.searches);
        assert_eq!(relay.options, original.options);
        assert_eq!(original.domains["corp.example"].servers, ["198.18.0.54"]);
    }

    #[test]
    fn configuration_escapes_values_without_adding_sections() {
        let mut relay = GlobalDns::local_relay(None);
        relay.searches = vec!["corp.example".into()];
        relay.options = vec!["a,b;c\\c\n[bad]\r\t d".into()];
        let text = relay.configuration().unwrap();
        assert!(text.contains("options=a\\,b;c\\\\c\\n[bad]\\r\\t\\sd\n"));
        assert_eq!(text.lines().filter(|line| line.starts_with('[')).count(), 2);
        assert!(text.contains("[global-dns-domain-*]\nservers=127.0.0.3\noptions=\n"));
    }

    #[test]
    fn configuration_rejects_section_injection_and_excessive_size() {
        let mut relay = GlobalDns::local_relay(None);
        relay
            .domains
            .insert("bad]\n[main".into(), relay.domains["*"].clone());
        assert_eq!(
            relay.configuration().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        relay.domains.remove("bad]\n[main");
        relay.options = vec!["x".repeat(65536)];
        assert_eq!(
            relay.configuration().unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
    }
}
