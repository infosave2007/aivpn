//! Правила netfilter снимаются одной транзакцией до удаления удерживаемых ими BPF pins.
use super::*;
use crate::{
    linux::kernel::retirement::{Base, Kind, Pin},
    maintenance::DecommissionProof,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chain {
    family: String,
    table: String,
    name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Routes {
    family: String,
    table: u32,
    priority: u32,
    mark: u32,
    rule: Value,
    routes: Vec<Value>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::linux) struct PathRetirement {
    chains: Vec<Chain>,
    tables: Vec<String>,
    firewall: Vec<Value>,
    routes: Vec<Routes>,
}

fn ruleset() -> io::Result<Vec<Value>> {
    json("nft", &["-j", "-a", "list", "ruleset"])?["nftables"]
        .as_array()
        .cloned()
        .ok_or_else(invalid)
}

fn references(rule: &Value, chain: &str) -> bool {
    rule["expr"].as_array().is_some_and(|expressions| {
        expressions
            .iter()
            .any(|expr| expr["jump"]["target"] == chain || expr["goto"]["target"] == chain)
    })
}

impl PathRetirement {
    pub(in crate::linux) fn validate(&self, namespace: [u8; 16]) -> io::Result<()> {
        if self.tables.len() > 256
            || self.chains.len() != self.tables.len() * 4
            || self.routes.len() != self.tables.len() * 2
            || self.firewall.len() > 16384
        {
            return Err(invalid());
        }
        let prefix = namespace[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut seen = std::collections::BTreeSet::new();
        for (position, table) in self.tables.iter().enumerate() {
            let number = (1..=256u32)
                .find(|number| {
                    let suffix = if *number == 1 {
                        prefix.clone()
                    } else {
                        format!("{prefix}_{number}")
                    };
                    *table == format!("aivpn_{suffix}")
                })
                .ok_or_else(invalid)?;
            if !seen.insert(number) {
                return Err(invalid());
            }
            let chain_name = table.replacen("aivpn_", "AIVPN_", 1);
            for (offset, (family, chain_table)) in [
                ("ip", "raw"),
                ("ip", "mangle"),
                ("ip6", "raw"),
                ("ip6", "mangle"),
            ]
            .into_iter()
            .enumerate()
            {
                let chain = &self.chains[position * 4 + offset];
                if chain.family != family || chain.table != chain_table || chain.name != chain_name
                {
                    return Err(invalid());
                }
            }
            for (offset, family) in ["-4", "-6"].into_iter().enumerate() {
                let routes = &self.routes[position * 2 + offset];
                let owned = OwnedRule {
                    priority: 100,
                    table: 42000 + number,
                    mark: (0xa100 + number) << 16,
                };
                if routes.family != family
                    || routes.priority != owned.priority
                    || routes.table != owned.table
                    || routes.mark != owned.mark
                    || !owned.matches(&routes.rule)
                    || routes.routes.len() != 1
                    || routes.routes[0]["type"] != "unreachable"
                    || routes.routes[0]["dst"] != "default"
                    || routes.routes[0]["metric"] != 32767
                {
                    return Err(invalid());
                }
            }
        }
        if self.select(&self.firewall)? != self.firewall {
            return Err(invalid());
        }
        Ok(())
    }
    pub(in crate::linux) fn capture(
        namespace: [u8; 16],
        resources: StateDirectory,
    ) -> io::Result<(Self, Vec<Pin>)> {
        let paths = DataPaths::open(namespace, resources)?;
        let mut plan = Self::default();
        let mut pins = Vec::new();
        for path in paths.all() {
            if path.record.phase == "new" {
                continue;
            }
            path.verify_persistent()?;
            if path.record.tunnel.is_some() || path.record.matcher == 0 || path.record.slot == 0 {
                return Err(invalid());
            }
            let name = format!(
                "{}_{:08x}",
                namespace
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                path.record.slot
            );
            pins.push(Pin::capture(
                Base::Profiles,
                namespace,
                name,
                Kind::Program,
                path.record.matcher,
            )?);
            for family in ["ip", "ip6"] {
                for table in ["raw", "mangle"] {
                    plan.chains.push(Chain {
                        family: family.into(),
                        table: table.into(),
                        name: path.record.chain.clone(),
                    });
                }
            }
            plan.tables.push(path.record.nft.clone());
            for family in ["-4", "-6"] {
                let routes = table_routes(family, path.record.table)?;
                if routes.len() != 1
                    || routes[0]["type"] != "unreachable"
                    || routes[0]["dst"] != "default"
                    || routes[0]["metric"] != 32767
                {
                    return Err(invalid());
                }
                let owned = OwnedRule {
                    priority: path.record.priority,
                    table: path.record.table,
                    mark: path.record.mark,
                };
                let rules = json("ip", &[family, "-j", "rule", "show"])?;
                let relevant = relevant_rules(&rules, &owned)?;
                if relevant.len() != 1 || !owned.matches(&relevant[0]) {
                    return Err(invalid());
                }
                plan.routes.push(Routes {
                    family: family.into(),
                    table: owned.table,
                    priority: owned.priority,
                    mark: owned.mark,
                    rule: relevant[0].clone(),
                    routes,
                });
            }
        }
        plan.firewall = plan.select(&ruleset()?)?;
        // Каждая цепочка имеет ровно один штатный переход из OUTPUT.
        for chain in &plan.chains {
            let own: Vec<_> = plan
                .firewall
                .iter()
                .filter_map(|row| row.get("chain"))
                .filter(|row| {
                    row["family"] == chain.family
                        && row["table"] == chain.table
                        && row["name"] == chain.name
                })
                .collect();
            let incoming: Vec<_> = plan
                .firewall
                .iter()
                .filter_map(|row| row.get("rule"))
                .filter(|row| {
                    row["family"] == chain.family
                        && row["table"] == chain.table
                        && references(row, &chain.name)
                })
                .collect();
            if own.len() != 1
                || incoming.len() != 1
                || incoming[0]["chain"] != "OUTPUT"
                || incoming[0]["expr"] != serde_json::json!([{"jump":{"target":chain.name}}])
            {
                return Err(invalid());
            }
        }
        Ok((plan, pins))
    }

    fn select(&self, rows: &[Value]) -> io::Result<Vec<Value>> {
        let mut selected = Vec::new();
        for row in rows {
            if row.get("metainfo").is_some() {
                continue;
            }
            let object = row
                .as_object()
                .filter(|object| object.len() == 1)
                .and_then(|object| object.values().next())
                .ok_or_else(invalid)?;
            let whole_table = object["family"] == "inet"
                && self.tables.iter().any(|table| {
                    object["name"] == *table && row.get("table").is_some()
                        || object["table"] == *table
                });
            let owned_chain = self.chains.iter().any(|chain| {
                object["family"] == chain.family
                    && object["table"] == chain.table
                    && (row.get("chain").is_some() && object["name"] == chain.name
                        || row.get("rule").is_some()
                            && (object["chain"] == chain.name || references(object, &chain.name)))
            });
            if whole_table || owned_chain {
                let mut row = row.clone();
                // Счетчики меняются от обычного трафика и не определяют владельца правила.
                if let Some(expressions) = row
                    .get_mut("rule")
                    .and_then(|rule| rule.get_mut("expr"))
                    .and_then(Value::as_array_mut)
                {
                    expressions.retain(|expression| expression.get("counter").is_none());
                }
                selected.push(row);
            }
        }
        Ok(selected)
    }

    pub(in crate::linux) fn preflight(&self) -> io::Result<()> {
        let actual = self.select(&ruleset()?)?;
        if !actual.is_empty() && actual != self.firewall {
            return Err(invalid());
        }
        for routes in &self.routes {
            routes.inspect()?;
        }
        Ok(())
    }

    pub(in crate::linux) fn apply(&self, proof: &DecommissionProof<'_>) -> io::Result<()> {
        proof.confirm()?;
        self.preflight()?;
        let actual = self.select(&ruleset()?)?;
        if !actual.is_empty() {
            if actual != self.firewall {
                return Err(invalid());
            }
            let mut script = String::new();
            for chain in &self.chains {
                let incoming = actual
                    .iter()
                    .filter_map(|row| row.get("rule"))
                    .find(|rule| {
                        rule["family"] == chain.family
                            && rule["table"] == chain.table
                            && references(rule, &chain.name)
                    })
                    .ok_or_else(invalid)?;
                let handle = incoming["handle"].as_u64().ok_or_else(invalid)?;
                script.push_str(&format!("delete rule {} {} OUTPUT handle {}\nflush chain {} {} {}\ndelete chain {} {} {}\n", chain.family, chain.table, handle, chain.family, chain.table, chain.name, chain.family, chain.table, chain.name));
            }
            for table in &self.tables {
                script.push_str(&format!("delete table inet {table}\n"));
            }
            proof.confirm()?;
            run("nft", &["-f", "-"], Some(script.as_bytes()))?;
            if !self.select(&ruleset()?)?.is_empty() {
                return Err(invalid());
            }
        }
        for routes in &self.routes {
            proof.confirm()?;
            routes.remove()?;
        }
        Ok(())
    }
}

fn relevant_rules(rules: &Value, owned: &OwnedRule) -> io::Result<Vec<Value>> {
    let mut relevant = Vec::new();
    for rule in rules.as_array().ok_or_else(invalid)? {
        if number(&rule["table"]) == Some(u64::from(owned.table)) || mark_overlap(rule, owned.mark)?
        {
            relevant.push(rule.clone());
        }
    }
    Ok(relevant)
}

fn table_routes(family: &str, table: u32) -> io::Result<Vec<Value>> {
    let routes = json("ip", &[family, "-j", "route", "show", "table", "all"])?;
    let mut selected = Vec::new();
    for route in routes.as_array().ok_or_else(invalid)? {
        if number(&route["table"]) == Some(u64::from(table)) {
            let mut route = route.clone();
            route.as_object_mut().ok_or_else(invalid)?.remove("table");
            selected.push(route);
        }
    }
    Ok(selected)
}

impl Routes {
    fn inspect(&self) -> io::Result<(bool, bool)> {
        let owned = OwnedRule {
            priority: self.priority,
            table: self.table,
            mark: self.mark,
        };
        let rules = relevant_rules(&json("ip", &[&self.family, "-j", "rule", "show"])?, &owned)?;
        let routes = table_routes(&self.family, self.table)?;
        if (!rules.is_empty() && rules != [self.rule.clone()])
            || (!routes.is_empty() && routes != self.routes)
        {
            return Err(invalid());
        }
        Ok((!rules.is_empty(), !routes.is_empty()))
    }
    fn remove(&self) -> io::Result<()> {
        let (rule, _) = self.inspect()?;
        if rule {
            run(
                "ip",
                &[
                    &self.family,
                    "rule",
                    "del",
                    "priority",
                    &self.priority.to_string(),
                    "fwmark",
                    &format!("0x{:x}/0x{:x}", self.mark, PROFILE_MARK_MASK),
                    "lookup",
                    &self.table.to_string(),
                ],
                None,
            )?;
        }
        let (_, routes) = self.inspect()?;
        if routes {
            run(
                "ip",
                &[
                    &self.family,
                    "route",
                    "del",
                    "unreachable",
                    "default",
                    "table",
                    &self.table.to_string(),
                    "metric",
                    "32767",
                ],
                None,
            )?;
        }
        if self.inspect()? != (false, false) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn firewall_selection_includes_foreign_references_but_preserves_unrelated_rules() {
        let plan = PathRetirement {
            chains: vec![Chain {
                family: "ip".into(),
                table: "raw".into(),
                name: "AIVPN_test".into(),
            }],
            tables: vec!["aivpn_test".into()],
            ..Default::default()
        };
        let own = json!({"chain":{"family":"ip","table":"raw","name":"AIVPN_test","handle":4}});
        let jump = json!({"rule":{"family":"ip","table":"raw","chain":"OUTPUT","expr":[{"jump":{"target":"AIVPN_test"}}],"handle":5}});
        let foreign_ref = json!({"rule":{"family":"ip","table":"raw","chain":"FOREIGN","expr":[{"goto":{"target":"AIVPN_test"}}],"handle":6}});
        let foreign = json!({"rule":{"family":"ip","table":"raw","chain":"OUTPUT","expr":[{"accept":null}],"handle":7}});
        let table = json!({"table":{"family":"inet","name":"aivpn_test","handle":10}});
        let inner =
            json!({"chain":{"family":"inet","table":"aivpn_test","name":"post","handle":11}});
        let other_family = json!({"table":{"family":"ip6","name":"aivpn_test","handle":12}});
        let with_counter = json!({"rule":{"family":"ip","table":"raw","chain":"OUTPUT","expr":[{"counter":{"packets":128,"bytes":65536}},{"jump":{"target":"AIVPN_test"}}],"handle":5}});
        assert_eq!(plan.select(&[with_counter]).unwrap(), vec![jump.clone()]);
        assert_eq!(
            plan.select(&[
                own.clone(),
                jump.clone(),
                foreign_ref.clone(),
                foreign,
                table.clone(),
                inner.clone(),
                other_family
            ])
            .unwrap(),
            vec![own, jump, foreign_ref, table, inner]
        );
    }
}
