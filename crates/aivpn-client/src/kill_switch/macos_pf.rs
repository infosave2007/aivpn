//! Порядок фильтрующих правил PF при подключении защиты приложения.

pub(super) fn with_first_anchor(configuration: &str) -> String {
    let lines: Vec<_> = configuration
        .lines()
        .filter(|line| !line.trim_start().starts_with("anchor \"aivpn_ks\""))
        .collect();
    let first = lines
        .iter()
        .position(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("anchor" | "pass" | "block" | "antispoof")
            )
        })
        .unwrap_or(lines.len());
    let mut output = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index == first {
            output.push_str("anchor \"aivpn_ks\" quick\n");
        }
        output.push_str(line);
        output.push('\n');
    }
    if first == lines.len() {
        output.push_str("anchor \"aivpn_ks\" quick\n");
    }
    output
}

pub(super) fn anchor_is_first(rules: &str) -> bool {
    rules
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .is_some_and(|line| {
            line.starts_with("anchor \"aivpn_ks\"")
                && line.split_whitespace().any(|word| word == "quick")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn precedes_existing_quick_pass_without_moving_nat_or_options() {
        let config = "set skip on lo0\nnat-anchor \"com.apple/*\"\npass out quick all\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";
        let rules = with_first_anchor(config);
        assert!(rules.starts_with("set skip on lo0\nnat-anchor \"com.apple/*\"\nanchor \"aivpn_ks\" quick\npass out quick all"));
        assert!(anchor_is_first(
            "anchor \"aivpn_ks\" quick all\npass out quick all"
        ));
        assert!(!anchor_is_first(
            "pass out quick all\nanchor \"aivpn_ks\" quick"
        ));
        assert!(!anchor_is_first("anchor \"aivpn_ks\" all"));
        assert_eq!(with_first_anchor(&rules), rules);
    }
}
