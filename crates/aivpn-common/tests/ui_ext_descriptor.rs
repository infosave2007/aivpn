//! Контракт данных дескриптора секций настроек.
//!
//! Компилятор его не проверяет — в отличие от Rust-контракта шва. Этот файл
//! единственное, что стоит между рассинхронизацией схемы и молча неправильно
//! отрисованной секцией.

use aivpn_common::ui_ext::{apply, parse_descriptor, FieldKind, FieldValue};

/// Эталонный дескриптор. Парная копия живёт в закрытом репозитории и
/// разбирается тем же тестом — так обе стороны ломаются одновременно и явно.
const REFERENCE: &str = r#"{
  "schema": 1,
  "id": "alt",
  "title": "Extra transport",
  "transport": "alt",
  "gate_field": "enabled",
  "fields": [
    { "key": "enabled",  "label": "Enable",   "type": "toggle" },
    { "key": "endpoint", "label": "Endpoint", "type": "text" },
    { "key": "secret",   "label": "Secret",   "type": "secret" },
    { "key": "mode",     "label": "Mode",     "type": "select",
      "options": ["a", "b", "c"] }
  ]
}"#;

#[test]
fn reference_descriptor_parses() {
    let d = parse_descriptor(REFERENCE).expect("эталон должен разбираться");
    assert_eq!(d.id, "alt");
    assert_eq!(d.transport, "alt");
    assert_eq!(d.gate_field.as_deref(), Some("enabled"));
    assert_eq!(d.fields.len(), 4);
    assert_eq!(d.fields[0].kind, FieldKind::Toggle);
    assert_eq!(d.fields[1].kind, FieldKind::Text);
    assert_eq!(d.fields[2].kind, FieldKind::Secret);
    assert_eq!(
        d.fields[3].kind,
        FieldKind::Select {
            options: vec!["a".into(), "b".into(), "c".into()]
        }
    );
}

#[test]
fn unknown_schema_version_is_rejected_loudly() {
    let bad = REFERENCE.replace("\"schema\": 1", "\"schema\": 2");
    let err = parse_descriptor(&bad).expect_err("версия 2 не должна разбираться");
    assert!(
        err.to_string().contains("schema"),
        "ошибка обязана называть версию схемы, получено: {err}"
    );
}

#[test]
fn unknown_field_type_is_a_parse_error_not_a_skip() {
    let bad = REFERENCE.replace("\"type\": \"toggle\"", "\"type\": \"slider\"");
    assert!(
        parse_descriptor(&bad).is_err(),
        "неизвестный тип поля обязан быть ошибкой, а не молча пропущенным полем"
    );
}

#[test]
fn unknown_key_is_a_parse_error_not_a_skip() {
    let bad = REFERENCE.replace("\"id\": \"alt\"", "\"id\": \"alt\", \"colour\": \"red\"");
    assert!(
        parse_descriptor(&bad).is_err(),
        "опечатка в ключе обязана быть ошибкой: молча пропущенный ключ — это \
         секция, которая выглядит рабочей и ведёт себя не так"
    );
}

#[test]
fn gate_field_off_means_default_transport() {
    let d = parse_descriptor(REFERENCE).unwrap();
    let values = vec![
        ("enabled".to_string(), FieldValue::Toggle(false)),
        ("endpoint".to_string(), FieldValue::Text("host:1".into())),
    ];
    assert!(apply(&d, &values).is_none());
}

#[test]
fn gate_field_on_yields_config_with_all_values() {
    let d = parse_descriptor(REFERENCE).unwrap();
    let values = vec![
        ("enabled".to_string(), FieldValue::Toggle(true)),
        ("endpoint".to_string(), FieldValue::Text("host:1".into())),
        ("secret".to_string(), FieldValue::Text("s3cr3t".into())),
        ("mode".to_string(), FieldValue::Select(2)),
    ];
    let cfg = apply(&d, &values).expect("шлюз открыт — конфиг обязан быть");
    assert_eq!(cfg.name(), "alt");
    let v: serde_json::Value = serde_json::from_slice(cfg.params()).unwrap();
    assert_eq!(v["endpoint"], "host:1");
    assert_eq!(v["secret"], "s3cr3t");
    assert_eq!(v["mode"], 2);
    assert!(
        v.get("enabled").is_none(),
        "поле-шлюз не должно уезжать в параметры: оно решение хоста, а не \
         параметр транспорта"
    );
}

#[test]
fn absent_descriptor_means_no_section() {
    assert!(aivpn_common::ui_ext::load_descriptor(std::path::Path::new(
        "/nonexistent/ext-sections.json"
    ))
    .is_none());
}
