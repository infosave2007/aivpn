//! Дескриптор дополнительных секций настроек для GUI.
//!
//! Публичный GUI имеет фиксированный набор экранов. Сборка, подключающая
//! альтернативный транспорт датаграмм (см. [`crate::transport`]), может нести
//! несколько собственных элементов управления. Их подписи и само их наличие
//! описывают подключённый модуль, а не приложение, поэтому в публичном дереве
//! их нет.
//!
//! Секция описывается **данными**, а не кодом: файл-дескриптор перечисляет
//! поля с типами и подписями, хост рисует их родными виджетами и не знает
//! смысла ни одного. Нет файла — секции нет вовсе, что и есть поведение
//! публичной сборки.
//!
//! # Почему данные, а не трейт
//!
//! Провайдер, который здесь напрашивается, не содержал бы логики: он читает
//! поля, проверяет один переключатель и складывает остальные в JSON. Ради
//! этого не нужен ни крейт, ни динамическая диспетчеризация — нужен файл. Так
//! GUI остаются обычными бинарями, а не библиотеками, которые кто-то линкует
//! снаружи.
//!
//! # Чем этот контракт опаснее соседнего
//!
//! Форму [`crate::transport`] проверяет компилятор. Форму дескриптора — никто:
//! рассинхронизация даёт не ошибку сборки, а секцию, которая молча
//! отрисовалась не так или не отрисовалась совсем. Поэтому формат
//! версионирован, незнакомая версия и незнакомый ключ — ошибки разбора, а не
//! повод что-то пропустить, и эталонный дескриптор разбирается тестом с обеих
//! сторон границы.

use std::path::Path;

use serde::Deserialize;

use crate::transport::TransportConfig;

/// Единственная версия формата, которую понимает этот код.
pub const SCHEMA_VERSION: u32 = 1;

/// Тип поля. Хост выбирает виджет по нему и только по нему.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// Флажок.
    Toggle,
    /// Однострочный ввод.
    Text,
    /// Однострочный ввод со скрытыми символами.
    Secret,
    /// Выбор одного из; значение — индекс в `options`.
    Select { options: Vec<String> },
}

/// Одно поле секции.
///
/// `key` непрозрачен для хоста и попадает в параметры транспорта как есть;
/// `label` показывается пользователю и приходит из дескриптора, а не из
/// переводов приложения — сборка, в которую модуль не входит, не должна
/// содержать его строк.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub kind: FieldKind,
}

/// Разобранный дескриптор одной секции.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub id: String,
    pub title: String,
    /// Имя транспорта, которое уйдёт в [`TransportConfig`].
    pub transport: String,
    /// Поле-шлюз: если оно выключено, [`apply`] возвращает `None`
    /// («транспорт по умолчанию»). `None` — секция всегда включена.
    pub gate_field: Option<String>,
    pub fields: Vec<Field>,
}

/// Отредактированное значение поля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Toggle(bool),
    Text(String),
    /// Индекс выбранного варианта.
    Select(usize),
}

/// Ошибка разбора дескриптора.
#[derive(Debug)]
pub enum DescriptorError {
    /// Файл не является корректным JSON либо не соответствует форме.
    Malformed(String),
    /// Версия схемы не та, которую понимает этот код.
    UnsupportedSchema { found: u32, expected: u32 },
}

impl std::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed settings descriptor: {m}"),
            Self::UnsupportedSchema { found, expected } => write!(
                f,
                "unsupported settings descriptor schema {found}, \
                 this build understands {expected}"
            ),
        }
    }
}

impl std::error::Error for DescriptorError {}

// ── Форма файла ──────────────────────────────────────────────────────────────
//
// Отдельные типы от публичных: `deny_unknown_fields` обязателен, чтобы опечатка
// в ключе была ошибкой, а не молча пропущенным полем. Секция, выглядящая
// рабочей и ведущая себя не так, хуже секции, которой нет.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescriptor {
    schema: u32,
    id: String,
    title: String,
    transport: String,
    #[serde(default)]
    gate_field: Option<String>,
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    key: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    options: Vec<String>,
}

/// Разобрать дескриптор из строки.
pub fn parse_descriptor(s: &str) -> Result<Descriptor, DescriptorError> {
    let raw: RawDescriptor =
        serde_json::from_str(s).map_err(|e| DescriptorError::Malformed(e.to_string()))?;

    if raw.schema != SCHEMA_VERSION {
        return Err(DescriptorError::UnsupportedSchema {
            found: raw.schema,
            expected: SCHEMA_VERSION,
        });
    }

    let mut fields = Vec::with_capacity(raw.fields.len());
    for f in raw.fields {
        let kind = match f.kind.as_str() {
            "toggle" => FieldKind::Toggle,
            "text" => FieldKind::Text,
            "secret" => FieldKind::Secret,
            "select" => FieldKind::Select { options: f.options },
            other => {
                return Err(DescriptorError::Malformed(format!(
                    "unknown field type '{other}' for key '{}'",
                    f.key
                )))
            }
        };
        fields.push(Field {
            key: f.key,
            label: f.label,
            kind,
        });
    }

    Ok(Descriptor {
        id: raw.id,
        title: raw.title,
        transport: raw.transport,
        gate_field: raw.gate_field,
        fields,
    })
}

/// Прочитать дескриптор из файла.
///
/// `None` означает «секции нет» — файла нет, он нечитаем или не разбирается.
/// Ошибка разбора логируется, но не роняет GUI: неверный дескриптор не должен
/// мешать пользоваться приложением.
pub fn load_descriptor(path: &Path) -> Option<Descriptor> {
    let text = std::fs::read_to_string(path).ok()?;
    match parse_descriptor(&text) {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::warn!("settings descriptor at {} ignored: {e}", path.display());
            None
        }
    }
}

/// Свернуть отредактированные значения в конфигурацию транспорта.
///
/// `None` — «использовать транспорт по умолчанию»: поле-шлюз выключено. Иначе
/// все значения складываются в JSON-объект и уходят как непрозрачные параметры
/// транспорта, имя которого назвал дескриптор.
///
/// Поле-шлюз в параметры не попадает: оно решение хоста о том, включать ли
/// транспорт вообще, а не параметр самого транспорта.
pub fn apply(descriptor: &Descriptor, values: &[(String, FieldValue)]) -> Option<TransportConfig> {
    if let Some(gate) = &descriptor.gate_field {
        let open = values
            .iter()
            .any(|(k, v)| k == gate && matches!(v, FieldValue::Toggle(true)));
        if !open {
            return None;
        }
    }

    let mut params = serde_json::Map::new();
    for (key, value) in values {
        if Some(key) == descriptor.gate_field.as_ref() {
            continue;
        }
        let json = match value {
            FieldValue::Toggle(b) => serde_json::Value::Bool(*b),
            FieldValue::Text(s) => serde_json::Value::String(s.clone()),
            FieldValue::Select(i) => serde_json::Value::from(*i),
        };
        params.insert(key.clone(), json);
    }

    let bytes = serde_json::to_vec(&serde_json::Value::Object(params)).ok()?;
    Some(TransportConfig::new(descriptor.transport.clone(), bytes))
}
