//! Обученные эталонные модели привязаны к ID маски и хешу ее сигнатуры.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

use crate::neural_training::{
    read_bounded_file, signature_hash_hex, TrainEvaluation, TrainedEncoder, FEATURE_VERSION,
    SCHEMA_VERSION,
};

const MAX_LIBRARY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MODELS: usize = 128;

#[derive(Default)]
pub struct ModelLibrary {
    models: BTreeMap<String, TrainedEncoder>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryFile {
    schema_version: u32,
    feature_version: u32,
    models: Vec<ModelFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelFile {
    mask_id: String,
    model: serde_json::Value,
    evaluation: serde_json::Value,
}

impl ModelLibrary {
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        if let Some(path) = path {
            let bytes =
                read_bounded_file(path, MAX_LIBRARY_BYTES).map_err(|error| error.to_string())?;
            let text = std::str::from_utf8(&bytes).map_err(|error| error.to_string())?;
            Self::from_json(text)
        } else {
            Self::from_json(include_str!("../../../assets/neural/models.json"))
        }
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() as u64 > MAX_LIBRARY_BYTES {
            return Err("Библиотека моделей превышает 8 МиБ".into());
        }
        let file: LibraryFile = serde_json::from_str(text).map_err(|error| error.to_string())?;
        if file.schema_version != SCHEMA_VERSION || file.feature_version != FEATURE_VERSION {
            return Err("Версия библиотеки моделей не поддерживается".into());
        }
        if file.models.len() > MAX_MODELS {
            return Err("В библиотеке больше 128 моделей".into());
        }
        let mut models = BTreeMap::new();
        for entry in file.models {
            if entry.mask_id.is_empty()
                || entry.mask_id.len() > 128
                || entry.mask_id.chars().any(char::is_control)
            {
                return Err("Недопустимый ID маски в библиотеке моделей".into());
            }
            let model = TrainedEncoder::from_json(&entry.model.to_string())
                .map_err(|error| error.to_string())?;
            let evaluation = TrainEvaluation::from_json(&entry.evaluation.to_string())
                .map_err(|error| error.to_string())?;
            if model.signature_hash != evaluation.signature_hash
                || model.hidden != evaluation.hidden
                || evaluation.model_digest != model.digest().map_err(|error| error.to_string())?
            {
                return Err("Отчет обучения не соответствует модели".into());
            }
            if models.insert(entry.mask_id, model).is_some() {
                return Err("В библиотеке повторяется ID маски".into());
            }
        }
        Ok(Self { models })
    }

    pub fn matching(&self, mask_id: &str, signature: &[f32]) -> Option<&TrainedEncoder> {
        let model = self.models.get(mask_id)?;
        (model.signature_hash == signature_hash_hex(signature).ok()?).then_some(model)
    }

    pub fn len(&self) -> usize {
        self.models.len()
    }
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incompatible_library_versions_and_oversized_content() {
        assert!(ModelLibrary::from_json(
            r#"{"schema_version":1,"feature_version":99,"models":[]}"#
        )
        .is_err());
        assert!(ModelLibrary::from_json(&" ".repeat(MAX_LIBRARY_BYTES as usize + 1)).is_err());
    }
}
