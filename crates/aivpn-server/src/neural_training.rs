//! Офлайн-обучение узкого автоэнкодера и строгая переносимая сериализация.
//!
//! Живой шлюз этот модуль не вызывает. Пороги `NeuralConfig` и веса
//! `BakedMaskEncoder` здесь не меняются. Модуль не читает PCAP и не делает
//! кросс-семейную проверку чужих протоколов: это остается вызывающему коду.
//!
//! Признаки готовит `neural::encode_features`. Для `FEATURE_VERSION` = 1 это
//! вектор из 64 конечных f32:
//! блоки 0-15 размеры, 16-31 интервалы, 32-47 энтропия, 48-63 время.
//! Пока раскладка `encode_features` не менялась, версия признака остается 1.
//!
//! Сеть: 64 входа, узкий скрытый слой, ReLU, 64 выхода. Скрытый размер по
//! умолчанию `DEFAULT_HIDDEN` (16). Допустимая альтернатива той же схемы:
//! `DEFAULT_HIDDEN_WIDE` (32). Верхняя граница при разборе модели: 1024.
//! `score` считает среднюю квадратичную ошибку по 64 выходам, ту же величину,
//! что `BakedMaskEncoder::reconstruction_error`.
//!
//! Обучение: обратное распространение и Adam. Старт весов детерминирован,
//! поток BLAKE3 строится из little-endian байт подписи, версии и скрытого
//! размера. Смещение скрытого слоя положительное, масштаб первого слоя
//! умеренный: на признаках из отрезка [0, 1] полный He закрывает ReLU, и
//! сеть застывает константой. Группы train, validation и test передаются
//! раздельно. Эпоха выбирается по минимальной ошибке validation (при равенстве
//! берется более ранняя). test считается один раз после выбора весов.
//! Перемешивания между группами нет.
//!
//! Вызывающий код сам режет окна по времени, держит embargo и не кладет одну
//! и ту же выборку в две группы. Библиотека запрещает пустые группы, неконечные
//! числа, выход за пределы и пересечение срезов в памяти. Одинаковые по
//! значению копии в разных буферах она не отличает: меток времени у нее нет.
//!
//! `signature_hash` это BLAKE3-256 от склейки `to_le_bytes` каждого f32 подписи,
//! без префикса, 64 шестнадцатеричных символа в нижнем регистре.
//!
//! JSON набора (вход CLI), лишние поля запрещены:
//! ```text
//! {
//!   "schema_version": 1,
//!   "feature_version": 1,
//!   "signature_hash": "<64 hex>",
//!   "signature": [64 числа],
//!   "hidden": 16,
//!   "epochs": 40,
//!   "learning_rate": 0.01,
//!   "batch_size": 32,
//!   "beta1": 0.9,
//!   "beta2": 0.999,
//!   "epsilon": 1e-8,
//!   "train": [[64 числа], ...],
//!   "validation": [[64 числа], ...],
//!   "test": [[64 числа], ...]
//! }
//! ```
//! Поля hidden, epochs, learning_rate, batch_size, beta1, beta2, epsilon
//! можно опустить: тогда берутся `TrainConfig::default`.
//!
//! JSON модели:
//! schema_version, feature_version, signature_hash, hidden, w1, b1, w2, b2.
//! w1 хранится по строкам скрытого слоя (hidden * 64).
//! w2 хранится по строкам выхода (64 * hidden).
//! b1 имеет длину hidden, b2 имеет длину 64.
//! Числа в JSON, не сырой дамп памяти. Грузить только через `from_json`:
//! проверяются версия, форма хеша, скрытый размер 1..=1024, точные длины
//! весов и конечность каждого веса. Длина текста ограничена, чтобы разбор
//! не выделял память под произвольный документ.
//!
//! Отчет содержит model_digest - хеш точных весов. history содержит ошибку
//! validation после каждой эпохи и не содержит test.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Длина вектора `neural::encode_features` и обоих линейных краев сети.
pub const FEATURE_DIM: usize = 64;

/// Версия JSON набора, модели и отчета.
pub const SCHEMA_VERSION: u32 = 1;

/// Версия раскладки признаков. Совпадает с текущим `encode_features`.
pub const FEATURE_VERSION: u32 = 1;

/// Узкий скрытый слой по умолчанию.
pub const DEFAULT_HIDDEN: usize = 16;

/// Второй допустимый узкий размер той же схемы. В живой конфиг не пишется.
pub const DEFAULT_HIDDEN_WIDE: usize = 32;

/// Верхняя граница скрытого слоя при проверке модели.
pub const MAX_HIDDEN: usize = 1024;

/// Сколько образцов можно положить в одну группу.
pub const MAX_SAMPLES_PER_SPLIT: usize = 16_384;

/// Сколько эпох можно запросить за один запуск.
pub const MAX_EPOCHS: u32 = 2_000;

/// Предел размера JSON набора до чтения тела в разбор.
pub const MAX_DATASET_BYTES: u64 = 64 * 1024 * 1024;

/// Предел размера JSON модели или отчета до разбора.
pub const MAX_MODEL_JSON_BYTES: usize = 8 * 1024 * 1024;

const INIT_DOMAIN: &[u8] = b"aivpn-trained-encoder-init-v1";

/// Ошибка обучения, разбора или записи.
#[derive(Debug, Clone, PartialEq)]
pub enum TrainError {
    EmptySplit(&'static str),
    TooManySamples {
        split: &'static str,
        count: usize,
        max: usize,
    },
    NonFinite {
        split: &'static str,
        index: usize,
    },
    BadWidth {
        split: &'static str,
        index: usize,
        width: usize,
    },
    AliasedSplits {
        left: &'static str,
        right: &'static str,
    },
    BadSignature(&'static str),
    BadConfig(&'static str),
    Diverged {
        epoch: u32,
    },
    SchemaMismatch {
        expected: u32,
        actual: u32,
    },
    FeatureVersionMismatch {
        expected: u32,
        actual: u32,
    },
    BadSignatureHash,
    SignatureHashMismatch,
    HiddenOutOfRange {
        hidden: usize,
    },
    WeightCount {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    NonFiniteWeight {
        name: &'static str,
        index: usize,
    },
    TooLarge {
        bytes: u64,
        max: u64,
    },
    Json(String),
    Io(String),
}

impl std::fmt::Display for TrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrainError::EmptySplit(name) => write!(f, "пустая группа {name}"),
            TrainError::TooManySamples { split, count, max } => {
                write!(f, "слишком много образцов в {split}: {count} > {max}")
            }
            TrainError::NonFinite { split, index } => {
                write!(f, "неконечное значение в {split}, образец {index}")
            }
            TrainError::BadWidth {
                split,
                index,
                width,
            } => {
                write!(
                    f,
                    "длина вектора в {split}[{index}] равна {width}, нужна {FEATURE_DIM}"
                )
            }
            TrainError::AliasedSplits { left, right } => {
                write!(f, "группы {left} и {right} пересекаются в памяти")
            }
            TrainError::BadSignature(msg) => write!(f, "{msg}"),
            TrainError::BadConfig(msg) => write!(f, "{msg}"),
            TrainError::Diverged { epoch } => {
                write!(
                    f,
                    "обучение разошлось на эпохе {epoch}: неконечный вес или ошибка"
                )
            }
            TrainError::SchemaMismatch { expected, actual } => {
                write!(f, "версия схемы {actual}, ожидается {expected}")
            }
            TrainError::FeatureVersionMismatch { expected, actual } => {
                write!(f, "версия признаков {actual}, ожидается {expected}")
            }
            TrainError::BadSignatureHash => {
                write!(
                    f,
                    "signature_hash должен быть 64 шестнадцатеричных символа в нижнем регистре"
                )
            }
            TrainError::SignatureHashMismatch => {
                write!(f, "signature_hash не совпал с BLAKE3 подписи")
            }
            TrainError::HiddenOutOfRange { hidden } => {
                write!(f, "скрытый размер {hidden} вне диапазона 1..={MAX_HIDDEN}")
            }
            TrainError::WeightCount {
                name,
                expected,
                actual,
            } => write!(f, "длина {name} равна {actual}, ожидается {expected}"),
            TrainError::NonFiniteWeight { name, index } => {
                write!(f, "неконечный вес {name}[{index}]")
            }
            TrainError::TooLarge { bytes, max } => {
                write!(f, "документ слишком большой: {bytes} байт, предел {max}")
            }
            TrainError::Json(msg) => write!(f, "ошибка JSON: {msg}"),
            TrainError::Io(msg) => write!(f, "ошибка ввода: {msg}"),
        }
    }
}

impl std::error::Error for TrainError {}

/// Параметры Adam и размер сети. В боевой рантайм не подставляются.
#[derive(Debug, Clone, PartialEq)]
pub struct TrainConfig {
    pub hidden: usize,
    pub epochs: u32,
    pub learning_rate: f32,
    pub batch_size: usize,
    pub beta1: f32,
    pub beta2: f32,
    pub epsilon: f32,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            hidden: DEFAULT_HIDDEN,
            epochs: 40,
            learning_rate: 1.0e-2,
            batch_size: 32,
            beta1: 0.9,
            beta2: 0.999,
            epsilon: 1.0e-8,
        }
    }
}

impl TrainConfig {
    /// Проверяет границы до выделения весов и до первого шага.
    pub fn validate(&self) -> Result<(), TrainError> {
        if !(1..=MAX_HIDDEN).contains(&self.hidden) {
            return Err(TrainError::HiddenOutOfRange {
                hidden: self.hidden,
            });
        }
        if !(1..=MAX_EPOCHS).contains(&self.epochs) {
            return Err(TrainError::BadConfig("число эпох вне диапазона"));
        }
        if !self.learning_rate.is_finite() || self.learning_rate <= 0.0 || self.learning_rate > 1.0
        {
            return Err(TrainError::BadConfig(
                "шаг обучения должен быть конечным и лежать в (0, 1]",
            ));
        }
        if !self.beta1.is_finite() || self.beta1 <= 0.0 || self.beta1 >= 1.0 {
            return Err(TrainError::BadConfig("beta1 должна лежать в (0, 1)"));
        }
        if !self.beta2.is_finite() || self.beta2 <= 0.0 || self.beta2 >= 1.0 {
            return Err(TrainError::BadConfig("beta2 должна лежать в (0, 1)"));
        }
        if !self.epsilon.is_finite() || self.epsilon <= 0.0 || self.epsilon > 1.0e-2 {
            return Err(TrainError::BadConfig(
                "epsilon должна быть конечной и лежать в (0, 0.01]",
            ));
        }
        if !(1..=MAX_SAMPLES_PER_SPLIT).contains(&self.batch_size) {
            return Err(TrainError::BadConfig("размер батча вне диапазона"));
        }
        Ok(())
    }
}

/// Три раздельные группы уже посчитанных признаков.
#[derive(Debug, Clone, Copy)]
pub struct FeatureSplits<'a> {
    pub train: &'a [[f32; FEATURE_DIM]],
    pub validation: &'a [[f32; FEATURE_DIM]],
    pub test: &'a [[f32; FEATURE_DIM]],
}

/// Проверяет группы до обучения: пустота, предел, конечность, пересечение памяти.
pub fn validate_splits(splits: FeatureSplits<'_>) -> Result<(), TrainError> {
    check_rows("train", splits.train)?;
    check_rows("validation", splits.validation)?;
    check_rows("test", splits.test)?;
    ensure_separated("train", splits.train, "validation", splits.validation)?;
    ensure_separated("train", splits.train, "test", splits.test)?;
    ensure_separated("validation", splits.validation, "test", splits.test)?;
    Ok(())
}

fn check_rows(name: &'static str, rows: &[[f32; FEATURE_DIM]]) -> Result<(), TrainError> {
    if rows.is_empty() {
        return Err(TrainError::EmptySplit(name));
    }
    if rows.len() > MAX_SAMPLES_PER_SPLIT {
        return Err(TrainError::TooManySamples {
            split: name,
            count: rows.len(),
            max: MAX_SAMPLES_PER_SPLIT,
        });
    }
    for (index, row) in rows.iter().enumerate() {
        if row.iter().any(|value| !value.is_finite()) {
            return Err(TrainError::NonFinite { split: name, index });
        }
    }
    Ok(())
}

fn ensure_separated(
    left_name: &'static str,
    left: &[[f32; FEATURE_DIM]],
    right_name: &'static str,
    right: &[[f32; FEATURE_DIM]],
) -> Result<(), TrainError> {
    if slices_overlap(left, right) {
        Err(TrainError::AliasedSplits {
            left: left_name,
            right: right_name,
        })
    } else {
        Ok(())
    }
}

fn slices_overlap(left: &[[f32; FEATURE_DIM]], right: &[[f32; FEATURE_DIM]]) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let size = std::mem::size_of::<[f32; FEATURE_DIM]>();
    let Some(left_bytes) = left.len().checked_mul(size) else {
        return true;
    };
    let Some(right_bytes) = right.len().checked_mul(size) else {
        return true;
    };
    let left_start = left.as_ptr() as usize;
    let right_start = right.as_ptr() as usize;
    let Some(left_end) = left_start.checked_add(left_bytes) else {
        return true;
    };
    let Some(right_end) = right_start.checked_add(right_bytes) else {
        return true;
    };
    left_start < right_end && right_start < left_end
}

/// BLAKE3-256 от little-endian f32 подписи. Подпись обязана иметь длину 64.
pub fn signature_hash_hex(signature: &[f32]) -> Result<String, TrainError> {
    Ok(hex_encode(&signature_hash_bytes(signature)?))
}

fn signature_hash_bytes(signature: &[f32]) -> Result<[u8; 32], TrainError> {
    validate_signature(signature)?;
    let mut hasher = blake3::Hasher::new();
    for value in signature {
        hasher.update(&value.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn validate_signature(signature: &[f32]) -> Result<(), TrainError> {
    if signature.len() != FEATURE_DIM {
        return Err(TrainError::BadSignature("длина подписи должна быть 64"));
    }
    if signature.iter().any(|value| !value.is_finite()) {
        return Err(TrainError::BadSignature(
            "подпись содержит неконечное значение",
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hash_is_well_formed(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn input_digest(signature: &[f32], splits: FeatureSplits<'_>) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"aivpn-neural-dataset-v1");
    hash.update(&FEATURE_VERSION.to_le_bytes());
    for value in signature {
        hash.update(&value.to_le_bytes());
    }
    for (role, samples) in [
        (b"train".as_slice(), splits.train),
        (b"validation".as_slice(), splits.validation),
        (b"test".as_slice(), splits.test),
    ] {
        hash.update(role);
        hash.update(&(samples.len() as u64).to_le_bytes());
        for sample in samples {
            for value in sample {
                hash.update(&value.to_le_bytes());
            }
        }
    }
    hash.finalize().to_hex().to_string()
}

/// Обученная модель с явными метаданными. Поля публичные для интеграции,
/// но загружать документ нужно через `from_json`: прямой разбор serde эти
/// проверки не выполняет.
#[derive(Debug, Clone, PartialEq)]
pub struct TrainedEncoder {
    pub schema_version: u32,
    pub feature_version: u32,
    pub signature_hash: String,
    pub hidden: usize,
    pub w1: Vec<f32>,
    pub b1: Vec<f32>,
    pub w2: Vec<f32>,
    pub b2: Vec<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrainedEncoderFile {
    schema_version: u32,
    feature_version: u32,
    signature_hash: String,
    hidden: usize,
    w1: Vec<f32>,
    b1: Vec<f32>,
    w2: Vec<f32>,
    b2: Vec<f32>,
}

impl TrainedEncoder {
    /// Детерминированный старт без шагов обучения. Нужен как базовая точка
    /// и как начальное состояние `train`.
    pub fn initialize(signature: &[f32], hidden: usize) -> Result<Self, TrainError> {
        if !(1..=MAX_HIDDEN).contains(&hidden) {
            return Err(TrainError::HiddenOutOfRange { hidden });
        }
        let signature_hash = signature_hash_hex(signature)?;
        let w1_len = hidden * FEATURE_DIM;
        let w2_len = FEATURE_DIM * hidden;
        let n_i16 = w1_len + hidden + w2_len + FEATURE_DIM;
        let mut raw = vec![0u8; n_i16 * 2];
        fill_init_xof(signature, hidden, &mut raw);
        let mut cursor = 0usize;
        let next = |cursor: &mut usize| -> i16 {
            let value = i16::from_le_bytes([raw[*cursor], raw[*cursor + 1]]);
            *cursor += 2;
            value
        };
        // Узкий равномерный диапазон, не полный He: см. комментарий модуля.
        let w1_limit = 0.08f32;
        let w2_limit = (1.0f32 / hidden as f32).sqrt();
        let mut w1 = Vec::with_capacity(w1_len);
        let mut b1 = Vec::with_capacity(hidden);
        let mut w2 = Vec::with_capacity(w2_len);
        let mut b2 = Vec::with_capacity(FEATURE_DIM);
        for _ in 0..w1_len {
            w1.push(uniform_unit(next(&mut cursor), w1_limit));
        }
        for _ in 0..hidden {
            let open = unit_interval(next(&mut cursor));
            b1.push(0.08 + 0.04 * open);
        }
        for _ in 0..w2_len {
            w2.push(uniform_unit(next(&mut cursor), w2_limit));
        }
        for _ in 0..FEATURE_DIM {
            b2.push(uniform_unit(next(&mut cursor), 0.01));
        }
        let model = Self {
            schema_version: SCHEMA_VERSION,
            feature_version: FEATURE_VERSION,
            signature_hash,
            hidden,
            w1,
            b1,
            w2,
            b2,
        };
        model.check_strict()?;
        Ok(model)
    }

    /// Полный проход Adam. test не читается, пока не выбран лучший epoch.
    pub fn train(
        signature: &[f32],
        splits: FeatureSplits<'_>,
        config: &TrainConfig,
    ) -> Result<(Self, TrainEvaluation), TrainError> {
        config.validate()?;
        if config.batch_size > splits.train.len() {
            return Err(TrainError::BadConfig(
                "размер батча больше обучающей группы",
            ));
        }
        validate_splits(splits)?;
        let mut model = Self::initialize(signature, config.hidden)?;
        let mut adam = Adam::new(&model, config);
        let mut best = model.clone();
        let mut history = Vec::with_capacity(config.epochs as usize);
        let mut best_index = 0usize;
        let mut best_value = f32::INFINITY;

        for epoch in 1..=config.epochs {
            adam.run_epoch(&mut model, splits.train, config.batch_size, epoch)?;
            if let Err(err) = model.check_finite_weights() {
                let _ = err;
                return Err(TrainError::Diverged { epoch });
            }
            let validation_loss = mean_score_trusted(&model, splits.validation, "validation")?;
            if !validation_loss.is_finite() {
                return Err(TrainError::Diverged { epoch });
            }
            history.push(validation_loss);
            if validation_loss < best_value {
                best_value = validation_loss;
                best_index = (epoch - 1) as usize;
                best = model.clone();
            }
        }

        model = best;
        model.check_strict()?;
        let train_loss = mean_score_trusted(&model, splits.train, "train")?;
        let validation_loss = mean_score_trusted(&model, splits.validation, "validation")?;
        // test только здесь, после фиксации весов по validation.
        let test_loss = mean_score_trusted(&model, splits.test, "test")?;
        if validation_loss.to_bits() != history[best_index].to_bits() {
            return Err(TrainError::Diverged {
                epoch: (best_index as u32) + 1,
            });
        }
        let report = TrainEvaluation {
            schema_version: SCHEMA_VERSION,
            feature_version: FEATURE_VERSION,
            signature_hash: model.signature_hash.clone(),
            model_digest: model.digest()?,
            dataset_digest: input_digest(signature, splits),
            hidden: model.hidden,
            epochs_requested: config.epochs,
            best_epoch: (best_index as u32) + 1,
            learning_rate: config.learning_rate,
            batch_size: config.batch_size,
            beta1: config.beta1,
            beta2: config.beta2,
            epsilon: config.epsilon,
            train_samples: splits.train.len(),
            validation_samples: splits.validation.len(),
            test_samples: splits.test.len(),
            train_loss,
            validation_loss,
            test_loss,
            validation_loss_history: history,
        };
        report.check()?;
        Ok((model, report))
    }

    /// Восстановление входа. Модель и вход проверяются.
    pub fn reconstruct(
        &self,
        features: &[f32; FEATURE_DIM],
    ) -> Result<[f32; FEATURE_DIM], TrainError> {
        self.check_strict()?;
        reconstruct_trusted(self, features)
    }

    /// Средняя квадратичная ошибка одного вектора.
    pub fn score(&self, features: &[f32; FEATURE_DIM]) -> Result<f32, TrainError> {
        let restored = self.reconstruct(features)?;
        let score = mse_pair(features, &restored);
        if !score.is_finite() {
            return Err(TrainError::NonFinite {
                split: "score",
                index: 0,
            });
        }
        Ok(score)
    }

    /// Средняя `score` по группе. Строгая проверка модели делается один раз.
    pub fn mean_score(&self, samples: &[[f32; FEATURE_DIM]]) -> Result<f32, TrainError> {
        self.check_strict()?;
        mean_score_trusted(self, samples, "samples")
    }

    /// Полная проверка метаданных и весов.
    pub fn check_strict(&self) -> Result<(), TrainError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrainError::SchemaMismatch {
                expected: SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.feature_version != FEATURE_VERSION {
            return Err(TrainError::FeatureVersionMismatch {
                expected: FEATURE_VERSION,
                actual: self.feature_version,
            });
        }
        if !hash_is_well_formed(&self.signature_hash) {
            return Err(TrainError::BadSignatureHash);
        }
        if !(1..=MAX_HIDDEN).contains(&self.hidden) {
            return Err(TrainError::HiddenOutOfRange {
                hidden: self.hidden,
            });
        }
        let w1_len = self
            .hidden
            .checked_mul(FEATURE_DIM)
            .ok_or(TrainError::HiddenOutOfRange {
                hidden: self.hidden,
            })?;
        let w2_len = FEATURE_DIM
            .checked_mul(self.hidden)
            .ok_or(TrainError::HiddenOutOfRange {
                hidden: self.hidden,
            })?;
        expect_len("w1", &self.w1, w1_len)?;
        expect_len("b1", &self.b1, self.hidden)?;
        expect_len("w2", &self.w2, w2_len)?;
        expect_len("b2", &self.b2, FEATURE_DIM)?;
        self.check_finite_weights()?;
        // Конечные веса еще могут переполнить f32. Признаки шлюза лежат
        // в [-1, 1], поэтому сумма модулей дает верхнюю границу активаций.
        let hidden_bounds: Vec<f64> = self
            .w1
            .chunks_exact(FEATURE_DIM)
            .zip(&self.b1)
            .map(|(row, bias)| {
                row.iter().map(|value| (*value as f64).abs()).sum::<f64>() + (*bias as f64).abs()
            })
            .collect();
        if hidden_bounds
            .iter()
            .any(|bound| *bound > f32::MAX as f64 / 2.0)
        {
            return Err(TrainError::BadConfig("веса переполняют скрытый слой"));
        }
        let output_limit = (f32::MAX as f64 / FEATURE_DIM as f64).sqrt() / 2.0;
        for (row, bias) in self.w2.chunks_exact(self.hidden).zip(&self.b2) {
            let bound = row
                .iter()
                .zip(&hidden_bounds)
                .map(|(weight, activation)| (*weight as f64).abs() * activation)
                .sum::<f64>()
                + (*bias as f64).abs();
            if bound > output_limit {
                return Err(TrainError::BadConfig(
                    "веса переполняют ошибку реконструкции",
                ));
            }
        }
        Ok(())
    }

    fn check_finite_weights(&self) -> Result<(), TrainError> {
        finite_vec("w1", &self.w1)?;
        finite_vec("b1", &self.b1)?;
        finite_vec("w2", &self.w2)?;
        finite_vec("b2", &self.b2)?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, TrainError> {
        self.check_strict()?;
        let file = TrainedEncoderFile {
            schema_version: self.schema_version,
            feature_version: self.feature_version,
            signature_hash: self.signature_hash.clone(),
            hidden: self.hidden,
            w1: self.w1.clone(),
            b1: self.b1.clone(),
            w2: self.w2.clone(),
            b2: self.b2.clone(),
        };
        let mut text =
            serde_json::to_string_pretty(&file).map_err(|err| TrainError::Json(err.to_string()))?;
        text.push('\n');
        if text.len() > MAX_MODEL_JSON_BYTES {
            return Err(TrainError::TooLarge {
                bytes: text.len() as u64,
                max: MAX_MODEL_JSON_BYTES as u64,
            });
        }
        Ok(text)
    }

    /// Строгий разбор. Сначала предел длины, затем схема, затем веса.
    /// Хеш канонического JSON связывает отчет с конкретными весами.
    pub fn digest(&self) -> Result<String, TrainError> {
        Ok(blake3::hash(self.to_json()?.as_bytes())
            .to_hex()
            .to_string())
    }

    pub fn from_json(text: &str) -> Result<Self, TrainError> {
        ensure_text_limit(text.len(), MAX_MODEL_JSON_BYTES)?;
        let file: TrainedEncoderFile =
            serde_json::from_str(text).map_err(|err| TrainError::Json(err.to_string()))?;
        let model = Self {
            schema_version: file.schema_version,
            feature_version: file.feature_version,
            signature_hash: file.signature_hash,
            hidden: file.hidden,
            w1: file.w1,
            b1: file.b1,
            w2: file.w2,
            b2: file.b2,
        };
        model.check_strict()?;
        Ok(model)
    }
}

fn fill_init_xof(signature: &[f32], hidden: usize, raw: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INIT_DOMAIN);
    hasher.update(&SCHEMA_VERSION.to_le_bytes());
    hasher.update(&FEATURE_VERSION.to_le_bytes());
    hasher.update(&(hidden as u32).to_le_bytes());
    hasher.update(&(signature.len() as u32).to_le_bytes());
    for value in signature {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize_xof().fill(raw);
}

fn uniform_unit(raw: i16, limit: f32) -> f32 {
    let unit = (raw as f32 / i16::MAX as f32).clamp(-1.0, 1.0);
    let weight = unit * limit;
    if weight == 0.0 {
        0.0
    } else {
        weight
    }
}

fn unit_interval(raw: i16) -> f32 {
    let unit = (raw as f32 / i16::MAX as f32).clamp(-1.0, 1.0);
    unit * 0.5 + 0.5
}

fn expect_len(name: &'static str, values: &[f32], expected: usize) -> Result<(), TrainError> {
    if values.len() != expected {
        Err(TrainError::WeightCount {
            name,
            expected,
            actual: values.len(),
        })
    } else {
        Ok(())
    }
}

fn finite_vec(name: &'static str, values: &[f32]) -> Result<(), TrainError> {
    if let Some(index) = values.iter().position(|value| !value.is_finite()) {
        Err(TrainError::NonFiniteWeight { name, index })
    } else {
        Ok(())
    }
}

fn forward(model: &TrainedEncoder, input: &[f32; FEATURE_DIM]) -> [f32; FEATURE_DIM] {
    let hidden = model.hidden;
    let mut activated = vec![0.0f32; hidden];
    for unit in 0..hidden {
        let mut sum = model.b1[unit];
        let row = unit * FEATURE_DIM;
        for feature in 0..FEATURE_DIM {
            sum += model.w1[row + feature] * input[feature];
        }
        if sum > 0.0 {
            activated[unit] = sum;
        }
    }
    let mut output = [0.0f32; FEATURE_DIM];
    for feature in 0..FEATURE_DIM {
        let mut sum = model.b2[feature];
        let row = feature * hidden;
        for unit in 0..hidden {
            sum += model.w2[row + unit] * activated[unit];
        }
        output[feature] = sum;
    }
    output
}

fn reconstruct_trusted(
    model: &TrainedEncoder,
    features: &[f32; FEATURE_DIM],
) -> Result<[f32; FEATURE_DIM], TrainError> {
    if let Some(index) = features.iter().position(|value| !value.is_finite()) {
        return Err(TrainError::NonFinite {
            split: "features",
            index,
        });
    }
    let output = forward(model, features);
    if let Some(index) = output.iter().position(|value| !value.is_finite()) {
        return Err(TrainError::NonFiniteWeight {
            name: "output",
            index,
        });
    }
    Ok(output)
}

fn mse_pair(input: &[f32; FEATURE_DIM], output: &[f32; FEATURE_DIM]) -> f32 {
    let mut acc = 0.0f32;
    for index in 0..FEATURE_DIM {
        let diff = input[index] - output[index];
        acc += diff * diff;
    }
    acc / FEATURE_DIM as f32
}

fn mean_score_trusted(
    model: &TrainedEncoder,
    samples: &[[f32; FEATURE_DIM]],
    split: &'static str,
) -> Result<f32, TrainError> {
    if samples.is_empty() {
        return Err(TrainError::EmptySplit(split));
    }
    let mut acc = 0.0f32;
    for (index, sample) in samples.iter().enumerate() {
        if sample.iter().any(|value| !value.is_finite()) {
            return Err(TrainError::NonFinite { split, index });
        }
        let output = forward(model, sample);
        if output.iter().any(|value| !value.is_finite()) {
            return Err(TrainError::NonFiniteWeight {
                name: "output",
                index: 0,
            });
        }
        let loss = mse_pair(sample, &output);
        if !loss.is_finite() {
            return Err(TrainError::NonFinite { split, index });
        }
        acc += loss;
    }
    let mean = acc / samples.len() as f32;
    if !mean.is_finite() {
        return Err(TrainError::NonFinite { split, index: 0 });
    }
    Ok(mean)
}

struct Grads {
    w1: Vec<f32>,
    b1: Vec<f32>,
    w2: Vec<f32>,
    b2: Vec<f32>,
}

impl Grads {
    fn zeros(hidden: usize) -> Self {
        Self {
            w1: vec![0.0; hidden * FEATURE_DIM],
            b1: vec![0.0; hidden],
            w2: vec![0.0; FEATURE_DIM * hidden],
            b2: vec![0.0; FEATURE_DIM],
        }
    }
}

/// Средний градиент MSE по батчу. Та же функция используется тестом конечных разностей.
fn mean_grads(model: &TrainedEncoder, batch: &[[f32; FEATURE_DIM]]) -> Result<Grads, TrainError> {
    if batch.is_empty() {
        return Err(TrainError::EmptySplit("batch"));
    }
    let mut grads = Grads::zeros(model.hidden);
    let hidden = model.hidden;
    let scale = 2.0f32 / FEATURE_DIM as f32;
    for sample in batch {
        let mut activated = vec![0.0f32; hidden];
        let mut active = vec![false; hidden];
        for unit in 0..hidden {
            let mut sum = model.b1[unit];
            let row = unit * FEATURE_DIM;
            for feature in 0..FEATURE_DIM {
                sum += model.w1[row + feature] * sample[feature];
            }
            if sum > 0.0 {
                activated[unit] = sum;
                active[unit] = true;
            }
        }
        let mut output = [0.0f32; FEATURE_DIM];
        for feature in 0..FEATURE_DIM {
            let mut sum = model.b2[feature];
            let row = feature * hidden;
            for unit in 0..hidden {
                sum += model.w2[row + unit] * activated[unit];
            }
            output[feature] = sum;
        }
        let mut dy = [0.0f32; FEATURE_DIM];
        for feature in 0..FEATURE_DIM {
            dy[feature] = scale * (output[feature] - sample[feature]);
        }
        let mut dh = vec![0.0f32; hidden];
        for feature in 0..FEATURE_DIM {
            let row = feature * hidden;
            grads.b2[feature] += dy[feature];
            for unit in 0..hidden {
                grads.w2[row + unit] += dy[feature] * activated[unit];
                dh[unit] += model.w2[row + unit] * dy[feature];
            }
        }
        for unit in 0..hidden {
            if !active[unit] {
                continue;
            }
            let dz = dh[unit];
            grads.b1[unit] += dz;
            let row = unit * FEATURE_DIM;
            for feature in 0..FEATURE_DIM {
                grads.w1[row + feature] += dz * sample[feature];
            }
        }
    }
    let inv = 1.0f32 / batch.len() as f32;
    scale_grads(&mut grads, inv);
    finite_vec("grad_w1", &grads.w1)?;
    finite_vec("grad_b1", &grads.b1)?;
    finite_vec("grad_w2", &grads.w2)?;
    finite_vec("grad_b2", &grads.b2)?;
    Ok(grads)
}

fn scale_grads(grads: &mut Grads, factor: f32) {
    for value in grads
        .w1
        .iter_mut()
        .chain(grads.b1.iter_mut())
        .chain(grads.w2.iter_mut())
        .chain(grads.b2.iter_mut())
    {
        *value *= factor;
    }
}

struct Adam {
    mw1: Vec<f32>,
    vw1: Vec<f32>,
    mb1: Vec<f32>,
    vb1: Vec<f32>,
    mw2: Vec<f32>,
    vw2: Vec<f32>,
    mb2: Vec<f32>,
    vb2: Vec<f32>,
    beta1: f32,
    beta2: f32,
    beta1_pow: f32,
    beta2_pow: f32,
    lr: f32,
    eps: f32,
}

impl Adam {
    fn new(model: &TrainedEncoder, config: &TrainConfig) -> Self {
        let z = |len: usize| vec![0.0f32; len];
        Self {
            mw1: z(model.w1.len()),
            vw1: z(model.w1.len()),
            mb1: z(model.b1.len()),
            vb1: z(model.b1.len()),
            mw2: z(model.w2.len()),
            vw2: z(model.w2.len()),
            mb2: z(model.b2.len()),
            vb2: z(model.b2.len()),
            beta1: config.beta1,
            beta2: config.beta2,
            beta1_pow: 1.0,
            beta2_pow: 1.0,
            lr: config.learning_rate,
            eps: config.epsilon,
        }
    }

    fn run_epoch(
        &mut self,
        model: &mut TrainedEncoder,
        train: &[[f32; FEATURE_DIM]],
        batch_size: usize,
        epoch: u32,
    ) -> Result<(), TrainError> {
        let mut start = 0usize;
        while start < train.len() {
            let end = (start + batch_size).min(train.len());
            let grads = mean_grads(model, &train[start..end]).map_err(|err| match err {
                TrainError::NonFiniteWeight { .. } | TrainError::NonFinite { .. } => {
                    TrainError::Diverged { epoch }
                }
                other => other,
            })?;
            self.apply(model, &grads, epoch)?;
            start = end;
        }
        Ok(())
    }

    fn apply(
        &mut self,
        model: &mut TrainedEncoder,
        grads: &Grads,
        epoch: u32,
    ) -> Result<(), TrainError> {
        self.beta1_pow *= self.beta1;
        self.beta2_pow *= self.beta2;
        if !self.beta1_pow.is_finite() || !self.beta2_pow.is_finite() {
            return Err(TrainError::Diverged { epoch });
        }
        let bc1 = (1.0 - self.beta1_pow).max(1.0e-12);
        let bc2 = (1.0 - self.beta2_pow).max(1.0e-12);
        apply_tensor(
            &mut model.w1,
            &mut self.mw1,
            &mut self.vw1,
            &grads.w1,
            self.lr,
            self.beta1,
            self.beta2,
            self.eps,
            bc1,
            bc2,
            epoch,
        )?;
        apply_tensor(
            &mut model.b1,
            &mut self.mb1,
            &mut self.vb1,
            &grads.b1,
            self.lr,
            self.beta1,
            self.beta2,
            self.eps,
            bc1,
            bc2,
            epoch,
        )?;
        apply_tensor(
            &mut model.w2,
            &mut self.mw2,
            &mut self.vw2,
            &grads.w2,
            self.lr,
            self.beta1,
            self.beta2,
            self.eps,
            bc1,
            bc2,
            epoch,
        )?;
        apply_tensor(
            &mut model.b2,
            &mut self.mb2,
            &mut self.vb2,
            &grads.b2,
            self.lr,
            self.beta1,
            self.beta2,
            self.eps,
            bc1,
            bc2,
            epoch,
        )?;
        Ok(())
    }
}

fn apply_tensor(
    param: &mut [f32],
    moment: &mut [f32],
    second: &mut [f32],
    grad: &[f32],
    lr: f32,
    beta1: f32,
    beta2: f32,
    eps: f32,
    bc1: f32,
    bc2: f32,
    epoch: u32,
) -> Result<(), TrainError> {
    for index in 0..param.len() {
        moment[index] = beta1 * moment[index] + (1.0 - beta1) * grad[index];
        second[index] = beta2 * second[index] + (1.0 - beta2) * grad[index] * grad[index];
        if !moment[index].is_finite() || !second[index].is_finite() {
            return Err(TrainError::Diverged { epoch });
        }
        let updated =
            param[index] - lr * (moment[index] / bc1) / ((second[index] / bc2).sqrt() + eps);
        if !updated.is_finite() {
            return Err(TrainError::Diverged { epoch });
        }
        param[index] = if updated == 0.0 { 0.0 } else { updated };
    }
    Ok(())
}

/// Отчет одного запуска. test_loss заполнен уже после выбора best_epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct TrainEvaluation {
    pub schema_version: u32,
    pub feature_version: u32,
    pub signature_hash: String,
    pub model_digest: String,
    pub dataset_digest: String,
    pub hidden: usize,
    pub epochs_requested: u32,
    pub best_epoch: u32,
    pub learning_rate: f32,
    pub batch_size: usize,
    pub beta1: f32,
    pub beta2: f32,
    pub epsilon: f32,
    pub train_samples: usize,
    pub validation_samples: usize,
    pub test_samples: usize,
    pub train_loss: f32,
    pub validation_loss: f32,
    pub test_loss: f32,
    pub validation_loss_history: Vec<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrainEvaluationFile {
    schema_version: u32,
    feature_version: u32,
    signature_hash: String,
    model_digest: String,
    dataset_digest: String,
    hidden: usize,
    epochs_requested: u32,
    best_epoch: u32,
    learning_rate: f32,
    batch_size: usize,
    beta1: f32,
    beta2: f32,
    epsilon: f32,
    train_samples: usize,
    validation_samples: usize,
    test_samples: usize,
    train_loss: f32,
    validation_loss: f32,
    test_loss: f32,
    validation_loss_history: Vec<f32>,
}

impl TrainEvaluation {
    pub fn check(&self) -> Result<(), TrainError> {
        if !hash_is_well_formed(&self.dataset_digest) {
            return Err(TrainError::BadSignature("неверный хеш набора в отчете"));
        }
        TrainConfig {
            hidden: self.hidden,
            epochs: self.epochs_requested,
            learning_rate: self.learning_rate,
            batch_size: self.batch_size,
            beta1: self.beta1,
            beta2: self.beta2,
            epsilon: self.epsilon,
        }
        .validate()?;
        if self.train_loss < 0.0
            || self.validation_loss < 0.0
            || self.test_loss < 0.0
            || self.validation_loss_history.iter().any(|loss| *loss < 0.0)
        {
            return Err(TrainError::BadConfig(
                "ошибка MSE не может быть отрицательной",
            ));
        }
        if !hash_is_well_formed(&self.model_digest) {
            return Err(TrainError::BadSignature("неверный хеш весов в отчете"));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrainError::SchemaMismatch {
                expected: SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.feature_version != FEATURE_VERSION {
            return Err(TrainError::FeatureVersionMismatch {
                expected: FEATURE_VERSION,
                actual: self.feature_version,
            });
        }
        if !hash_is_well_formed(&self.signature_hash) {
            return Err(TrainError::BadSignatureHash);
        }
        if !(1..=MAX_HIDDEN).contains(&self.hidden) {
            return Err(TrainError::HiddenOutOfRange {
                hidden: self.hidden,
            });
        }
        if !(1..=MAX_EPOCHS).contains(&self.epochs_requested) {
            return Err(TrainError::BadConfig("число эпох вне диапазона"));
        }
        if self.validation_loss_history.len() != self.epochs_requested as usize {
            return Err(TrainError::BadConfig(
                "длина истории validation не равна числу эпох",
            ));
        }
        if self.best_epoch == 0 || self.best_epoch > self.epochs_requested {
            return Err(TrainError::BadConfig("best_epoch вне диапазона эпох"));
        }
        if !(1..=MAX_SAMPLES_PER_SPLIT).contains(&self.batch_size) {
            return Err(TrainError::BadConfig("размер батча вне диапазона"));
        }
        for (name, count) in [
            ("train", self.train_samples),
            ("validation", self.validation_samples),
            ("test", self.test_samples),
        ] {
            if count == 0 {
                return Err(TrainError::EmptySplit(name));
            }
            if count > MAX_SAMPLES_PER_SPLIT {
                return Err(TrainError::TooManySamples {
                    split: name,
                    count,
                    max: MAX_SAMPLES_PER_SPLIT,
                });
            }
        }
        if self.batch_size > self.train_samples {
            return Err(TrainError::BadConfig(
                "размер батча больше обучающей группы",
            ));
        }
        for (index, loss) in self.validation_loss_history.iter().enumerate() {
            if !loss.is_finite() {
                return Err(TrainError::NonFinite {
                    split: "validation_loss_history",
                    index,
                });
            }
        }
        if !self.learning_rate.is_finite()
            || !self.train_loss.is_finite()
            || !self.validation_loss.is_finite()
            || !self.test_loss.is_finite()
        {
            return Err(TrainError::NonFinite {
                split: "evaluation",
                index: 0,
            });
        }
        let best_index = first_min_index(&self.validation_loss_history)?;
        if (best_index as u32) + 1 != self.best_epoch {
            return Err(TrainError::BadConfig(
                "best_epoch не совпал с первой минимальной ошибкой validation",
            ));
        }
        if self.validation_loss.to_bits() != self.validation_loss_history[best_index].to_bits() {
            return Err(TrainError::BadConfig(
                "validation_loss не совпала с историей выбранной эпохи",
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, TrainError> {
        self.check()?;
        let file = TrainEvaluationFile {
            schema_version: self.schema_version,
            feature_version: self.feature_version,
            signature_hash: self.signature_hash.clone(),
            model_digest: self.model_digest.clone(),
            dataset_digest: self.dataset_digest.clone(),
            hidden: self.hidden,
            epochs_requested: self.epochs_requested,
            best_epoch: self.best_epoch,
            learning_rate: self.learning_rate,
            batch_size: self.batch_size,
            beta1: self.beta1,
            beta2: self.beta2,
            epsilon: self.epsilon,
            train_samples: self.train_samples,
            validation_samples: self.validation_samples,
            test_samples: self.test_samples,
            train_loss: self.train_loss,
            validation_loss: self.validation_loss,
            test_loss: self.test_loss,
            validation_loss_history: self.validation_loss_history.clone(),
        };
        let mut text =
            serde_json::to_string_pretty(&file).map_err(|err| TrainError::Json(err.to_string()))?;
        text.push('\n');
        if text.len() > MAX_MODEL_JSON_BYTES {
            return Err(TrainError::TooLarge {
                bytes: text.len() as u64,
                max: MAX_MODEL_JSON_BYTES as u64,
            });
        }
        Ok(text)
    }

    pub fn from_json(text: &str) -> Result<Self, TrainError> {
        ensure_text_limit(text.len(), MAX_MODEL_JSON_BYTES)?;
        let file: TrainEvaluationFile =
            serde_json::from_str(text).map_err(|err| TrainError::Json(err.to_string()))?;
        let report = Self {
            schema_version: file.schema_version,
            feature_version: file.feature_version,
            signature_hash: file.signature_hash,
            model_digest: file.model_digest,
            dataset_digest: file.dataset_digest,
            hidden: file.hidden,
            epochs_requested: file.epochs_requested,
            best_epoch: file.best_epoch,
            learning_rate: file.learning_rate,
            batch_size: file.batch_size,
            beta1: file.beta1,
            beta2: file.beta2,
            epsilon: file.epsilon,
            train_samples: file.train_samples,
            validation_samples: file.validation_samples,
            test_samples: file.test_samples,
            train_loss: file.train_loss,
            validation_loss: file.validation_loss,
            test_loss: file.test_loss,
            validation_loss_history: file.validation_loss_history,
        };
        report.check()?;
        Ok(report)
    }
}

fn first_min_index(values: &[f32]) -> Result<usize, TrainError> {
    let mut best_index = 0usize;
    let mut best_value = *values.first().ok_or(TrainError::BadConfig(
        "длина истории validation не равна числу эпох",
    ))?;
    if !best_value.is_finite() {
        return Err(TrainError::NonFinite {
            split: "validation_loss_history",
            index: 0,
        });
    }
    for (index, value) in values.iter().enumerate().skip(1) {
        if !value.is_finite() {
            return Err(TrainError::NonFinite {
                split: "validation_loss_history",
                index,
            });
        }
        if *value < best_value {
            best_value = *value;
            best_index = index;
        }
    }
    Ok(best_index)
}

/// Разобранный набор. Группы уже отделены и проверены.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedDataset {
    pub signature: [f32; FEATURE_DIM],
    pub signature_hash: String,
    pub train: Vec<[f32; FEATURE_DIM]>,
    pub validation: Vec<[f32; FEATURE_DIM]>,
    pub test: Vec<[f32; FEATURE_DIM]>,
    pub config: TrainConfig,
}

impl PreparedDataset {
    pub fn splits(&self) -> FeatureSplits<'_> {
        FeatureSplits {
            train: &self.train,
            validation: &self.validation,
            test: &self.test,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetFile {
    schema_version: u32,
    feature_version: u32,
    signature_hash: String,
    signature: Vec<f32>,
    #[serde(default)]
    hidden: Option<usize>,
    #[serde(default)]
    epochs: Option<u32>,
    #[serde(default)]
    learning_rate: Option<f32>,
    #[serde(default)]
    batch_size: Option<usize>,
    #[serde(default)]
    beta1: Option<f32>,
    #[serde(default)]
    beta2: Option<f32>,
    #[serde(default)]
    epsilon: Option<f32>,
    train: Vec<Vec<f32>>,
    validation: Vec<Vec<f32>>,
    test: Vec<Vec<f32>>,
}

/// Разбор JSON набора. `max_bytes` позволяет тесту проверить предел без огромного файла.
pub fn parse_dataset_with_limit(
    text: &str,
    max_bytes: usize,
) -> Result<PreparedDataset, TrainError> {
    ensure_text_limit(text.len(), max_bytes)?;
    let file: DatasetFile =
        serde_json::from_str(text).map_err(|err| TrainError::Json(err.to_string()))?;
    if file.schema_version != SCHEMA_VERSION {
        return Err(TrainError::SchemaMismatch {
            expected: SCHEMA_VERSION,
            actual: file.schema_version,
        });
    }
    if file.feature_version != FEATURE_VERSION {
        return Err(TrainError::FeatureVersionMismatch {
            expected: FEATURE_VERSION,
            actual: file.feature_version,
        });
    }
    if !hash_is_well_formed(&file.signature_hash) {
        return Err(TrainError::BadSignatureHash);
    }
    let computed = signature_hash_hex(&file.signature)?;
    if computed != file.signature_hash {
        return Err(TrainError::SignatureHashMismatch);
    }
    let mut signature = [0.0f32; FEATURE_DIM];
    signature.copy_from_slice(&file.signature);
    let mut config = TrainConfig::default();
    if let Some(value) = file.hidden {
        config.hidden = value;
    }
    if let Some(value) = file.epochs {
        config.epochs = value;
    }
    if let Some(value) = file.learning_rate {
        config.learning_rate = value;
    }
    if let Some(value) = file.batch_size {
        config.batch_size = value;
    }
    if let Some(value) = file.beta1 {
        config.beta1 = value;
    }
    if let Some(value) = file.beta2 {
        config.beta2 = value;
    }
    if let Some(value) = file.epsilon {
        config.epsilon = value;
    }
    config.validate()?;
    let train = take_split("train", file.train)?;
    let validation = take_split("validation", file.validation)?;
    let test = take_split("test", file.test)?;
    if config.batch_size > train.len() {
        return Err(TrainError::BadConfig(
            "размер батча больше обучающей группы",
        ));
    }
    let prepared = PreparedDataset {
        signature,
        signature_hash: computed,
        train,
        validation,
        test,
        config,
    };
    validate_splits(prepared.splits())?;
    Ok(prepared)
}

pub fn parse_dataset(text: &str) -> Result<PreparedDataset, TrainError> {
    parse_dataset_with_limit(text, MAX_DATASET_BYTES as usize)
}

fn take_split(
    name: &'static str,
    rows: Vec<Vec<f32>>,
) -> Result<Vec<[f32; FEATURE_DIM]>, TrainError> {
    if rows.is_empty() {
        return Err(TrainError::EmptySplit(name));
    }
    if rows.len() > MAX_SAMPLES_PER_SPLIT {
        return Err(TrainError::TooManySamples {
            split: name,
            count: rows.len(),
            max: MAX_SAMPLES_PER_SPLIT,
        });
    }
    let mut out = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        if row.len() != FEATURE_DIM {
            return Err(TrainError::BadWidth {
                split: name,
                index,
                width: row.len(),
            });
        }
        if row.iter().any(|value| !value.is_finite()) {
            return Err(TrainError::NonFinite { split: name, index });
        }
        let mut sample = [0.0f32; FEATURE_DIM];
        sample.copy_from_slice(&row);
        out.push(sample);
    }
    Ok(out)
}

fn ensure_text_limit(len: usize, max_bytes: usize) -> Result<(), TrainError> {
    if len > max_bytes {
        Err(TrainError::TooLarge {
            bytes: len as u64,
            max: max_bytes as u64,
        })
    } else {
        Ok(())
    }
}

/// Читает файл только если метаданные и фактическая длина не выше предела.
pub fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, TrainError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| TrainError::Io(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| TrainError::Io(error.to_string()))?;
    if !metadata.is_file() {
        return Err(TrainError::Io("ожидается обычный файл".into()));
    }
    if metadata.len() > max_bytes {
        return Err(TrainError::TooLarge {
            bytes: metadata.len(),
            max: max_bytes,
        });
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| TrainError::Io(error.to_string()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(TrainError::TooLarge {
            bytes: bytes.len() as u64,
            max: max_bytes,
        });
    }
    Ok(bytes)
}

/// Разные написания одного пути не разрешают затереть исходный набор.
pub fn ensure_distinct_paths(paths: &[&Path]) -> Result<(), TrainError> {
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        let normalized = match std::fs::canonicalize(path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                let name = path
                    .file_name()
                    .ok_or_else(|| TrainError::Io("путь без имени файла".into()))?;
                std::fs::canonicalize(parent)
                    .map_err(|error| TrainError::Io(error.to_string()))?
                    .join(name)
            }
            Err(error) => return Err(TrainError::Io(error.to_string())),
        };
        #[cfg(windows)]
        let normalized = PathBuf::from(normalized.to_string_lossy().to_lowercase());
        if !seen.insert(normalized) {
            return Err(TrainError::Io(
                "пути набора, модели и отчета должны различаться".into(),
            ));
        }
    }
    Ok(())
}

pub fn load_dataset_path(path: &Path) -> Result<PreparedDataset, TrainError> {
    let bytes = read_bounded_file(path, MAX_DATASET_BYTES)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| TrainError::Json("файл не utf-8".to_string()))?;
    parse_dataset(text)
}

/// Запись через временный файл в том же каталоге и `rename`.
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), TrainError> {
    let parent = path
        .parent()
        .filter(|item| !item.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| TrainError::Io("путь без имени файла".to_string()))?;
    let unique = rand::random::<u128>();
    let tmp: PathBuf = parent.join(format!(
        ".{}.{}.{unique:032x}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|error| TrainError::Io(error.to_string()))?;
    let write_result = (|| -> Result<(), TrainError> {
        file.write_all(bytes)
            .map_err(|err| TrainError::Io(err.to_string()))?;
        file.sync_all()
            .map_err(|err| TrainError::Io(err.to_string()))?;
        Ok(())
    })();
    drop(file);
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(TrainError::Io(err.to_string()));
    }
    Ok(())
}

/// Пишет модель и отчет. Каждый файл появляется через rename.
/// Если второй rename не удался, первая публикация уже видна: это не одна транзакция.
pub fn publish_model_and_evaluation(
    model_path: &Path,
    model_json: &str,
    eval_path: &Path,
    eval_json: &str,
) -> Result<(), TrainError> {
    ensure_distinct_paths(&[model_path, eval_path])?;
    let model = TrainedEncoder::from_json(model_json)?;
    let report = TrainEvaluation::from_json(eval_json)?;
    if report.model_digest != model.digest()?
        || report.signature_hash != model.signature_hash
        || report.hidden != model.hidden
    {
        return Err(TrainError::BadSignature(
            "отчет не соответствует весам модели",
        ));
    }
    write_bytes_atomic(model_path, model_json.as_bytes())?;
    if let Err(err) = write_bytes_atomic(eval_path, eval_json.as_bytes()) {
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neural::{encode_features, TrafficStats};

    fn signature_from(seed: f32) -> [f32; FEATURE_DIM] {
        let mut signature = [0.0f32; FEATURE_DIM];
        for index in 0..FEATURE_DIM {
            signature[index] = ((index as f32 + 1.0) * seed).sin() * 0.5 + 0.25;
        }
        signature
    }

    fn manifold(index: u32) -> [f32; FEATURE_DIM] {
        let z = (index as f32 * 0.31).sin();
        let mut sample = [0.0f32; FEATURE_DIM];
        for feature in 0..FEATURE_DIM {
            let direction = if feature % 2 == 0 { 0.35 } else { -0.35 };
            sample[feature] = 0.5 + direction * z;
        }
        sample
    }

    fn collect(start: u32, count: usize) -> Vec<[f32; FEATURE_DIM]> {
        (start..start + count as u32).map(manifold).collect()
    }

    fn fit_config() -> TrainConfig {
        TrainConfig {
            hidden: DEFAULT_HIDDEN,
            epochs: 60,
            learning_rate: 2.0e-2,
            batch_size: 16,
            ..TrainConfig::default()
        }
    }

    fn mean_vector(samples: &[[f32; FEATURE_DIM]]) -> [f32; FEATURE_DIM] {
        let mut mean = [0.0f32; FEATURE_DIM];
        for sample in samples {
            for feature in 0..FEATURE_DIM {
                mean[feature] += sample[feature];
            }
        }
        let scale = 1.0 / samples.len() as f32;
        for value in &mut mean {
            *value *= scale;
        }
        mean
    }

    fn baseline_mse(mean: &[f32; FEATURE_DIM], samples: &[[f32; FEATURE_DIM]]) -> f32 {
        let mut acc = 0.0f32;
        for sample in samples {
            acc += mse_pair(sample, mean);
        }
        acc / samples.len() as f32
    }

    #[test]
    fn signature_hash_is_blake3_of_le_f32() {
        let signature = signature_from(0.17);
        let hex = signature_hash_hex(&signature).unwrap();
        let bytes: Vec<u8> = signature
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(hex, blake3::hash(&bytes).to_hex().to_string());
        assert!(hash_is_well_formed(&hex));
        let mut bad = signature;
        bad[0] = f32::NAN;
        assert!(matches!(
            signature_hash_hex(&bad),
            Err(TrainError::BadSignature(_))
        ));
    }

    #[test]
    fn initialization_is_deterministic_and_signature_dependent() {
        let left = signature_from(0.2);
        let right = signature_from(0.8);
        let a = TrainedEncoder::initialize(&left, DEFAULT_HIDDEN).unwrap();
        let b = TrainedEncoder::initialize(&left, DEFAULT_HIDDEN).unwrap();
        let c = TrainedEncoder::initialize(&right, DEFAULT_HIDDEN).unwrap();
        let wide = TrainedEncoder::initialize(&left, DEFAULT_HIDDEN_WIDE).unwrap();
        assert_eq!(a.w1, b.w1);
        assert_eq!(a.b2, b.b2);
        assert_ne!(a.w1, c.w1);
        assert_eq!(wide.hidden, 32);
        assert_eq!(wide.w1.len(), 32 * FEATURE_DIM);
        assert!(a.w1.iter().all(|value| value.is_finite()));
        assert!(matches!(
            TrainedEncoder::initialize(&left, 0),
            Err(TrainError::HiddenOutOfRange { hidden: 0 })
        ));
        assert!(matches!(
            TrainedEncoder::initialize(&left, MAX_HIDDEN + 1),
            Err(TrainError::HiddenOutOfRange { .. })
        ));
    }

    #[test]
    fn backprop_matches_finite_difference() {
        let mut model = TrainedEncoder::initialize(&signature_from(0.3), 4).unwrap();
        for (index, value) in model.w1.iter_mut().enumerate() {
            *value = 0.05 + (index as f32) * 0.001;
        }
        for value in &mut model.b1 {
            *value = 0.02;
        }
        for (index, value) in model.w2.iter_mut().enumerate() {
            *value = 0.03 - (index as f32) * 0.0007;
        }
        model.b2 = vec![0.01; FEATURE_DIM];
        let sample = manifold(7);
        let grads = mean_grads(&model, &[sample]).unwrap();
        let probe = |mutate: &mut dyn FnMut(&mut TrainedEncoder, f32)| {
            let eps = 1.0e-3f32;
            let mut plus = model.clone();
            mutate(&mut plus, eps);
            let mut minus = model.clone();
            mutate(&mut minus, -eps);
            let loss_plus = mse_pair(&sample, &forward(&plus, &sample));
            let loss_minus = mse_pair(&sample, &forward(&minus, &sample));
            (loss_plus - loss_minus) / (2.0 * eps)
        };
        let numeric_w1 = probe(&mut |encoder, delta| encoder.w1[3] += delta);
        let numeric_b1 = probe(&mut |encoder, delta| encoder.b1[1] += delta);
        let numeric_w2 = probe(&mut |encoder, delta| encoder.w2[5] += delta);
        let numeric_b2 = probe(&mut |encoder, delta| encoder.b2[9] += delta);
        assert!(
            (numeric_w1 - grads.w1[3]).abs() < 2.0e-3,
            "{numeric_w1} vs {}",
            grads.w1[3]
        );
        assert!(
            (numeric_b1 - grads.b1[1]).abs() < 2.0e-3,
            "{numeric_b1} vs {}",
            grads.b1[1]
        );
        assert!(
            (numeric_w2 - grads.w2[5]).abs() < 2.0e-3,
            "{numeric_w2} vs {}",
            grads.w2[5]
        );
        assert!(
            (numeric_b2 - grads.b2[9]).abs() < 2.0e-3,
            "{numeric_b2} vs {}",
            grads.b2[9]
        );
    }

    #[test]
    fn held_out_reconstruction_beats_train_mean_and_init() {
        let train = collect(0, 96);
        let validation = collect(400, 32);
        let test = collect(800, 32);
        assert_disjoint(&train, &validation);
        assert_disjoint(&train, &test);
        assert_disjoint(&validation, &test);
        let signature = signature_from(0.41);
        let config = fit_config();
        let initial = TrainedEncoder::initialize(&signature, config.hidden).unwrap();
        let initial_test = initial.mean_score(&test).unwrap();
        let (model, report) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test,
            },
            &config,
        )
        .unwrap();
        let again = model.mean_score(&test).unwrap();
        let baseline = baseline_mse(&mean_vector(&train), &test);
        let mut spread = 0.0f32;
        let first = model.reconstruct(&test[0]).unwrap();
        for sample in &test {
            let output = model.reconstruct(sample).unwrap();
            for feature in 0..FEATURE_DIM {
                let diff = output[feature] - first[feature];
                spread += diff * diff;
            }
        }
        spread /= (test.len() * FEATURE_DIM) as f32;
        assert_eq!(report.train_samples, 96);
        assert_eq!(report.validation_samples, 32);
        assert_eq!(report.test_samples, 32);
        assert_eq!(report.validation_loss_history.len(), config.epochs as usize);
        assert_eq!(again.to_bits(), report.test_loss.to_bits());
        assert!(
            report.test_loss < initial_test * 0.5,
            "init {initial_test} trained {}",
            report.test_loss
        );
        assert!(
            report.test_loss < baseline * 0.5,
            "baseline {baseline} trained {}",
            report.test_loss
        );
        assert!(
            spread > baseline * 0.25,
            "выход схлопнулся в константу: spread {spread} baseline {baseline}"
        );
        let repeated = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test,
            },
            &config,
        )
        .unwrap();
        assert_eq!(model.w1, repeated.0.w1);
        assert_eq!(model.w2, repeated.0.w2);
        assert_eq!(model.b1, repeated.0.b1);
        assert_eq!(model.b2, repeated.0.b2);
        assert_eq!(report.best_epoch, repeated.1.best_epoch);
        assert_eq!(report.test_loss.to_bits(), repeated.1.test_loss.to_bits());
    }

    #[test]
    fn overflowing_adam_moment_is_reported_instead_of_freezing_learning() {
        let mut parameter = [0.0];
        let mut moment = [0.0];
        let mut second = [0.0];
        let result = apply_tensor(
            &mut parameter,
            &mut moment,
            &mut second,
            &[1.0e30],
            0.01,
            0.9,
            0.999,
            1.0e-8,
            0.1,
            0.001,
            1,
        );
        assert!(matches!(result, Err(TrainError::Diverged { epoch: 1 })));
        assert_eq!(parameter, [0.0]);
    }

    #[test]
    fn test_split_does_not_change_weights_or_selected_epoch() {
        let train = collect(10, 64);
        let validation = collect(500, 24);
        let test_a = collect(900, 24);
        let mut test_b = collect(1400, 24);
        for sample in &mut test_b {
            for value in sample.iter_mut() {
                *value = 0.97;
            }
        }
        let signature = signature_from(0.55);
        let config = TrainConfig {
            epochs: 25,
            ..fit_config()
        };
        let (model_a, report_a) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test_a,
            },
            &config,
        )
        .unwrap();
        let (model_b, report_b) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test_b,
            },
            &config,
        )
        .unwrap();
        assert_eq!(model_a.w1, model_b.w1);
        assert_eq!(model_a.w2, model_b.w2);
        assert_eq!(model_a.b1, model_b.b1);
        assert_eq!(model_a.b2, model_b.b2);
        assert_eq!(report_a.best_epoch, report_b.best_epoch);
        assert_ne!(report_a.dataset_digest, report_b.dataset_digest);
        assert_eq!(
            report_a.validation_loss_history,
            report_b.validation_loss_history
        );
        assert_eq!(report_a.train_loss.to_bits(), report_b.train_loss.to_bits());
        assert_ne!(report_a.test_loss.to_bits(), report_b.test_loss.to_bits());
        let min_index = first_min_index(&report_a.validation_loss_history).unwrap();
        assert_eq!(report_a.best_epoch, (min_index as u32) + 1);
    }

    #[test]
    fn invalid_splits_and_config_are_rejected() {
        let train = collect(0, 8);
        let validation = collect(20, 8);
        let test = collect(40, 8);
        let signature = signature_from(0.12);
        let mut nan_train = train.clone();
        nan_train[2][4] = f32::INFINITY;
        let err = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &nan_train,
                validation: &validation,
                test: &test,
            },
            &TrainConfig {
                batch_size: 4,
                epochs: 1,
                ..fit_config()
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TrainError::NonFinite {
                split: "train",
                index: 2
            }
        ));

        let empty: [[f32; FEATURE_DIM]; 0] = [];
        let err = validate_splits(FeatureSplits {
            train: &train,
            validation: &empty,
            test: &test,
        })
        .unwrap_err();
        assert!(matches!(err, TrainError::EmptySplit("validation")));

        let err = validate_splits(FeatureSplits {
            train: &train,
            validation: &train,
            test: &test,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            TrainError::AliasedSplits {
                left: "train",
                right: "validation"
            }
        ));

        let shared = collect(0, 12);
        let err = validate_splits(FeatureSplits {
            train: &shared[0..8],
            validation: &shared[6..10],
            test: &shared[10..12],
        })
        .unwrap_err();
        assert!(matches!(err, TrainError::AliasedSplits { .. }));
        assert!(validate_splits(FeatureSplits {
            train: &shared[0..4],
            validation: &shared[4..8],
            test: &shared[8..12],
        })
        .is_ok());

        let mut too_many = Vec::with_capacity(MAX_SAMPLES_PER_SPLIT + 1);
        too_many.resize(MAX_SAMPLES_PER_SPLIT + 1, manifold(1));
        let err = validate_splits(FeatureSplits {
            train: &too_many,
            validation: &validation,
            test: &test,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            TrainError::TooManySamples { split: "train", .. }
        ));

        let mut config = fit_config();
        config.epochs = 0;
        assert!(matches!(config.validate(), Err(TrainError::BadConfig(_))));
        config.epochs = MAX_EPOCHS + 1;
        assert!(matches!(config.validate(), Err(TrainError::BadConfig(_))));
        config = fit_config();
        config.learning_rate = f32::NAN;
        assert!(matches!(config.validate(), Err(TrainError::BadConfig(_))));
        config.learning_rate = 0.01;
        config.batch_size = 0;
        assert!(matches!(config.validate(), Err(TrainError::BadConfig(_))));
        config.batch_size = 4;
        config.hidden = MAX_HIDDEN + 1;
        assert!(matches!(
            config.validate(),
            Err(TrainError::HiddenOutOfRange { .. })
        ));
    }

    #[test]
    fn corrupt_model_json_is_rejected_and_roundtrip_keeps_scores() {
        let train = collect(0, 32);
        let validation = collect(100, 16);
        let test = collect(200, 16);
        let signature = signature_from(0.63);
        let config = TrainConfig {
            epochs: 8,
            batch_size: 8,
            ..fit_config()
        };
        let (model, report) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test,
            },
            &config,
        )
        .unwrap();
        let json = model.to_json().unwrap();
        let loaded = TrainedEncoder::from_json(&json).unwrap();
        assert_eq!(loaded.w1, model.w1);
        assert_eq!(loaded.w2, model.w2);
        for sample in test.iter().take(5) {
            assert_eq!(
                model.score(sample).unwrap().to_bits(),
                loaded.score(sample).unwrap().to_bits()
            );
            assert_eq!(
                model.reconstruct(sample).unwrap(),
                loaded.reconstruct(sample).unwrap()
            );
        }
        let eval_json = report.to_json().unwrap();
        let loaded_eval = TrainEvaluation::from_json(&eval_json).unwrap();
        assert_eq!(loaded_eval, report);

        let mut corrupt = json.clone();
        corrupt = corrupt.replacen("\"schema_version\": 1", "\"schema_version\": 2", 1);
        assert!(matches!(
            TrainedEncoder::from_json(&corrupt),
            Err(TrainError::SchemaMismatch { .. })
        ));

        let mut weights = model.clone();
        weights.w1.pop();
        assert!(matches!(
            weights.check_strict(),
            Err(TrainError::WeightCount { name: "w1", .. })
        ));
        weights = model.clone();
        weights.w1[1] = f32::NAN;
        assert!(matches!(
            weights.check_strict(),
            Err(TrainError::NonFiniteWeight {
                name: "w1",
                index: 1
            })
        ));
        weights.hidden = MAX_HIDDEN + 5;
        assert!(matches!(
            weights.check_strict(),
            Err(TrainError::HiddenOutOfRange { .. })
        ));

        let hash = "ab".repeat(32);
        let mut w1 = vec!["0.0"; FEATURE_DIM];
        w1[0] = "1e39";
        let blown = format!(
            "{{\"schema_version\":1,\"feature_version\":1,\"signature_hash\":\"{hash}\",\"hidden\":1,\"w1\":[{}],\"b1\":[0.0],\"w2\":[{}],\"b2\":[{}]}}",
            w1.join(","),
            vec!["0.0"; FEATURE_DIM].join(","),
            vec!["0.0"; FEATURE_DIM].join(",")
        );
        assert!(matches!(
            TrainedEncoder::from_json(&blown),
            Err(TrainError::NonFiniteWeight {
                name: "w1",
                index: 0
            })
        ));

        let extra = json.replacen(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"note\": 1",
            1,
        );
        assert!(matches!(
            TrainedEncoder::from_json(&extra),
            Err(TrainError::Json(_))
        ));
        assert!(matches!(
            TrainedEncoder::from_json(&"x".repeat(MAX_MODEL_JSON_BYTES + 1)),
            Err(TrainError::TooLarge { .. })
        ));

        let mut features = test[0];
        features[3] = f32::NAN;
        assert!(matches!(
            model.score(&features),
            Err(TrainError::NonFinite {
                split: "features",
                ..
            })
        ));
    }

    #[test]
    fn dataset_json_enforces_hash_width_and_limits() {
        let signature = signature_from(0.29);
        let hash = signature_hash_hex(&signature).unwrap();
        let row = |index: u32| serde_json::to_string(&manifold(index).to_vec()).unwrap();
        let train: Vec<String> = (0..8).map(row).collect();
        let validation: Vec<String> = (20..24).map(row).collect();
        let test: Vec<String> = (40..44).map(row).collect();
        let body = format!(
            "{{\"schema_version\":1,\"feature_version\":1,\"signature_hash\":\"{hash}\",\"signature\":{},\"hidden\":16,\"epochs\":2,\"learning_rate\":0.02,\"batch_size\":4,\"train\":[{}],\"validation\":[{}],\"test\":[{}]}}",
            serde_json::to_string(&signature.to_vec()).unwrap(),
            train.join(","),
            validation.join(","),
            test.join(",")
        );
        let prepared = parse_dataset(&body).unwrap();
        assert_eq!(prepared.train.len(), 8);
        assert_eq!(prepared.config.epochs, 2);
        assert_eq!(prepared.config.batch_size, 4);
        let (model, report) =
            TrainedEncoder::train(&prepared.signature, prepared.splits(), &prepared.config)
                .unwrap();
        assert_eq!(report.train_samples, 8);
        assert_eq!(report.test_samples, 4);
        assert_eq!(model.signature_hash, hash);
        assert!(model.mean_score(&prepared.test).unwrap().is_finite());

        let bad_hash = body.replacen(&hash, &"0".repeat(64), 1);
        assert!(matches!(
            parse_dataset(&bad_hash),
            Err(TrainError::SignatureHashMismatch)
        ));
        let short = body.replacen(&train[0], "[0.2,0.3]", 1);
        assert!(matches!(
            parse_dataset(&short),
            Err(TrainError::BadWidth {
                split: "train",
                index: 0,
                ..
            })
        ));
        let nan = body.replacen("0.02", "1e39", 1);
        // 1e39 может попасть в подпись или в образец. Оба пути обязаны отвергнуть документ.
        assert!(parse_dataset(&nan).is_err());
        assert!(matches!(
            parse_dataset_with_limit("{}", 1),
            Err(TrainError::TooLarge { .. })
        ));
        let unknown = body.replacen("\"hidden\":16", "\"hidden\":16,\"extra\":1", 1);
        assert!(matches!(parse_dataset(&unknown), Err(TrainError::Json(_))));
        let empty_test = body.replacen(&format!("\"test\":[{}]", test.join(",")), "\"test\":[]", 1);
        assert!(matches!(
            parse_dataset(&empty_test),
            Err(TrainError::EmptySplit("test"))
        ));
    }

    #[test]
    fn encode_features_windows_are_accepted() {
        let mut windows = Vec::new();
        for seed in 0..48u32 {
            let mut stats = TrafficStats::new();
            for step in 0..36u32 {
                let size = 180 + ((seed * 13 + step * 17) % 900) as u16;
                let iat = 4.0 + ((seed + step) % 30) as f64;
                let entropy = 6.2 + ((step % 7) as f64) * 0.15;
                stats.add_packet(size, iat, entropy, true);
            }
            let features = encode_features(&stats);
            assert!(features.iter().all(|value| value.is_finite()));
            windows.push(features);
        }
        let signature = signature_from(0.33);
        let config = TrainConfig {
            hidden: DEFAULT_HIDDEN_WIDE,
            epochs: 3,
            learning_rate: 0.01,
            batch_size: 8,
            ..TrainConfig::default()
        };
        let (model, report) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &windows[0..24],
                validation: &windows[24..36],
                test: &windows[36..48],
            },
            &config,
        )
        .unwrap();
        assert_eq!(report.train_samples, 24);
        assert_eq!(report.validation_samples, 12);
        assert_eq!(report.test_samples, 12);
        assert!(report.train_loss.is_finite());
        assert!(report.validation_loss.is_finite());
        assert!(report.test_loss.is_finite());
        assert!(model.score(&windows[36]).unwrap().is_finite());
    }

    #[test]
    fn atomic_publish_roundtrip_and_first_min_tie() {
        assert_eq!(first_min_index(&[0.5, 0.2, 0.2, 0.4]).unwrap(), 1);
        let dir = std::env::temp_dir().join(format!(
            "aivpn-neural-train-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let model_path = dir.join("model.json");
        let eval_path = dir.join("eval.json");
        let signature = signature_from(0.15);
        let model = TrainedEncoder::initialize(&signature, 2).unwrap();
        let history = vec![0.4, 0.2];
        let report = TrainEvaluation {
            schema_version: SCHEMA_VERSION,
            feature_version: FEATURE_VERSION,
            signature_hash: model.signature_hash.clone(),
            model_digest: model.digest().unwrap(),
            dataset_digest: "0".repeat(64),
            hidden: model.hidden,
            epochs_requested: 2,
            best_epoch: 2,
            learning_rate: 0.01,
            batch_size: 1,
            beta1: 0.9,
            beta2: 0.999,
            epsilon: 1e-8,
            train_samples: 1,
            validation_samples: 1,
            test_samples: 1,
            train_loss: 0.2,
            validation_loss: 0.2,
            test_loss: 0.25,
            validation_loss_history: history,
        };
        publish_model_and_evaluation(
            &model_path,
            &model.to_json().unwrap(),
            &eval_path,
            &report.to_json().unwrap(),
        )
        .unwrap();
        let loaded = TrainedEncoder::from_json(
            &std::str::from_utf8(
                &read_bounded_file(&model_path, MAX_MODEL_JSON_BYTES as u64).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.w1, model.w1);
        let loaded_eval = TrainEvaluation::from_json(
            &std::str::from_utf8(
                &read_bounded_file(&eval_path, MAX_MODEL_JSON_BYTES as u64).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(loaded_eval.best_epoch, 2);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|item| item.ok())
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_paths_cannot_alias_and_reports_bind_exact_weights() {
        let dir = tempfile::tempdir().unwrap();
        let dataset = dir.path().join("dataset.json");
        std::fs::write(&dataset, b"original").unwrap();
        assert!(ensure_distinct_paths(&[&dataset, &dir.path().join("./dataset.json")]).is_err());
        #[cfg(unix)]
        {
            let alias = dir.path().join("alias");
            std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
            assert!(ensure_distinct_paths(&[&dataset, &alias.join("dataset.json")]).is_err());
        }
        let train = collect(0, 32);
        let validation = collect(100, 16);
        let test = collect(200, 16);
        let signature = signature_from(0.15);
        let (mut model, report) = TrainedEncoder::train(
            &signature,
            FeatureSplits {
                train: &train,
                validation: &validation,
                test: &test,
            },
            &TrainConfig {
                epochs: 2,
                batch_size: 16,
                ..TrainConfig::default()
            },
        )
        .unwrap();
        assert_eq!(report.model_digest, model.digest().unwrap());
        model.b2[0] += 0.1;
        let output = dir.path().join("model.json");
        let evaluation = dir.path().join("evaluation.json");
        assert!(publish_model_and_evaluation(
            &output,
            &model.to_json().unwrap(),
            &evaluation,
            &report.to_json().unwrap()
        )
        .is_err());
        assert!(!output.exists() && !evaluation.exists());
        assert_eq!(std::fs::read(&dataset).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_a_fifo_without_waiting_and_output_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_bounded_file(&fifo, 32).is_err());
        let output = directory.path().join("output");
        write_bytes_atomic(&output, b"model").unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(read_bounded_file(&output, 4).is_err());
        assert_eq!(read_bounded_file(&output, 5).unwrap(), b"model");
    }

    #[test]
    fn finite_but_overflowing_weights_are_rejected() {
        let mut model = TrainedEncoder::initialize(&signature_from(0.15), 16).unwrap();
        let mut encoded: serde_json::Value =
            serde_json::from_str(&model.to_json().unwrap()).unwrap();
        encoded["w1"][0] = serde_json::json!(f32::MAX);
        assert!(TrainedEncoder::from_json(&encoded.to_string()).is_err());
        model.b2[0] = f32::MAX;
        assert!(model.check_strict().is_err());
        assert!(model.score(&[1.0; FEATURE_DIM]).is_err());
        model.w1.fill(0.0);
        model.w2.fill(0.0);
        model.b1.fill(0.0);
        model.b2.fill(0.0);
        assert!(model.check_strict().is_ok());
        assert!(model.score(&[f32::MAX; FEATURE_DIM]).is_err());
    }

    fn assert_disjoint(left: &[[f32; FEATURE_DIM]], right: &[[f32; FEATURE_DIM]]) {
        for lhs in left {
            for rhs in right {
                assert_ne!(lhs, rhs);
            }
        }
    }
}
