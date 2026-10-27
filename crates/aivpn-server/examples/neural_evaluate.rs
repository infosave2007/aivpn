//! Проверяет зафиксированные веса на отложенных окнах и отдельном корпусе.

use std::path::Path;

use aivpn_server::{
    neural::BakedMaskEncoder,
    neural_training::{
        load_dataset_path, read_bounded_file, TrainedEncoder, FEATURE_DIM, MAX_MODEL_JSON_BYTES,
    },
};

fn scores(
    model: &TrainedEncoder,
    samples: &[[f32; FEATURE_DIM]],
) -> Result<serde_json::Value, String> {
    let mut values: Vec<_> = samples
        .iter()
        .map(|sample| model.score(sample))
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?;
    values.sort_by(f32::total_cmp);
    let mean = values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64;
    let percentile =
        |fraction: f64| values[((values.len() - 1) as f64 * fraction).round() as usize];
    Ok(serde_json::json!({"samples": values.len(), "mean": mean,
        "p50": percentile(0.5), "p95": percentile(0.95), "p99": percentile(0.99),
        "max": values.last().unwrap()}))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&args.len()) {
        return Err("Использование: neural_evaluate DATASET MODEL [OTHER_DATASET]".into());
    }
    let dataset = load_dataset_path(Path::new(&args[0])).map_err(|error| error.to_string())?;
    let bytes = read_bounded_file(Path::new(&args[1]), MAX_MODEL_JSON_BYTES as u64)
        .map_err(|error| error.to_string())?;
    let model =
        TrainedEncoder::from_json(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if model.signature_hash != dataset.signature_hash {
        return Err("Модель не соответствует сигнатуре набора".into());
    }
    let initial = TrainedEncoder::initialize(&dataset.signature, model.hidden)
        .map_err(|error| error.to_string())?;
    let projection = BakedMaskEncoder::from_signature(&dataset.signature, 128);
    let mean: Vec<f64> = (0..FEATURE_DIM)
        .map(|i| {
            dataset
                .train
                .iter()
                .map(|window| window[i] as f64)
                .sum::<f64>()
                / dataset.train.len() as f64
        })
        .collect();
    let constant_test_mean = dataset
        .test
        .iter()
        .map(|window| {
            window
                .iter()
                .zip(&mean)
                .map(|(value, mean)| (*value as f64 - mean).powi(2))
                .sum::<f64>()
                / FEATURE_DIM as f64
        })
        .sum::<f64>()
        / dataset.test.len() as f64;
    let projection_mean = dataset
        .test
        .iter()
        .map(|sample| projection.reconstruction_error(sample) as f64)
        .sum::<f64>()
        / dataset.test.len() as f64;
    let other = if let Some(path) = args.get(2) {
        let other = load_dataset_path(Path::new(path)).map_err(|error| error.to_string())?;
        Some(scores(&model, &other.test)?)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({
            "signature_hash": model.signature_hash,
            "validation": scores(&model, &dataset.validation)?,
            "test": scores(&model, &dataset.test)?,
            "untrained_test": scores(&initial, &dataset.test)?,
            "projection_test_mean": projection_mean,
            "constant_test_mean": constant_test_mean,
            "other_corpus_test": other,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
