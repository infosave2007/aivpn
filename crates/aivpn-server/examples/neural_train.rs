//! neural_train: офлайн-обучение узкого автоэнкодера по готовому JSON.
//!
//! Формат набора, модели и отчета задан в `aivpn_server::neural_training`.
//! Программа не читает PCAP, не меняет боевые пороги и не открывает сеть.
//! Окна признаков, разрез по времени и embargo готовит вызывающий код.
//!
//! Запуск:
//!   cargo run --release -p aivpn-server --example neural_train -- \
//!     dataset.json model.json eval.json
//!
//! Код выхода: 0 запись выполнена, 1 ошибка данных или диска, 2 неверные аргументы.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aivpn_server::neural_training::{
    ensure_distinct_paths, load_dataset_path, publish_model_and_evaluation, TrainedEncoder,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let dataset = args.next();
    let model = args.next();
    let evaluation = args.next();
    if dataset.is_none() || model.is_none() || evaluation.is_none() || args.next().is_some() {
        eprintln!("использование: neural_train <dataset.json> <model.json> <eval.json>");
        return ExitCode::from(2);
    }
    let dataset = PathBuf::from(dataset.unwrap());
    let model = PathBuf::from(model.unwrap());
    let evaluation = PathBuf::from(evaluation.unwrap());
    if dataset == model || dataset == evaluation || model == evaluation {
        eprintln!("ошибка: пути dataset, model и eval должны различаться");
        return ExitCode::from(2);
    }
    match run(&dataset, &model, &evaluation) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ошибка: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(dataset: &Path, model_path: &Path, eval_path: &Path) -> Result<(), String> {
    ensure_distinct_paths(&[dataset, model_path, eval_path]).map_err(|error| error.to_string())?;
    let prepared = load_dataset_path(dataset).map_err(|err| err.to_string())?;
    let (model, report) =
        TrainedEncoder::train(&prepared.signature, prepared.splits(), &prepared.config)
            .map_err(|err| err.to_string())?;
    let model_json = model.to_json().map_err(|err| err.to_string())?;
    let eval_json = report.to_json().map_err(|err| err.to_string())?;
    publish_model_and_evaluation(model_path, &model_json, eval_path, &eval_json)
        .map_err(|err| err.to_string())?;
    println!(
        "samples train={} validation={} test={}",
        report.train_samples, report.validation_samples, report.test_samples
    );
    println!(
        "best_epoch={} epochs={} hidden={}",
        report.best_epoch, report.epochs_requested, report.hidden
    );
    println!(
        "loss train={:.6} validation={:.6} test={:.6}",
        report.train_loss, report.validation_loss, report.test_loss
    );
    println!("signature_hash={}", report.signature_hash);
    println!("model={}", model_path.display());
    println!("eval={}", eval_path.display());
    Ok(())
}
