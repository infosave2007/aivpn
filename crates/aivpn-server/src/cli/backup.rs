//! CLI handlers for full-server backup export/import (`--export`/`--import`).
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_server::backup::{
    export_server, import_server_with_options, ExportOptions, ImportOptions,
};
use aivpn_server::ServerArgs;
use std::path::PathBuf;

pub(crate) fn handle_export(args: &ServerArgs, output_path: &str) {
    let opts = ExportOptions {
        include_clients: true,
        include_masks: true,
        include_config: true,
        config_path: Some(PathBuf::from(
            args.config.as_deref().unwrap_or("/etc/aivpn/server.json"),
        )),
        mask_dir: Some(PathBuf::from(
            args.mask_dir.as_deref().unwrap_or("/var/lib/aivpn/masks"),
        )),
        clients_db: Some(PathBuf::from(&args.clients_db)),
    };
    match export_server(&opts, std::path::Path::new(output_path)) {
        Ok(()) => println!("✅ Export complete: {}", output_path),
        Err(e) => {
            eprintln!("❌ Export failed: {}", e);
            std::process::exit(1);
        }
    }
}

pub(crate) fn handle_import(archive_path: &str, dry_run: bool, args: &ServerArgs) {
    let opts = ImportOptions {
        config_path: PathBuf::from(args.config.as_deref().unwrap_or("/etc/aivpn/server.json")),
        clients_db: PathBuf::from(&args.clients_db),
        mask_dir: PathBuf::from(args.mask_dir.as_deref().unwrap_or("/var/lib/aivpn/masks")),
    };
    match import_server_with_options(std::path::Path::new(archive_path), &opts, dry_run) {
        Ok(summary) => {
            if summary.dry_run {
                println!("DRY RUN — no files will be written.");
                println!("Backup created:  {}", summary.created_at);
                println!("Backup version:  {}", summary.aivpn_version);
                println!("Components:      {:?}", summary.components);
                println!("Пути восстановления: {:?}", opts);
                println!("Signed:          {}", summary.signed);
                println!("✅ Dry-run complete. No files written.");
            } else {
                println!("✅ Import complete.");
            }
        }
        Err(e) => {
            eprintln!("❌ Import failed: {}", e);
            std::process::exit(1);
        }
    }
}
