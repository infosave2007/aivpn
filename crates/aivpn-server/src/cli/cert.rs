//! CLI handlers for the standalone mTLS CA (`--gen-ca`, `--issue-cert`).
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_server::ServerArgs;

pub(crate) fn handle_gen_ca() {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let priv_hex = hex::encode(sk.to_bytes());
    let pub_hex = hex::encode(pk.to_bytes());
    println!("ca_private_key_hex: {priv_hex}");
    println!("ca_public_key_hex:  {pub_hex}");
    println!();
    println!("Add to server.json:");
    println!("  \"mtls\": {{");
    println!("    \"ca_public_key_hex\": \"{pub_hex}\",");
    println!("    \"required\": false");
    println!("  }}");
    println!();
    println!("Keep ca_private_key_hex offline — it is only needed to run --issue-cert.");
}

pub(crate) fn handle_issue_cert(pubkey_hex: &str, args: &ServerArgs) {
    let pk_bytes: [u8; 32] = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!(
                "error: --issue-cert expects a 64-char hex string (32 bytes), got {pubkey_hex:?}"
            );
            std::process::exit(1);
        }
    };

    let ca_key_hex = match args.ca_key.as_deref() {
        Some(h) => h,
        None => {
            eprintln!("error: --ca-key <HEX> is required with --issue-cert");
            std::process::exit(1);
        }
    };

    let ca_bytes: [u8; 32] = match hex::decode(ca_key_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("error: --ca-key must be a 64-char hex string (32 bytes)");
            std::process::exit(1);
        }
    };

    let expiry_ts = aivpn_common::crypto::current_timestamp_ms() / 1000 + args.days * 86_400;
    let cert = aivpn_server::mtls::issue_cert(pk_bytes, expiry_ts, &ca_bytes);
    let cert_hex = hex::encode(cert.to_bytes());
    println!("{cert_hex}");
    println!();
    println!(
        "cert_hex ({} chars) — pass to aivpn-client via --mtls-cert",
        cert_hex.len()
    );
    println!("or base64-encode for mobile platforms.");
    println!("Expires: {expiry_ts} unix ({} days)", args.days);
}
