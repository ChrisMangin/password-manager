//! 2FA: TOTP, backup codes, email OTP, WebAuthn
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use totp_rs::{TOTP, Algorithm, Secret};
use sha2::{Sha256, Digest};
use base64::Engine as _;

fn now() -> f64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64() }

// ── TOTP ───────────────────────────────────────────────────────────────────────
fn twofa_path(vault_path: &str) -> PathBuf { Path::new(vault_path).with_extension("2fa") }

pub fn has_2fa(vault_path: &str) -> bool { twofa_path(vault_path).exists() }

pub fn generate_secret() -> String {
    totp_rs::Secret::generate_secret().to_encoded().to_string()
}

pub fn totp_uri(secret: &str, account: &str) -> String {
    format!("otpauth://totp/Password%20Manager:{account}?secret={secret}&issuer=Password%20Manager")
}

pub fn qr_svg(uri: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::svg;
    let code = QrCode::new(uri.as_bytes()).unwrap_or_else(|_| QrCode::new(b"error").unwrap());
    code.render::<svg::Color>()
        .min_dimensions(200, 200)
        .build()
}

pub fn enable_2fa(vault_path: &str, secret: &str) {
    let _ = std::fs::write(twofa_path(vault_path), serde_json::json!({"secret": secret}).to_string());
}

pub fn disable_2fa(vault_path: &str) { let _ = std::fs::remove_file(twofa_path(vault_path)); }

pub fn get_totp_secret(vault_path: &str) -> Option<String> {
    let p = twofa_path(vault_path);
    if !p.exists() { return None; }
    serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(p).ok()?)
        .ok()?.get("secret")?.as_str().map(|s| s.to_string())
}

pub fn verify_totp(vault_path: &str, code: &str) -> bool {
    let Some(secret) = get_totp_secret(vault_path) else { return true };
    let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, Secret::Encoded(secret).to_bytes().unwrap_or_default()) else { return false };
    totp.check_current(code.trim()).unwrap_or(false)
}

pub fn current_totp(secret: &str) -> serde_json::Value {
    let remaining = 30 - (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() % 30);
    let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, Secret::Encoded(secret.to_string()).to_bytes().unwrap_or_default()) else {
        return serde_json::json!({"code": "------", "remaining": 0, "valid": false});
    };
    let code = totp.generate_current().unwrap_or_else(|_| "------".to_string());
    serde_json::json!({"code": code, "remaining": remaining, "valid": true})
}

// ── backup codes ───────────────────────────────────────────────────────────────
fn bcodes_path(vault_path: &str) -> PathBuf { Path::new(vault_path).with_extension("bcodes") }

pub fn has_backup_codes(vault_path: &str) -> bool { bcodes_path(vault_path).exists() }

pub fn generate_backup_codes(vault_path: &str) -> Vec<String> {
    let codes: Vec<String> = (0..10).map(|_| hex::encode(rand::random::<[u8;4]>()).to_uppercase()).collect();
    let hashed: Vec<String> = codes.iter().map(|c| { let mut h = Sha256::new(); h.update(c.as_bytes()); hex::encode(h.finalize()) }).collect();
    let _ = std::fs::write(bcodes_path(vault_path), serde_json::json!({"codes": hashed}).to_string());
    codes
}

pub fn backup_codes_remaining(vault_path: &str) -> usize {
    let p = bcodes_path(vault_path);
    if !p.exists() { return 0; }
    serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(p).unwrap_or_default())
        .ok().and_then(|v| v["codes"].as_array().map(|a| a.len())).unwrap_or(0)
}

pub fn use_backup_code(vault_path: &str, code: &str) -> bool {
    let p = bcodes_path(vault_path);
    if !p.exists() { return false; }
    let Ok(raw) = std::fs::read_to_string(&p) else { return false };
    let Ok(mut data) = serde_json::from_str::<serde_json::Value>(&raw) else { return false };
    let mut h = Sha256::new(); h.update(code.trim().to_uppercase().as_bytes());
    let hashed = hex::encode(h.finalize());
    if let Some(arr) = data["codes"].as_array_mut() {
        if let Some(pos) = arr.iter().position(|c| c.as_str() == Some(&hashed)) {
            arr.remove(pos);
            let _ = std::fs::write(&p, data.to_string());
            return true;
        }
    }
    false
}

pub fn delete_backup_codes(vault_path: &str) { let _ = std::fs::remove_file(bcodes_path(vault_path)); }

// ── email OTP ──────────────────────────────────────────────────────────────────
fn email2fa_path(vault_path: &str) -> PathBuf { Path::new(vault_path).with_extension("email2fa") }
fn otp_path(vault_path: &str)     -> PathBuf { Path::new(vault_path).with_extension("otp") }

pub fn has_email2fa(vault_path: &str) -> bool { email2fa_path(vault_path).exists() }
pub fn get_email2fa_addr(vault_path: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(email2fa_path(vault_path)).ok()?)
        .ok()?.get("email")?.as_str().map(|s| s.to_string())
}
pub fn setup_email2fa(vault_path: &str, email: &str) {
    let _ = std::fs::write(email2fa_path(vault_path), serde_json::json!({"email": email}).to_string());
}
pub fn disable_email2fa(vault_path: &str) {
    let _ = std::fs::remove_file(email2fa_path(vault_path));
    let _ = std::fs::remove_file(otp_path(vault_path));
}
pub fn generate_otp(vault_path: &str) -> String {
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let _ = std::fs::write(otp_path(vault_path), serde_json::json!({"code": code, "expires": now() + 600.0}).to_string());
    code
}
pub fn verify_otp(vault_path: &str, code: &str) -> bool {
    let p = otp_path(vault_path);
    if !p.exists() { return false; }
    let Ok(raw) = std::fs::read_to_string(&p) else { return false };
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&raw) else { return false };
    if now() > data["expires"].as_f64().unwrap_or(0.0) { let _ = std::fs::remove_file(&p); return false; }
    if data["code"].as_str() == Some(code.trim()) { let _ = std::fs::remove_file(&p); return true; }
    false
}

pub fn send_otp_email(smtp_cfg: &crate::config::SmtpConfig, to: &str, code: &str, vault_label: &str) -> anyhow::Result<()> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::message::header::ContentType;
    let email = Message::builder()
        .from(smtp_cfg.from_addr.parse()?)
        .to(to.parse()?)
        .subject(format!("[Password Manager] Unlock code for {vault_label}"))
        .header(ContentType::TEXT_PLAIN)
        .body(format!("Your one-time code to unlock \"{vault_label}\":\n\n    {code}\n\nThis code expires in 10 minutes."))?;
    let creds = Credentials::new(smtp_cfg.username.clone(), smtp_cfg.password.clone());
    let mailer = SmtpTransport::starttls_relay(&smtp_cfg.host)?.credentials(creds).build();
    mailer.send(&email)?;
    Ok(())
}

// ── WebAuthn (simplified — same logic as Python) ───────────────────────────────
fn webauthn_path(vault_path: &str)   -> PathBuf { Path::new(vault_path).with_extension("webauthn") }
fn webauthn_chal_path(v: &str)       -> PathBuf { Path::new(v).with_extension("webauthn_chal") }

pub fn has_webauthn(vault_path: &str) -> bool { webauthn_path(vault_path).exists() }
pub fn disable_webauthn(vault_path: &str) {
    let _ = std::fs::remove_file(webauthn_path(vault_path));
    let _ = std::fs::remove_file(webauthn_chal_path(vault_path));
}

pub fn generate_webauthn_challenge(vault_path: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let ch = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let _ = std::fs::write(webauthn_chal_path(vault_path), serde_json::json!({"challenge": ch, "expires": now() + 300.0}).to_string());
    ch
}

fn pop_webauthn_challenge(vault_path: &str, challenge: &str) -> bool {
    let p = webauthn_chal_path(vault_path);
    if !p.exists() { return false; }
    let Ok(raw) = std::fs::read_to_string(&p) else { return false };
    let _ = std::fs::remove_file(&p);
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&raw) else { return false };
    if now() > data["expires"].as_f64().unwrap_or(0.0) { return false; }
    data["challenge"].as_str() == Some(challenge)
}

fn decode_b64url(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let s = s.replace('-', "+").replace('_', "/");
    let padded = format!("{}{}", s, "=".repeat((4 - s.len() % 4) % 4));
    Ok(base64::engine::general_purpose::STANDARD.decode(&padded)?)
}

pub fn process_webauthn_registration(vault_path: &str, cred_id: &str, response: &serde_json::Value) -> bool {
    (|| -> anyhow::Result<bool> {
        use sha2::{Sha256, Digest};
        let cdj   = decode_b64url(response["clientDataJSON"].as_str().unwrap_or(""))?;
        let att   = decode_b64url(response["attestationObject"].as_str().unwrap_or(""))?;
        let cd: serde_json::Value = serde_json::from_slice(&cdj)?;
        if cd["type"].as_str() != Some("webauthn.create") { anyhow::bail!("wrong type"); }
        let ch_b64 = cd["challenge"].as_str().unwrap_or("");
        let ch_bytes = decode_b64url(ch_b64)?;
        let stored_raw = std::fs::read_to_string(webauthn_chal_path(vault_path))?;
        let stored: serde_json::Value = serde_json::from_str(&stored_raw)?;
        let _ = std::fs::remove_file(webauthn_chal_path(vault_path));
        if now() > stored["expires"].as_f64().unwrap_or(0.0) { anyhow::bail!("expired"); }
        let expected = decode_b64url(stored["challenge"].as_str().unwrap_or(""))?;
        if ch_bytes != expected { anyhow::bail!("challenge mismatch"); }
        if !cd["origin"].as_str().unwrap_or("").contains("localhost") { anyhow::bail!("bad origin"); }
        // Parse CBOR attestation object
        let att_obj: serde_cbor::Value = serde_cbor::from_slice(&att)?;
        let auth_data = if let serde_cbor::Value::Map(ref m) = att_obj {
            m.get(&serde_cbor::Value::Text("authData".into()))
                .and_then(|v| if let serde_cbor::Value::Bytes(b) = v { Some(b.clone()) } else { None })
                .ok_or_else(|| anyhow::anyhow!("no authData"))?
        } else { anyhow::bail!("invalid attestation object"); };
        if auth_data.len() < 55 { anyhow::bail!("auth_data too short"); }
        let mut h = Sha256::new(); h.update(b"localhost");
        if &auth_data[..32] != h.finalize().as_slice() { anyhow::bail!("rp hash mismatch"); }
        if auth_data[32] & 0x40 == 0 { anyhow::bail!("AT flag not set"); }
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let pk_cbor = &auth_data[55 + cred_id_len..];
        let _ = std::fs::write(webauthn_path(vault_path), serde_json::json!({
            "credential_id": cred_id,
            "public_key": base64::engine::general_purpose::STANDARD.encode(pk_cbor),
            "sign_count": 0,
        }).to_string());
        Ok(true)
    })().unwrap_or(false)
}

pub fn get_webauthn_credential_ids(vault_path: &str) -> Vec<String> {
    if !has_webauthn(vault_path) { return vec![]; }
    serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(webauthn_path(vault_path)).unwrap_or_default())
        .ok().and_then(|v| v["credential_id"].as_str().map(|s| vec![s.to_string()]))
        .unwrap_or_default()
}

pub fn verify_webauthn_assertion(vault_path: &str, cred_id: &str, cdj_b64: &str, ad_b64: &str, sig_b64: &str) -> bool {
    (|| -> anyhow::Result<bool> {
        use sha2::{Sha256, Digest};
        let cred_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(webauthn_path(vault_path))?)?;
        if cred_data["credential_id"].as_str() != Some(cred_id) { anyhow::bail!("cred mismatch"); }
        let cdj = decode_b64url(cdj_b64)?;
        let ad  = decode_b64url(ad_b64)?;
        let sig = decode_b64url(sig_b64)?;
        let cd: serde_json::Value = serde_json::from_slice(&cdj)?;
        if cd["type"].as_str() != Some("webauthn.get") { anyhow::bail!("wrong type"); }
        if !cd["origin"].as_str().unwrap_or("").contains("localhost") { anyhow::bail!("bad origin"); }
        let ch_bytes = decode_b64url(cd["challenge"].as_str().unwrap_or(""))?;
        let stored_raw = std::fs::read_to_string(webauthn_chal_path(vault_path))?;
        let stored: serde_json::Value = serde_json::from_str(&stored_raw)?;
        let _ = std::fs::remove_file(webauthn_chal_path(vault_path));
        if now() > stored["expires"].as_f64().unwrap_or(0.0) { anyhow::bail!("expired"); }
        let expected = decode_b64url(stored["challenge"].as_str().unwrap_or(""))?;
        if ch_bytes != expected { anyhow::bail!("challenge mismatch"); }
        let mut h = Sha256::new(); h.update(b"localhost");
        if &ad[..32] != h.finalize().as_slice() { anyhow::bail!("rp hash"); }
        // Verify ECDSA signature
        let pk_cbor = base64::engine::general_purpose::STANDARD.decode(cred_data["public_key"].as_str().unwrap_or(""))?;
        let cose: serde_cbor::Value = serde_cbor::from_slice(&pk_cbor)?;
        let (x, y) = if let serde_cbor::Value::Map(ref m) = cose {
            let x = m.get(&serde_cbor::Value::Integer(-2))
                .and_then(|v| if let serde_cbor::Value::Bytes(b) = v { Some(b.clone()) } else { None })
                .ok_or_else(|| anyhow::anyhow!("no x coord"))?;
            let y = m.get(&serde_cbor::Value::Integer(-3))
                .and_then(|v| if let serde_cbor::Value::Bytes(b) = v { Some(b.clone()) } else { None })
                .ok_or_else(|| anyhow::anyhow!("no y coord"))?;
            (x, y)
        } else { anyhow::bail!("invalid COSE key"); };
        use p256::ecdsa::{VerifyingKey, signature::Verifier, DerSignature};
        use p256::EncodedPoint;
        let point = EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&x),
            p256::FieldBytes::from_slice(&y), false);
        let vk = VerifyingKey::from_encoded_point(&point)?;
        let mut h2 = Sha256::new(); h2.update(&cdj);
        let verification_data: Vec<u8> = ad.iter().chain(h2.finalize().iter()).cloned().collect();
        let der_sig = DerSignature::try_from(sig.as_slice())?;
        vk.verify(&verification_data, &der_sig)?;
        Ok(true)
    })().unwrap_or(false)
}
