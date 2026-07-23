#![cfg_attr(windows, windows_subsystem = "windows")]
mod config;
mod crypto;
mod twofa;
mod vault_store;

use axum::{
    body::Body,
    extract::{Multipart, Path, Query},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use rust_embed::Embed;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Embed)]
#[folder = "frontend/"]
struct Assets;

static LAST_PING: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn session_token(headers: &HeaderMap) -> String {
    headers.get("x-session-token").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}
fn ok(v: Value) -> Response { (StatusCode::OK, Json(v)).into_response() }
fn created(v: Value) -> Response { (StatusCode::CREATED, Json(v)).into_response() }
fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"error": msg}))).into_response()
}
fn require_session(headers: &HeaderMap) -> Result<String, Response> {
    let token = session_token(headers);
    if vault_store::session_exists(&token) { Ok(token) }
    else { Err(err(StatusCode::UNAUTHORIZED, "Locked or session expired")) }
}

async fn serve_index() -> Response { asset("index.html") }
async fn serve_guide() -> Response { asset("guide.html") }
async fn serve_static(Path(path): Path<String>) -> Response { asset(&path) }
fn asset(path: &str) -> Response {
    match Assets::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, mime.as_ref().to_string())],
             f.data.into_owned()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── vault list ──────────────────────────────────────────────────────────────
async fn api_vaults() -> Response {
    let unlocked = vault_store::get_unlocked_paths();
    let result: Vec<Value> = config::get_vaults().into_iter().map(|v| {
        let exists = !v.path.is_empty() && std::path::Path::new(&v.path).exists();
        json!({"id": v.id, "label": v.label, "path": v.path, "shared": v.shared,
            "exists": exists, "unlocked": unlocked.contains(&v.path),
            "has_2fa": !v.path.is_empty() && twofa::has_2fa(&v.path),
            "has_email2fa": !v.path.is_empty() && twofa::has_email2fa(&v.path),
            "has_webauthn": !v.path.is_empty() && twofa::has_webauthn(&v.path)})
    }).collect();
    ok(json!({"vaults": result}))
}

async fn api_add_vault(Json(body): Json<Value>) -> Response {
    let label = match body.get("label").and_then(Value::as_str) {
        Some(l) if !l.is_empty() => l.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "Label required"),
    };
    let v = config::add_vault(&label,
        body.get("shared").and_then(Value::as_bool).unwrap_or(false),
        body.get("path").and_then(Value::as_str).unwrap_or(""));
    created(json!({"id": v.id, "label": v.label, "path": v.path, "shared": v.shared}))
}

async fn api_update_vault(Path(vault_id): Path<String>, Json(body): Json<Value>) -> Response {
    let Some(v_cfg) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    if !v_cfg.path.is_empty() && std::path::Path::new(&v_cfg.path).exists() {
        let pw = body.get("password").and_then(Value::as_str).unwrap_or("");
        if pw.is_empty() { return err(StatusCode::FORBIDDEN, "Vault password required to save changes"); }
        if !vault_store::verify_password(&v_cfg.path, pw) {
            return err(StatusCode::FORBIDDEN, "Incorrect vault password");
        }
    }
    if twofa::has_2fa(&v_cfg.path) {
        let code = body.get("totp_code").and_then(Value::as_str).unwrap_or("");
        if code.is_empty() { return err(StatusCode::FORBIDDEN, "Authenticator code required"); }
        if !twofa::verify_totp(&v_cfg.path, code) {
            return err(StatusCode::UNAUTHORIZED, "Invalid authenticator code");
        }
    }
    match config::update_vault(&vault_id,
        body.get("label").and_then(Value::as_str),
        body.get("path").and_then(Value::as_str)) {
        Some(v) => ok(json!({"id": v.id, "label": v.label, "path": v.path, "shared": v.shared})),
        None => err(StatusCode::NOT_FOUND, "Vault not found"),
    }
}

async fn api_delete_vault(Path(vault_id): Path<String>) -> Response {
    if config::remove_vault(&vault_id) { ok(json!({"ok": true})) }
    else { err(StatusCode::NOT_FOUND, "Vault not found") }
}

async fn api_vault_unlock(Path(vault_id): Path<String>, Json(body): Json<Value>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if v.path.is_empty() { return err(StatusCode::BAD_REQUEST, "Vault path not configured"); }

    if twofa::has_webauthn(&v.path) {
        let cid = body.get("webauthn_credential_id").and_then(Value::as_str).unwrap_or("");
        let cdj = body.get("webauthn_client_data_json").and_then(Value::as_str).unwrap_or("");
        let ad  = body.get("webauthn_auth_data").and_then(Value::as_str).unwrap_or("");
        let sig = body.get("webauthn_signature").and_then(Value::as_str).unwrap_or("");
        if cid.is_empty() || cdj.is_empty() || ad.is_empty() || sig.is_empty() {
            let creds = twofa::get_webauthn_credential_ids(&v.path);
            let ch    = twofa::generate_webauthn_challenge(&v.path);
            return ok(json!({"needs_webauthn": true, "challenge": ch, "rpId": "localhost",
                "allowCredentials": creds.iter().map(|id| json!({"type":"public-key","id":id})).collect::<Vec<_>>(),
                "timeout": 60000, "userVerification": "preferred"}));
        }
        if !twofa::verify_webauthn_assertion(&v.path, cid, cdj, ad, sig) {
            return err(StatusCode::UNAUTHORIZED, "Security key verification failed");
        }
    }

    if twofa::has_email2fa(&v.path) {
        let code = body.get("email_code").and_then(Value::as_str).unwrap_or("");
        if code.is_empty() {
            let email_addr = twofa::get_email2fa_addr(&v.path).unwrap_or_default();
            let otp = twofa::generate_otp(&v.path);
            if let Some(smtp) = config::get_smtp() {
                if !smtp.host.is_empty() {
                    if let Err(e) = twofa::send_otp_email(&smtp, &email_addr, &otp, &v.label) {
                        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Email error: {e}"));
                    }
                }
            }
            let hint = email_addr.rfind('@').map(|at|
                format!("{}***{}", &email_addr[..3.min(email_addr.len())], &email_addr[at..])
            ).unwrap_or(email_addr);
            return ok(json!({"needs_email_otp": true, "email_hint": hint}));
        }
        if !twofa::verify_otp(&v.path, code) {
            return err(StatusCode::UNAUTHORIZED, "Invalid or expired email code");
        }
    }

    if twofa::has_2fa(&v.path) {
        let code = body.get("totp_code").and_then(Value::as_str).unwrap_or("");
        if code.is_empty() {
            return ok(json!({"needs_2fa": true, "has_backup_codes": twofa::has_backup_codes(&v.path)}));
        }
        if code.replace('-', "").len() == 8 && twofa::has_backup_codes(&v.path) {
            if !twofa::use_backup_code(&v.path, code) {
                return err(StatusCode::UNAUTHORIZED, "Invalid or already-used backup code");
            }
        } else if !twofa::verify_totp(&v.path, code) {
            return err(StatusCode::UNAUTHORIZED, "Invalid authenticator code");
        }
    }

    let pw       = body.get("password").and_then(Value::as_str).unwrap_or("");
    let autolock = body.get("autolock").and_then(Value::as_u64).unwrap_or(1800);
    match vault_store::unlock_vault(pw, &v.path, v.shared, autolock) {
        Ok(token) => ok(json!({"token": token, "vault_id": vault_id})),
        Err(e)    => err(StatusCode::UNAUTHORIZED, &e.to_string()),
    }
}

async fn api_vault_create(Path(vault_id): Path<String>, Json(body): Json<Value>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if v.path.is_empty() { return err(StatusCode::BAD_REQUEST, "Vault path not configured"); }
    if std::path::Path::new(&v.path).exists() {
        return err(StatusCode::CONFLICT, "Vault already exists, use unlock");
    }
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("");
    if pw.len() < 8 { return err(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"); }
    if !pw.chars().any(|c| c.is_ascii_digit()) {
        return err(StatusCode::BAD_REQUEST, "Password must contain at least one number");
    }
    if !pw.chars().any(|c| !c.is_alphanumeric()) {
        return err(StatusCode::BAD_REQUEST, "Password must contain at least one special character");
    }
    let autolock = body.get("autolock").and_then(Value::as_u64).unwrap_or(1800);
    match vault_store::create_vault(pw, &v.path, v.shared, autolock) {
        Ok(token) => ok(json!({"token": token, "vault_id": vault_id})),
        Err(e)    => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_vault_lock(Path(_): Path<String>, headers: HeaderMap) -> Response {
    let token = session_token(&headers);
    if !token.is_empty() { vault_store::lock_vault(&token); }
    ok(json!({"ok": true}))
}

async fn api_vault_set_path(Path(vault_id): Path<String>, Json(body): Json<Value>) -> Response {
    if config::get_vault(&vault_id).is_none() { return err(StatusCode::NOT_FOUND, "Vault not found"); }
    let p = body.get("path").and_then(Value::as_str).unwrap_or("").trim().to_string();
    config::set_vault_path(&vault_id, &p);
    ok(json!({"ok": true, "path": p}))
}

// ── 2FA — TOTP ──────────────────────────────────────────────────────────────
async fn api_2fa_status(Path(vault_id): Path<String>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    ok(json!({"enabled": !v.path.is_empty() && twofa::has_2fa(&v.path)}))
}

async fn api_2fa_setup(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    let secret = twofa::generate_secret();
    let uri    = twofa::totp_uri(&secret, &v.label);
    let svg    = twofa::qr_svg(&uri);
    ok(json!({"secret": secret, "uri": uri, "qr_svg": svg}))
}

async fn api_2fa_enable(Path(vault_id): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    let secret = body.get("secret").and_then(Value::as_str).unwrap_or("");
    let code   = body.get("code").and_then(Value::as_str).unwrap_or("");
    let Ok(totp) = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30,
        totp_rs::Secret::Encoded(secret.to_string()).to_bytes().unwrap_or_default())
    else { return err(StatusCode::BAD_REQUEST, "Invalid TOTP secret"); };
    if !totp.check_current(code.trim()).unwrap_or(false) {
        return err(StatusCode::BAD_REQUEST, "Code incorrect — check your authenticator app");
    }
    twofa::enable_2fa(&v.path, secret);
    ok(json!({"ok": true}))
}

async fn api_2fa_disable(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    twofa::disable_2fa(&v.path);
    twofa::delete_backup_codes(&v.path);
    ok(json!({"ok": true}))
}

async fn api_backup_codes_gen(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    let codes = twofa::generate_backup_codes(&v.path);
    let n = codes.len();
    ok(json!({"codes": codes, "count": n}))
}

async fn api_backup_codes_status(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    ok(json!({"has_codes": twofa::has_backup_codes(&v.path),
        "remaining": twofa::backup_codes_remaining(&v.path)}))
}

// ── 2FA — Email ─────────────────────────────────────────────────────────────
async fn api_email2fa_setup(Path(vault_id): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    let email = body.get("email").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if email.is_empty() || !email.contains('@') {
        return err(StatusCode::BAD_REQUEST, "Valid email address required");
    }
    twofa::setup_email2fa(&v.path, &email);
    ok(json!({"ok": true, "email": email}))
}

async fn api_email2fa_status(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    ok(json!({"enabled": twofa::has_email2fa(&v.path),
        "email": twofa::get_email2fa_addr(&v.path).unwrap_or_default()}))
}

async fn api_email2fa_disable(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    twofa::disable_email2fa(&v.path);
    ok(json!({"ok": true}))
}

// ── 2FA — WebAuthn ──────────────────────────────────────────────────────────
async fn api_webauthn_status(Path(vault_id): Path<String>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Vault not found");
    };
    ok(json!({"enabled": !v.path.is_empty() && twofa::has_webauthn(&v.path),
        "credential_ids": if v.path.is_empty() { vec![] } else { twofa::get_webauthn_credential_ids(&v.path) }}))
}

async fn api_webauthn_reg_begin(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    let ch = twofa::generate_webauthn_challenge(&v.path);
    ok(json!({"challenge": ch, "rp": {"id": "localhost", "name": "Password Manager"},
        "user": {"id": vault_id, "name": v.label, "displayName": v.label},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "timeout": 60000, "attestation": "none",
        "authenticatorSelection": {"userVerification": "preferred", "residentKey": "preferred"}}))
}

async fn api_webauthn_reg_finish(Path(vault_id): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if twofa::process_webauthn_registration(&v.path,
        body.get("id").and_then(Value::as_str).unwrap_or(""),
        &body.get("response").cloned().unwrap_or(json!({}))) {
        ok(json!({"ok": true}))
    } else {
        err(StatusCode::BAD_REQUEST, "Security key registration failed. Try again.")
    }
}

async fn api_webauthn_disable(Path(vault_id): Path<String>, headers: HeaderMap) -> Response {
    let Ok(_) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    twofa::disable_webauthn(&v.path);
    ok(json!({"ok": true}))
}

async fn api_webauthn_auth_begin(Path(vault_id): Path<String>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if !twofa::has_webauthn(&v.path) {
        return err(StatusCode::BAD_REQUEST, "No security key registered");
    }
    let ch    = twofa::generate_webauthn_challenge(&v.path);
    let creds = twofa::get_webauthn_credential_ids(&v.path);
    ok(json!({"challenge": ch, "rpId": "localhost",
        "allowCredentials": creds.iter().map(|id| json!({"type":"public-key","id":id})).collect::<Vec<_>>(),
        "timeout": 60000, "userVerification": "preferred"}))
}

// ── SMTP ─────────────────────────────────────────────────────────────────────
async fn api_smtp_get() -> Response {
    match config::get_smtp() {
        None => ok(json!({})),
        Some(c) => ok(json!({"host": c.host, "port": c.port, "username": c.username,
            "from_addr": c.from_addr,
            "password": if c.password.is_empty() { "" } else { "••••••••" }})),
    }
}

async fn api_smtp_set(Json(body): Json<Value>) -> Response {
    let e = config::get_smtp().unwrap_or_default();
    let new_pw = body.get("password").and_then(Value::as_str).unwrap_or("");
    config::set_smtp(config::SmtpConfig {
        host:      body.get("host").and_then(Value::as_str).unwrap_or(&e.host).to_string(),
        port:      body.get("port").and_then(Value::as_u64).unwrap_or(e.port as u64) as u16,
        username:  body.get("username").and_then(Value::as_str).unwrap_or(&e.username).to_string(),
        from_addr: body.get("from_addr").and_then(Value::as_str).unwrap_or(&e.from_addr).to_string(),
        password:  if !new_pw.is_empty() && new_pw != "••••••••" { new_pw.to_string() } else { e.password },
    });
    ok(json!({"ok": true}))
}

async fn api_smtp_test(Json(body): Json<Value>) -> Response {
    let to = body.get("to").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if to.is_empty() { return err(StatusCode::BAD_REQUEST, "Recipient email required"); }
    let Some(smtp) = config::get_smtp() else { return err(StatusCode::BAD_REQUEST, "SMTP not configured"); };
    if smtp.host.is_empty() { return err(StatusCode::BAD_REQUEST, "SMTP not configured"); }
    match twofa::send_otp_email(&smtp, &to, "123456", "Test") {
        Ok(_) => ok(json!({"ok": true})),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ── Export / Import ──────────────────────────────────────────────────────────
async fn api_export(headers: HeaderMap, Query(params): Query<HashMap<String, String>>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    if params.get("format").map(|s| s.as_str()).unwrap_or("csv") == "csv" {
        match vault_store::export_csv(&token) {
            Some(csv) => (StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                 (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=vault_export.csv".to_string())],
                csv).into_response(),
            None => err(StatusCode::UNAUTHORIZED, "Session expired"),
        }
    } else {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let data = serde_json::to_string_pretty(&json!({
            "entries":    vault_store::get_entries(&token).unwrap_or_default(),
            "categories": vault_store::get_categories(&token).unwrap_or_default(),
            "exported_at": ts,
        })).unwrap_or_default();
        (StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string()),
             (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=vault_export.json".to_string())],
            data).into_response()
    }
}

async fn api_import(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let mut imported = 0usize;
    let mut errors: Vec<String> = vec![];
    for e in body.get("entries").and_then(Value::as_array).cloned().unwrap_or_default() {
        let entry = json!({
            "title":       e.get("title").or(e.get("name")).and_then(Value::as_str).unwrap_or("Imported"),
            "username":    e.get("username").or(e.get("email")).and_then(Value::as_str).unwrap_or(""),
            "password":    e.get("password").and_then(Value::as_str).unwrap_or(""),
            "url":         e.get("url").and_then(Value::as_str).unwrap_or(""),
            "notes":       e.get("notes").and_then(Value::as_str).unwrap_or(""),
            "category":    e.get("category").or(e.get("type")).and_then(Value::as_str).unwrap_or("other"),
            "favorite":    e.get("favorite").or(e.get("starred")).and_then(Value::as_bool).unwrap_or(false),
            "expiry_date": e.get("expiry_date").and_then(Value::as_str).unwrap_or(""),
        });
        match vault_store::add_entry(&token, &entry) {
            Ok(_)  => imported += 1,
            Err(e) => { if errors.len() < 5 { errors.push(e.to_string()); } }
        }
    }
    ok(json!({"imported": imported, "errors": errors}))
}

// ── Entries ───────────────────────────────────────────────────────────────────
async fn api_entries(headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let result: Vec<Value> = vault_store::get_entries(&token).unwrap_or_default()
        .into_iter().map(|mut e| {
            if let Some(sec) = e.get("totp_secret").and_then(Value::as_str).map(|s| s.to_string()) {
                if !sec.is_empty() {
                    if let Some(obj) = e.as_object_mut() { obj.insert("totp".into(), twofa::current_totp(&sec)); }
                }
            }
            e
        }).collect();
    ok(json!({"entries": result}))
}

async fn api_add_entry(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    if body.get("title").and_then(Value::as_str).unwrap_or("").is_empty() {
        return err(StatusCode::BAD_REQUEST, "Title is required");
    }
    match vault_store::add_entry(&token, &body) {
        Ok(e)  => created(e),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    }
}

async fn api_update_entry(Path(eid): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    match vault_store::update_entry(&token, &eid, &body) {
        Ok(Some(e)) => ok(e),
        Ok(None)    => err(StatusCode::NOT_FOUND, "Entry not found"),
        Err(e)      => err(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    }
}

async fn api_delete_entry(Path(eid): Path<String>, headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    match vault_store::delete_entry(&token, &eid) {
        Ok(true)  => ok(json!({"ok": true})),
        Ok(false) => err(StatusCode::NOT_FOUND, "Entry not found"),
        Err(e)    => err(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    }
}

// ── Categories ───────────────────────────────────────────────────────────────
async fn api_get_cats(headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    ok(json!({"categories": vault_store::get_categories(&token).unwrap_or_default()}))
}

async fn api_add_cat(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    if body.get("label").and_then(Value::as_str).unwrap_or("").is_empty() {
        return err(StatusCode::BAD_REQUEST, "Label required");
    }
    match vault_store::add_category(&token, &body) {
        Ok(c)  => created(c),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_update_cat(Path(cid): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    match vault_store::update_category(&token, &cid, &body) {
        Ok(Some(c)) => ok(c),
        Ok(None)    => err(StatusCode::NOT_FOUND, "Category not found"),
        Err(e)      => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_delete_cat(Path(cid): Path<String>, headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    match vault_store::delete_category(&token, &cid) {
        Ok(true)  => ok(json!({"ok": true})),
        Ok(false) => err(StatusCode::BAD_REQUEST, "Cannot delete built-in category or not found"),
        Err(e)    => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ── Health / Settings / Utilities ────────────────────────────────────────────
async fn api_health(headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    match vault_store::health_report(&token) {
        Some(r) => ok(r),
        None    => err(StatusCode::UNAUTHORIZED, "Session expired"),
    }
}

async fn api_set_autolock(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let _ = vault_store::set_autolock(&token, body.get("seconds").and_then(Value::as_u64).unwrap_or(1800));
    ok(json!({"ok": true}))
}

async fn api_change_pw(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let pw = body.get("new_password").and_then(Value::as_str).unwrap_or("");
    if pw.len() < 8 { return err(StatusCode::BAD_REQUEST, "At least 8 characters required"); }
    match vault_store::change_password(&token, pw) {
        Ok(t)  => ok(json!({"token": t})),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_generate(Json(body): Json<Value>) -> Response {
    let pw = crypto::generate_password(
        body.get("length").and_then(Value::as_u64).unwrap_or(20) as usize,
        body.get("upper").and_then(Value::as_bool).unwrap_or(true),
        body.get("digits").and_then(Value::as_bool).unwrap_or(true),
        body.get("symbols").and_then(Value::as_bool).unwrap_or(true),
        body.get("no_ambiguous").and_then(Value::as_bool).unwrap_or(false),
    );
    let (score, label) = crypto::password_strength(&pw);
    ok(json!({"password": pw, "strength": {"score": score, "label": label}}))
}

async fn api_strength(Json(body): Json<Value>) -> Response {
    let (score, label) = crypto::password_strength(
        body.get("password").and_then(Value::as_str).unwrap_or(""));
    ok(json!({"score": score, "label": label}))
}

async fn api_totp(Json(body): Json<Value>) -> Response {
    ok(twofa::current_totp(body.get("secret").and_then(Value::as_str).unwrap_or("")))
}

// ── Activity / Mtime / Merge / Session / Forgot PW ───────────────────────────
async fn api_vault_activity(Path(_): Path<String>, headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    ok(json!({"log": vault_store::get_activity(&token).unwrap_or_default()}))
}

async fn api_vault_mtime(Path(vault_id): Path<String>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    let mtime = if v.path.is_empty() { 0 } else { vault_store::get_mtime(&v.path).unwrap_or(0) };
    ok(json!({"mtime": mtime}))
}

async fn api_vault_merge(Path(_): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    let src_id = body.get("source_vault_id").and_then(Value::as_str).unwrap_or("");
    let src_pw = body.get("source_password").and_then(Value::as_str).unwrap_or("");
    if src_id.is_empty() || src_pw.is_empty() {
        return err(StatusCode::BAD_REQUEST, "source_vault_id and source_password required");
    }
    let Some(src) = config::get_vault(src_id) else {
        return err(StatusCode::NOT_FOUND, "Source vault not found");
    };
    match vault_store::merge_vault(&token, &src.path, src_pw) {
        Ok(r)  => ok(r),
        Err(e) => err(StatusCode::UNAUTHORIZED, &e.to_string()),
    }
}

async fn api_session_touch(headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "Locked or session expired");
    };
    ok(json!({"ok": true, "autolock": vault_store::get_autolock(&token).unwrap_or(1800)}))
}

async fn api_forgot_pw_send(Path(vault_id): Path<String>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if !twofa::has_email2fa(&v.path) {
        return err(StatusCode::BAD_REQUEST, "No email 2FA configured for this vault");
    }
    let Some(smtp) = config::get_smtp() else {
        return err(StatusCode::BAD_REQUEST, "SMTP not configured");
    };
    if smtp.host.is_empty() { return err(StatusCode::BAD_REQUEST, "SMTP not configured"); }
    let email = twofa::get_email2fa_addr(&v.path).unwrap_or_default();
    let otp   = twofa::generate_otp(&v.path);
    if let Err(e) = twofa::send_otp_email(&smtp, &email, &otp, &v.label) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to send email: {e}"));
    }
    let hint = email.rfind('@').map(|at|
        format!("{}***{}", &email[..3.min(email.len())], &email[at..])
    ).unwrap_or(email);
    ok(json!({"ok": true, "email_hint": hint}))
}

async fn api_forgot_pw_verify(Path(vault_id): Path<String>, Json(body): Json<Value>) -> Response {
    let Some(v) = config::get_vault(&vault_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown vault");
    };
    if twofa::verify_otp(&v.path, body.get("code").and_then(Value::as_str).unwrap_or("")) {
        ok(json!({"ok": true, "verified": true}))
    } else {
        err(StatusCode::UNAUTHORIZED, "Invalid or expired code")
    }
}

// ── main ─────────────────────────────────────────────────────────────────────


// ── heartbeat & quit ─────────────────────────────────────────────────────────

async fn api_ping() -> Response {
    LAST_PING.store(now_unix(), Ordering::Relaxed);
    ok(json!({"ok": true}))
}

async fn api_quit() -> Response {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        std::process::exit(0);
    });
    ok(json!({"ok": true}))
}

// ── file entry handlers ───────────────────────────────────────────────────────

async fn api_list_files(headers: HeaderMap) -> Response {
    let Ok(token) = require_session(&headers) else { return err(StatusCode::UNAUTHORIZED, "Locked"); };
    match vault_store::get_file_entries(&token) {
        Some(files) => ok(json!({"files": files})),
        None        => err(StatusCode::UNAUTHORIZED, "Session expired"),
    }
}

async fn api_upload_file(headers: HeaderMap, mut multipart: Multipart) -> Response {
    let Ok(token) = require_session(&headers) else { return err(StatusCode::UNAUTHORIZED, "Locked"); };
    let mut filename  = String::from("file");
    let mut mime_type = String::from("application/octet-stream");
    let mut category  = String::from("other");
    let mut data: Vec<u8> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("file") => {
                filename  = field.file_name().unwrap_or("file").to_string();
                mime_type = field.content_type().unwrap_or("application/octet-stream").to_string();
                if let Ok(bytes) = field.bytes().await { data = bytes.to_vec(); }
            }
            Some("category") => {
                if let Ok(v) = field.text().await { category = v; }
            }
            _ => {}
        }
    }
    if data.is_empty() { return err(StatusCode::BAD_REQUEST, "No file data received"); }
    let safe_name = std::path::Path::new(&filename)
        .file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
    match vault_store::add_file_entry(&token, &safe_name, &data, &mime_type, &category) {
        Ok(entry) => created(json!({"file": entry})),
        Err(e)    => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_download_file(headers: HeaderMap, Path(file_id): Path<String>) -> Response {
    let Ok(token) = require_session(&headers) else { return err(StatusCode::UNAUTHORIZED, "Locked"); };
    match vault_store::get_file_entry_data(&token, &file_id) {
        Some((data, entry)) => {
            let mime = entry["file_mime"].as_str().unwrap_or("application/octet-stream").to_string();
            let name = entry["title"].as_str().unwrap_or("file").to_string();
            axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", name.replace('"',"")))
                .body(Body::from(data))
                .unwrap()
        }
        None => err(StatusCode::NOT_FOUND, "File not found"),
    }
}

async fn api_delete_file(headers: HeaderMap, Path(file_id): Path<String>) -> Response {
    let Ok(token) = require_session(&headers) else { return err(StatusCode::UNAUTHORIZED, "Locked"); };
    match vault_store::delete_entry(&token, &file_id) {
        Ok(true)  => ok(json!({"deleted": true})),
        Ok(false) => err(StatusCode::NOT_FOUND, "File not found"),
        Err(e)    => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn api_rename_file(headers: HeaderMap, Path(file_id): Path<String>, Json(body): Json<Value>) -> Response {
    let Ok(token) = require_session(&headers) else { return err(StatusCode::UNAUTHORIZED, "Locked"); };
    let name = body.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if name.is_empty() { return err(StatusCode::BAD_REQUEST, "Name required"); }
    match vault_store::rename_file_entry(&token, &file_id, &name) {
        Ok(Some(f)) => ok(json!({"file": f})),
        Ok(None)    => err(StatusCode::NOT_FOUND, "File not found"),
        Err(e)      => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}


#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/guide", get(serve_guide))
        .route("/api/vaults", get(api_vaults).post(api_add_vault))
        .route("/api/vaults/:id", put(api_update_vault).delete(api_delete_vault))
        .route("/api/vaults/:id/unlock", post(api_vault_unlock))
        .route("/api/vaults/:id/create", post(api_vault_create))
        .route("/api/vaults/:id/lock",   post(api_vault_lock))
        .route("/api/vaults/:id/path",   put(api_vault_set_path))
        .route("/api/vaults/:id/2fa/status",              get(api_2fa_status))
        .route("/api/vaults/:id/2fa/setup",               post(api_2fa_setup))
        .route("/api/vaults/:id/2fa/enable",              post(api_2fa_enable))
        .route("/api/vaults/:id/2fa/disable",             post(api_2fa_disable))
        .route("/api/vaults/:id/2fa/backup-codes",        post(api_backup_codes_gen))
        .route("/api/vaults/:id/2fa/backup-codes/status", get(api_backup_codes_status))
        .route("/api/vaults/:id/2fa/email/setup",         post(api_email2fa_setup))
        .route("/api/vaults/:id/2fa/email/status",        get(api_email2fa_status))
        .route("/api/vaults/:id/2fa/email/disable",       post(api_email2fa_disable))
        .route("/api/vaults/:id/2fa/webauthn/status",          get(api_webauthn_status))
        .route("/api/vaults/:id/2fa/webauthn/register-begin",  post(api_webauthn_reg_begin))
        .route("/api/vaults/:id/2fa/webauthn/register-finish", post(api_webauthn_reg_finish))
        .route("/api/vaults/:id/2fa/webauthn/disable",         post(api_webauthn_disable))
        .route("/api/vaults/:id/2fa/webauthn/auth-begin",      post(api_webauthn_auth_begin))
        .route("/api/smtp",      get(api_smtp_get).post(api_smtp_set))
        .route("/api/smtp/test", post(api_smtp_test))
        .route("/api/export",    get(api_export))
        .route("/api/import",    post(api_import))
        .route("/api/entries",     get(api_entries).post(api_add_entry))
        .route("/api/entries/:id", put(api_update_entry).delete(api_delete_entry))
        .route("/api/categories",     get(api_get_cats).post(api_add_cat))
        .route("/api/categories/:id", put(api_update_cat).delete(api_delete_cat))
        .route("/api/health",            get(api_health))
        .route("/api/settings/autolock", post(api_set_autolock))
        .route("/api/change-password",   post(api_change_pw))
        .route("/api/generate",          post(api_generate))
        .route("/api/strength",          post(api_strength))
        .route("/api/totp",              post(api_totp))
        .route("/api/vaults/:id/activity",               get(api_vault_activity))
        .route("/api/vaults/:id/mtime",                  get(api_vault_mtime))
        .route("/api/vaults/:id/merge",                  post(api_vault_merge))
        .route("/api/vaults/:id/forgot-password/send",   post(api_forgot_pw_send))
        .route("/api/vaults/:id/forgot-password/verify", post(api_forgot_pw_verify))
        .route("/api/session/touch", post(api_session_touch))
        .route("/api/ping",          post(api_ping))
        .route("/api/quit",          post(api_quit))
        .route("/api/files",              get(api_list_files).post(api_upload_file))
        .route("/api/files/:id/download", get(api_download_file))
        .route("/api/files/:id",          put(api_rename_file).delete(api_delete_file))
        .route("/*path", get(serve_static));

    let addr: SocketAddr = "127.0.0.1:7474".parse().unwrap();
    println!("Secure Vault running at http://127.0.0.1:7474");

    // Open browser after a short delay
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let _ = open::that("http://127.0.0.1:7474");
    });

    // Initialize heartbeat timestamp
    LAST_PING.store(now_unix(), Ordering::Relaxed);

    // Watchdog: exit if no browser ping for 8 seconds (tab/window closed)
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let last = LAST_PING.load(Ordering::Relaxed);
            if now_unix().saturating_sub(last) > 8 {
                std::process::exit(0);
            }
        }
    });

    // Purge expired sessions every 60 seconds
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            vault_store::expire_sessions();
        }
    });

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(_) => {
            // Another instance is already running — bring it to the foreground
            let _ = open::that("http://127.0.0.1:7474");
            return;
        }
    };
    axum::serve(listener, app).await.unwrap();
}
