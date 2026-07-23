//! In-memory session store + vault file I/O.
//! File format is 100% compatible with the Python version.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use once_cell::sync::Lazy;
use crate::crypto;

// ── default categories ─────────────────────────────────────────────────────────
pub fn default_categories() -> Vec<Value> {
    serde_json::from_str(r##"[
        {"id":"login",   "label":"Login",   "icon":"🌐","builtin":true, "color":"#8b5cf6"},
        {"id":"email",   "label":"Email",   "icon":"📧","builtin":true, "color":"#06b6d4"},
        {"id":"banking", "label":"Banking", "icon":"🏦","builtin":true, "color":"#10b981"},
        {"id":"social",  "label":"Social",  "icon":"💬","builtin":true, "color":"#f59e0b"},
        {"id":"work",    "label":"Work",    "icon":"💼","builtin":true, "color":"#6366f1"},
        {"id":"other",   "label":"Other",   "icon":"📁","builtin":true, "color":"#64748b"}
    ]"##).unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Session ────────────────────────────────────────────────────────────────────
pub struct Session {
    pub key:           [u8; 32],
    pub entries:       Vec<Value>,
    pub categories:    Vec<Value>,
    pub settings:      Value,
    pub token:         String,
    pub vault_path:    PathBuf,
    pub is_shared:     bool,
    pub autolock:      u64,
    pub last_activity: u64,
    pub activity_log:  Vec<(u64, String, String)>,
}

impl Session {
    fn new(key: [u8; 32], data: VaultData, vault_path: PathBuf, is_shared: bool, autolock: u64) -> Self {
        let token = URL_SAFE.encode(rand::random::<[u8; 32]>());
        Self {
            key, entries: data.entries, categories: data.categories,
            settings: data.settings, token, vault_path, is_shared,
            autolock, last_activity: now_secs(), activity_log: vec![],
        }
    }
    pub fn touch(&mut self) { self.last_activity = now_secs(); }
    pub fn is_expired(&self) -> bool {
        self.autolock > 0 && (now_secs() - self.last_activity) > self.autolock
    }
    pub fn log(&mut self, action: &str, detail: &str) {
        self.activity_log.push((now_secs(), action.to_string(), detail.to_string()));
        if self.activity_log.len() > 200 { self.activity_log.drain(0..1); }
    }
    pub fn to_data(&self) -> VaultData {
        VaultData { entries: self.entries.clone(), categories: self.categories.clone(), settings: self.settings.clone() }
    }
}

// ── vault file format ──────────────────────────────────────────────────────────
#[derive(Serialize, Deserialize)]
struct VaultFile {
    version:    u32,
    salt:       String,
    nonce:      String,
    ciphertext: String,
}

pub struct VaultData {
    pub entries:    Vec<Value>,
    pub categories: Vec<Value>,
    pub settings:   Value,
}

fn decode_data(path: &Path, key: &[u8; 32]) -> anyhow::Result<VaultData> {
    let raw = std::fs::read_to_string(path)?;
    let vf: VaultFile = serde_json::from_str(&raw)?;
    let nonce = STANDARD.decode(&vf.nonce)?;
    let ct    = STANDARD.decode(&vf.ciphertext)?;
    let pt    = crypto::decrypt(&nonce, &ct, key)?;
    let parsed: Value = serde_json::from_slice(&pt)?;
    // v1 compat: bare array = entries only
    if let Value::Array(arr) = parsed {
        return Ok(VaultData { entries: arr, categories: default_categories(), settings: Value::Object(Default::default()) });
    }
    let obj = parsed.as_object().cloned().unwrap_or_default();
    Ok(VaultData {
        entries:    obj.get("entries").and_then(Value::as_array).cloned().unwrap_or_default(),
        categories: obj.get("categories").and_then(Value::as_array).cloned().unwrap_or_else(default_categories),
        settings:   obj.get("settings").cloned().unwrap_or(Value::Object(Default::default())),
    })
}

fn write_vault(path: &Path, salt: &[u8], key: &[u8; 32], data: &VaultData) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "entries":    data.entries,
        "categories": data.categories,
        "settings":   data.settings,
    });
    let pt = serde_json::to_vec(&payload)?;
    let (nonce, ct) = crypto::encrypt(&pt, key)?;
    let vf = VaultFile {
        version: 2,
        salt:       STANDARD.encode(salt),
        nonce:      STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ct),
    };
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(path, serde_json::to_string_pretty(&vf)?)?;
    Ok(())
}

fn persist(sess: &Session) -> anyhow::Result<()> {
    let raw: VaultFile = serde_json::from_str(&std::fs::read_to_string(&sess.vault_path)?)?;
    let salt = STANDARD.decode(&raw.salt)?;
    write_vault(&sess.vault_path, &salt, &sess.key, &sess.to_data())
}

// ── file lock for shared vaults ────────────────────────────────────────────────
fn lock_path(p: &Path) -> PathBuf { p.with_extension("lock") }

fn acquire_lock(p: &Path) -> bool {
    let lp = lock_path(p);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match std::fs::OpenOptions::new().create_new(true).write(true).open(&lp) {
            Ok(_) => return true,
            Err(_) => {
                if let Ok(meta) = std::fs::metadata(&lp) {
                    if let Ok(modified) = meta.modified() {
                        if modified.elapsed().unwrap_or_default().as_secs() > 30 {
                            let _ = std::fs::remove_file(&lp);
                            continue;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    false
}

fn release_lock(p: &Path) { let _ = std::fs::remove_file(lock_path(p)); }

// ── write-op helper ────────────────────────────────────────────────────────────
fn write_op<F, R>(sess: &mut Session, f: F) -> anyhow::Result<R>
where F: FnOnce(&mut Session) -> R {
    if sess.is_shared {
        if !acquire_lock(&sess.vault_path) {
            anyhow::bail!("Vault is busy, please try again");
        }
        // Re-read entries to pick up concurrent changes
        if let Ok(data) = decode_data(&sess.vault_path, &sess.key) {
            sess.entries = data.entries;
        }
        let result = f(sess);
        let _ = persist(sess);
        release_lock(&sess.vault_path);
        Ok(result)
    } else {
        let result = f(sess);
        persist(sess)?;
        Ok(result)
    }
}

// ── global session store ───────────────────────────────────────────────────────
pub static SESSIONS: Lazy<Mutex<HashMap<String, Session>>> = Lazy::new(|| Mutex::new(HashMap::new()));


// ── public API ─────────────────────────────────────────────────────────────────
pub fn create_vault(password: &str, vault_path: &str, is_shared: bool, autolock: u64) -> anyhow::Result<String> {
    let path = PathBuf::from(vault_path);
    let salt = crypto::new_salt();
    let key  = crypto::derive_key(password, &salt)?;
    let data = VaultData { entries: vec![], categories: default_categories(), settings: Value::Object(Default::default()) };
    write_vault(&path, &salt, &key, &data)?;
    let sess = Session::new(key, data, path, is_shared, autolock);
    let token = sess.token.clone();
    SESSIONS.lock().unwrap().insert(token.clone(), sess);
    Ok(token)
}

pub fn unlock_vault(password: &str, vault_path: &str, is_shared: bool, autolock: u64) -> anyhow::Result<String> {
    let path = PathBuf::from(vault_path);
    if !path.exists() { anyhow::bail!("Vault file not found"); }
    let raw: VaultFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let salt = STANDARD.decode(&raw.salt)?;
    let key  = crypto::derive_key(password, &salt)?;
    let data = decode_data(&path, &key)?;
    let mut sess = Session::new(key, data, path, is_shared, autolock);
    sess.log("unlock", "");
    let token = sess.token.clone();
    SESSIONS.lock().unwrap().insert(token.clone(), sess);
    Ok(token)
}

pub fn lock_vault(token: &str) { SESSIONS.lock().unwrap().remove(token); }

pub fn verify_password(vault_path: &str, password: &str) -> bool {
    let path = PathBuf::from(vault_path);
    if !path.exists() { return false; }
    let Ok(raw) = std::fs::read_to_string(&path) else { return false; };
    let Ok(vf) = serde_json::from_str::<VaultFile>(&raw) else { return false; };
    let Ok(salt) = STANDARD.decode(&vf.salt) else { return false; };
    let Ok(key) = crypto::derive_key(password, &salt) else { return false; };
    decode_data(&path, &key).is_ok()
}

/// Run f with a mutable reference to the session, returning its result.
pub fn with_session<F, R>(token: &str, f: F) -> Option<R>
where F: FnOnce(&mut Session) -> R {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token)?;
    if sess.is_expired() { sessions.remove(token); return None; }
    sess.touch();
    Some(f(sess))
}

pub fn session_exists(token: &str) -> bool {
    let mut sessions = SESSIONS.lock().unwrap();
    if let Some(sess) = sessions.get(token) {
        if sess.is_expired() { sessions.remove(token); return false; }
        return true;
    }
    false
}

// ── entries ────────────────────────────────────────────────────────────────────
pub fn get_entries(token: &str) -> Option<Vec<Value>> {
    with_session(token, |sess| {
        if sess.is_shared {
            if let Ok(data) = decode_data(&sess.vault_path, &sess.key) {
                sess.entries = data.entries;
            }
        }
        sess.entries.clone()
    })
}

pub fn add_entry(token: &str, data: &Value) -> anyhow::Result<Value> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let entry = serde_json::json!({
        "id":               uuid::Uuid::new_v4().to_string(),
        "title":            data.get("title").and_then(Value::as_str).unwrap_or("Untitled"),
        "username":         data.get("username").and_then(Value::as_str).unwrap_or(""),
        "password":         data.get("password").and_then(Value::as_str).unwrap_or(""),
        "url":              data.get("url").and_then(Value::as_str).unwrap_or(""),
        "notes":            data.get("notes").and_then(Value::as_str).unwrap_or(""),
        "category":         data.get("category").and_then(Value::as_str).unwrap_or("login"),
        "tags":             data.get("tags").cloned().unwrap_or(Value::Array(vec![])),
        "favorite":         data.get("favorite").and_then(Value::as_bool).unwrap_or(false),
        "totp_secret":      data.get("totp_secret").and_then(Value::as_str).unwrap_or(""),
        "password_history": [],
        "created_at":       now_secs(),
        "updated_at":       now_secs(),
    });
    let title = entry["title"].as_str().unwrap_or("").to_string();
    write_op(sess, |s| { s.entries.push(entry.clone()); s.log("add_entry", &title); })?;
    Ok(entry)
}

pub fn update_entry(token: &str, entry_id: &str, data: &Value) -> anyhow::Result<Option<Value>> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let mut result = None;
    write_op(sess, |s| {
        if let Some(pos) = s.entries.iter().position(|e| e["id"].as_str() == Some(entry_id)) {
            let old = s.entries[pos].clone();
            let old_pw = old["password"].as_str().unwrap_or("");
            let new_pw = data.get("password").and_then(Value::as_str).unwrap_or(old_pw);
            let mut history: Vec<Value> = old.get("password_history").and_then(Value::as_array).cloned().unwrap_or_default();
            if !new_pw.is_empty() && new_pw != old_pw {
                history.insert(0, Value::String(old_pw.to_string()));
                history.truncate(5);
            }
            let new_title = data.get("title").and_then(Value::as_str).unwrap_or(old["title"].as_str().unwrap_or(""));
            let updated = serde_json::json!({
                "id":               entry_id,
                "title":            new_title,
                "username":         data.get("username").and_then(Value::as_str).unwrap_or(old["username"].as_str().unwrap_or("")),
                "password":         new_pw,
                "url":              data.get("url").and_then(Value::as_str).unwrap_or(old["url"].as_str().unwrap_or("")),
                "notes":            data.get("notes").and_then(Value::as_str).unwrap_or(old["notes"].as_str().unwrap_or("")),
                "category":         data.get("category").and_then(Value::as_str).unwrap_or(old["category"].as_str().unwrap_or("login")),
                "tags":             data.get("tags").cloned().unwrap_or_else(|| old["tags"].clone()),
                "favorite":         data.get("favorite").and_then(Value::as_bool).unwrap_or(old["favorite"].as_bool().unwrap_or(false)),
                "totp_secret":      data.get("totp_secret").and_then(Value::as_str).unwrap_or(old.get("totp_secret").and_then(Value::as_str).unwrap_or("")),
                "password_history": history,
                "created_at":       old["created_at"].clone(),
                "updated_at":       now_secs(),
            });
            s.log("update_entry", new_title);
            s.entries[pos] = updated.clone();
            result = Some(updated);
        }
    })?;
    Ok(result)
}

pub fn delete_entry(token: &str, entry_id: &str) -> anyhow::Result<bool> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let mut deleted = false;
    write_op(sess, |s| {
        let before = s.entries.len();
        let title = s.entries.iter().find(|e| e["id"].as_str() == Some(entry_id))
            .and_then(|e| e["title"].as_str()).unwrap_or("").to_string();
        s.entries.retain(|e| e["id"].as_str() != Some(entry_id));
        deleted = s.entries.len() < before;
        if deleted { s.log("delete_entry", &title); }
    })?;
    Ok(deleted)
}

// ── categories ─────────────────────────────────────────────────────────────────
pub fn get_categories(token: &str) -> Option<Vec<Value>> {
    with_session(token, |s| s.categories.clone())
}

pub fn add_category(token: &str, data: &Value) -> anyhow::Result<Value> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let cat = serde_json::json!({
        "id":      &uuid::Uuid::new_v4().to_string()[..8],
        "label":   data.get("label").and_then(Value::as_str).unwrap_or("Category"),
        "icon":    data.get("icon").and_then(Value::as_str).unwrap_or("📁"),
        "color":   data.get("color").and_then(Value::as_str).unwrap_or("#64748b"),
        "builtin": false,
    });
    write_op(sess, |s| s.categories.push(cat.clone()))?;
    Ok(cat)
}

pub fn update_category(token: &str, cat_id: &str, data: &Value) -> anyhow::Result<Option<Value>> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let mut result = None;
    write_op(sess, |s| {
        if let Some(pos) = s.categories.iter().position(|c| c["id"].as_str() == Some(cat_id)) {
            let old = s.categories[pos].clone();
            let updated = serde_json::json!({
                "id":      cat_id,
                "label":   data.get("label").and_then(Value::as_str).unwrap_or(old["label"].as_str().unwrap_or("")),
                "icon":    data.get("icon").and_then(Value::as_str).unwrap_or(old["icon"].as_str().unwrap_or("")),
                "color":   data.get("color").and_then(Value::as_str).unwrap_or(old["color"].as_str().unwrap_or("")),
                "builtin": old["builtin"].clone(),
            });
            s.categories[pos] = updated.clone();
            result = Some(updated);
        }
    })?;
    Ok(result)
}

pub fn delete_category(token: &str, cat_id: &str) -> anyhow::Result<bool> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let mut deleted = false;
    write_op(sess, |s| {
        let before = s.categories.len();
        s.categories.retain(|c| c["id"].as_str() != Some(cat_id));
        deleted = s.categories.len() < before;
        if deleted {
            for e in &mut s.entries {
                if e["category"].as_str() == Some(cat_id) {
                    if let Some(obj) = e.as_object_mut() { obj.insert("category".into(), Value::String("other".into())); }
                }
            }
        }
    })?;
    Ok(deleted)
}

// ── health ─────────────────────────────────────────────────────────────────────
pub fn health_report(token: &str) -> Option<Value> {
    with_session(token, |s| {
        let mut pw_counts: HashMap<String, Vec<String>> = HashMap::new();
        for e in &s.entries {
            let pw = e["password"].as_str().unwrap_or("").to_string();
            if !pw.is_empty() { pw_counts.entry(pw).or_default().push(e["id"].as_str().unwrap_or("").to_string()); }
        }
        let mut weak = vec![];
        let mut reused = vec![];
        for e in &s.entries {
            let pw = e["password"].as_str().unwrap_or("");
            let (score, _) = crypto::password_strength(pw);
            if score < 50 && !pw.is_empty() {
                weak.push(serde_json::json!({"id": e["id"], "title": e["title"], "score": score}));
            }
            if !pw.is_empty() && pw_counts.get(pw).map_or(0, |v| v.len()) > 1 {
                reused.push(serde_json::json!({"id": e["id"], "title": e["title"]}));
            }
        }
        let score = 100i64 - (weak.len() as i64 * 10) - (reused.len() as i64 * 5);
        serde_json::json!({"total": s.entries.len(), "weak": weak, "reused": reused, "score": score.max(0)})
    })
}

// ── settings ───────────────────────────────────────────────────────────────────
pub fn set_autolock(token: &str, secs: u64) -> anyhow::Result<()> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("no session"))?;
    sess.autolock = secs;
    if let Some(obj) = sess.settings.as_object_mut() { obj.insert("autolock".into(), secs.into()); }
    persist(sess)
}

pub fn change_password(token: &str, new_pw: &str) -> anyhow::Result<String> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("no session"))?;
    let salt = crypto::new_salt();
    let key  = crypto::derive_key(new_pw, &salt)?;
    let data = sess.to_data();
    write_vault(&sess.vault_path, &salt, &key, &data)?;
    let new_sess = Session::new(key, data, sess.vault_path.clone(), sess.is_shared, sess.autolock);
    let new_token = new_sess.token.clone();
    let old_token = token.to_string();
    sessions.remove(&old_token);
    sessions.insert(new_token.clone(), new_sess);
    Ok(new_token)
}

// ── merge ──────────────────────────────────────────────────────────────────────
pub fn merge_vault(token: &str, src_path: &str, src_pw: &str) -> anyhow::Result<serde_json::Value> {
    let src = PathBuf::from(src_path);
    if !src.exists() { anyhow::bail!("Source vault file not found"); }
    let raw: VaultFile = serde_json::from_str(&std::fs::read_to_string(&src)?)?;
    let salt = STANDARD.decode(&raw.salt)?;
    let key  = crypto::derive_key(src_pw, &salt)?;
    let data = decode_data(&src, &key)?;

    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("no session"))?;
    let mut added = 0;
    let mut skipped = 0;
    for entry in data.entries {
        let title = entry["title"].as_str().unwrap_or("").to_string();
        let uname = entry["username"].as_str().unwrap_or("").to_string();
        let dup = sess.entries.iter().any(|e| {
            e["title"].as_str().unwrap_or("") == title && e["username"].as_str().unwrap_or("") == uname
        });
        if dup { skipped += 1; } else { sess.entries.push(entry); added += 1; }
    }
    persist(sess)?;
    Ok(serde_json::json!({"added": added, "skipped": skipped}))
}

// ── import / export ────────────────────────────────────────────────────────────
pub fn export_csv(token: &str) -> Option<String> {
    with_session(token, |s| {
        let mut out = String::from("Title,Username,Password,URL,Notes,Category\n");
        for e in &s.entries {
            let row = [
                e["title"].as_str().unwrap_or(""),
                e["username"].as_str().unwrap_or(""),
                e["password"].as_str().unwrap_or(""),
                e["url"].as_str().unwrap_or(""),
                e["notes"].as_str().unwrap_or(""),
                e["category"].as_str().unwrap_or(""),
            ].iter().map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
             .collect::<Vec<_>>().join(",");
            out.push_str(&row); out.push('\n');
        }
        out
    })
}

pub fn import_entries(token: &str, entries: Vec<Value>) -> anyhow::Result<usize> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("no session"))?;
    let count = entries.len();
    write_op(sess, |s| {
        for mut e in entries {
            if e.get("id").and_then(Value::as_str).is_none() {
                if let Some(obj) = e.as_object_mut() { obj.insert("id".into(), Value::String(uuid::Uuid::new_v4().to_string())); }
            }
            s.entries.push(e);
        }
        s.log("import", &count.to_string());
    })?;
    Ok(count)
}

pub fn get_activity(token: &str) -> Option<Vec<serde_json::Value>> {
    with_session(token, |s| {
        s.activity_log.iter().rev().map(|(ts, action, detail)| {
            serde_json::json!({"timestamp": ts, "action": action, "detail": detail})
        }).collect()
    })
}

pub fn get_mtime(vault_path: &str) -> Option<u64> {
    std::fs::metadata(vault_path).ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

pub fn get_unlocked_paths() -> Vec<String> {
    SESSIONS.lock().unwrap().values()
        .filter(|s| !s.is_expired())
        .map(|s| s.vault_path.to_string_lossy().into_owned())
        .collect()
}

pub fn expire_sessions() {
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.retain(|_, s| !s.is_expired());
}

pub fn get_autolock(token: &str) -> Option<u64> {
    with_session(token, |s| s.autolock)
}


// ── file entries (stored inside vault as entries with entry_type="file") ───────

pub fn add_file_entry(token: &str, filename: &str, bytes: &[u8], mime_type: &str, category: &str) -> anyhow::Result<Value> {
    use base64::engine::general_purpose::STANDARD as B64;
    let file_data = B64.encode(bytes);
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let entry = serde_json::json!({
        "id":         uuid::Uuid::new_v4().to_string(),
        "entry_type": "file",
        "title":      filename,
        "file_data":  file_data,
        "file_size":  bytes.len(),
        "file_mime":  mime_type,
        "category":   category,
        "notes":      "",
        "favorite":   false,
        "created_at": now_secs(),
        "updated_at": now_secs(),
    });
    let name = filename.to_string();
    let entry_clone = entry.clone();
    write_op(sess, |s| { s.entries.push(entry_clone); s.log("add_file", &name); })?;
    Ok(entry)
}

pub fn get_file_entries(token: &str) -> Option<Vec<Value>> {
    with_session(token, |s| {
        s.entries.iter()
            .filter(|e| e["entry_type"].as_str() == Some("file"))
            .cloned()
            .collect::<Vec<_>>()
    })
}

pub fn get_file_entry_data(token: &str, file_id: &str) -> Option<(Vec<u8>, Value)> {
    use base64::engine::general_purpose::STANDARD as B64;
    with_session(token, |s| -> Option<(Vec<u8>, Value)> {
        let entry = s.entries.iter().find(|e|
            e["id"].as_str() == Some(file_id) &&
            e["entry_type"].as_str() == Some("file")
        )?.clone();
        let bytes = B64.decode(entry["file_data"].as_str()?).ok()?;
        Some((bytes, entry))
    }).flatten()
}

pub fn rename_file_entry(token: &str, file_id: &str, new_name: &str) -> anyhow::Result<Option<Value>> {
    let mut sessions = SESSIONS.lock().unwrap();
    let sess = sessions.get_mut(token).ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    let mut result: Option<Value> = None;
    write_op(sess, |s| {
        if let Some(pos) = s.entries.iter().position(|e|
            e["id"].as_str() == Some(file_id) && e["entry_type"].as_str() == Some("file")
        ) {
            let mut updated = s.entries[pos].clone();
            if let Some(obj) = updated.as_object_mut() {
                obj.insert("title".into(), Value::String(new_name.to_string()));
                obj.insert("updated_at".into(), now_secs().into());
            }
            s.entries[pos] = updated.clone();
            result = Some(updated);
            s.log("rename_file", new_name);
        }
    })?;
    Ok(result)
}
