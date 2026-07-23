//! Vault registry — stored in %APPDATA%/Vault/config.json
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id:     String,
    pub label:  String,
    pub path:   String,
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmtpConfig {
    pub host:      String,
    pub port:      u16,
    pub username:  String,
    pub password:  String,
    pub from_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ConfigFile {
    vaults: Vec<VaultEntry>,
    #[serde(default)]
    smtp: Option<SmtpConfig>,
}

fn config_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_sys_not_found_fallback());
    base.join("Vault")
}

fn dirs_sys_not_found_fallback() -> PathBuf {
    std::env::current_exe().unwrap_or_default().parent().unwrap_or(&PathBuf::from(".")).to_path_buf()
}

fn config_path() -> PathBuf { config_dir().join("config.json") }

fn load_raw() -> ConfigFile {
    let p = config_path();
    if p.exists() {
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(c) = serde_json::from_str::<ConfigFile>(&s) { return c; }
        }
    }
    // Defaults: one local Personal vault, one unconfigured Shared vault
    let local_path = config_dir().join("personal.json");
    ConfigFile {
        vaults: vec![
            VaultEntry { id: "local".into(),  label: "Personal".into(), path: local_path.to_string_lossy().into(), shared: false },
            VaultEntry { id: "shared".into(), label: "Shared".into(),   path: "".into(),                           shared: true  },
        ],
        smtp: None,
    }
}

fn save_raw(c: &ConfigFile) {
    let dir = config_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(s) = serde_json::to_string_pretty(c) {
        let _ = std::fs::write(config_path(), s);
    }
}

pub fn get_vaults() -> Vec<VaultEntry> { load_raw().vaults }

pub fn get_vault(id: &str) -> Option<VaultEntry> {
    load_raw().vaults.into_iter().find(|v| v.id == id)
}

pub fn add_vault(label: &str, shared: bool, path: &str) -> VaultEntry {
    let mut cfg = load_raw();
    let id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let resolved_path = if !shared && path.is_empty() {
        config_dir().join(format!("{id}.json")).to_string_lossy().into()
    } else {
        path.to_string()
    };
    let v = VaultEntry { id, label: label.trim().to_string(), path: resolved_path, shared };
    cfg.vaults.push(v.clone());
    save_raw(&cfg);
    v
}

pub fn remove_vault(id: &str) -> bool {
    let mut cfg = load_raw();
    let before = cfg.vaults.len();
    cfg.vaults.retain(|v| v.id != id);
    if cfg.vaults.len() < before { save_raw(&cfg); true } else { false }
}

pub fn update_vault(id: &str, label: Option<&str>, path: Option<&str>) -> Option<VaultEntry> {
    let mut cfg = load_raw();
    for v in &mut cfg.vaults {
        if v.id == id {
            if let Some(l) = label { v.label = l.trim().to_string(); }
            if let Some(p) = path  { v.path  = p.trim().to_string(); }
            let out = v.clone();
            save_raw(&cfg);
            return Some(out);
        }
    }
    None
}

pub fn set_vault_path(id: &str, path: &str) { update_vault(id, None, Some(path)); }

pub fn get_smtp() -> Option<SmtpConfig> { load_raw().smtp }

pub fn set_smtp(smtp: SmtpConfig) {
    let mut cfg = load_raw();
    cfg.smtp = Some(smtp);
    save_raw(&cfg);
}
