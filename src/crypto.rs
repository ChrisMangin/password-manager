//! Argon2id key derivation + AES-256-GCM encryption.
//! Parameters match the Python implementation exactly so existing vaults open.

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;

pub const SALT_LEN:  usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN:   usize = 32;

/// Argon2id with the same parameters as Python: t=3, m=65536, p=4
pub fn derive_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; KEY_LEN]> {
    let params = Params::new(65536, 3, 4, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(key)
}

pub fn new_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> anyhow::Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce_bytes = new_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    Ok((nonce_bytes, ct))
}

pub fn decrypt(nonce: &[u8], ciphertext: &[u8], key: &[u8; KEY_LEN]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("Incorrect vault password"))
}

// ── Password generation ────────────────────────────────────────────────────────
const SYMBOLS: &str = "!@#$%^&*-_=+?";
const AMBIGUOUS: &[char] = &['0','O','l','1','I'];

pub fn generate_password(length: usize, upper: bool, digits: bool, symbols: bool, no_ambiguous: bool) -> String {
    use rand::seq::SliceRandom;
    let mut pool: Vec<char> = ('a'..='z').collect();
    let mut required: Vec<char> = vec![*pool.choose(&mut rand::thread_rng()).unwrap()];

    if upper {
        let chars: Vec<char> = ('A'..='Z')
            .filter(|c| !no_ambiguous || !AMBIGUOUS.contains(c)).collect();
        pool.extend_from_slice(&chars);
        required.push(*chars.choose(&mut rand::thread_rng()).unwrap());
    }
    if digits {
        let chars: Vec<char> = ('0'..='9')
            .filter(|c| !no_ambiguous || !AMBIGUOUS.contains(c)).collect();
        pool.extend_from_slice(&chars);
        required.push(*chars.choose(&mut rand::thread_rng()).unwrap());
    }
    if symbols {
        let chars: Vec<char> = SYMBOLS.chars().collect();
        pool.extend_from_slice(&chars);
        required.push(*chars.choose(&mut rand::thread_rng()).unwrap());
    }
    if no_ambiguous {
        pool.retain(|c| !AMBIGUOUS.contains(c));
    }
    while required.len() < length {
        required.push(*pool.choose(&mut rand::thread_rng()).unwrap());
    }
    required.shuffle(&mut rand::thread_rng());
    required[..length].iter().collect()
}

pub fn password_strength(pw: &str) -> (u32, &'static str) {
    if pw.is_empty() { return (0, "Empty"); }
    let has_lower  = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_upper  = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit  = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_alphanumeric());
    let char_sets  = [has_lower, has_upper, has_digit, has_symbol].iter().filter(|&&x| x).count() as u32;
    let mut pool = 0u32;
    if has_lower  { pool += 26; }
    if has_upper  { pool += 26; }
    if has_digit  { pool += 10; }
    if has_symbol { pool += 32; }
    let entropy = if pool > 0 { pw.len() as f64 * (pool as f64).log2() } else { 0.0 };
    let mut score = ((entropy * 1.8) as u32).min(100);
    score = score.max((25 * char_sets).min(100));
    if pw.len() < 8       { score = score.min(20); }
    else if pw.len() < 12 { score = score.min(55); }
    let label = match score {
        0..=19  => "Very Weak",
        20..=39 => "Weak",
        40..=59 => "Fair",
        60..=79 => "Strong",
        _       => "Very Strong",
    };
    (score, label)
}
