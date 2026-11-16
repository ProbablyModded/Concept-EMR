use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const SALT_BYTES: usize = 16;
const ARGON_MEMORY_KIB: u32 = 65_536;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const STATE_AAD_PREFIX: &str = "smartemr/state/v2/";
const PASSWORD_WRAP_AAD: &[u8] = b"smartemr/data-key/password-wrap/v1";
const RECOVERY_WRAP_AAD: &[u8] = b"smartemr/data-key/recovery-wrap/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPayload {
    pub version: u8,
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKey {
    pub version: u8,
    pub algorithm: String,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn decode_key(encoded: &str) -> Result<Vec<u8>, String> {
    let key = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|_| "Encryption key is malformed.".to_string())?;
    if key.len() != KEY_BYTES {
        return Err("Encryption key has an invalid length.".to_string());
    }
    Ok(key)
}

fn make_argon2(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Argon2<'static>, String> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_BYTES))
        .map_err(|_| "Password key settings are invalid.".to_string())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn encrypt_bytes(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(String, String), String> {
    if key.len() != KEY_BYTES {
        return Err("Encryption key has an invalid length.".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Could not initialize encryption.".to_string())?;
    let nonce_bytes = random_bytes::<NONCE_BYTES>();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Could not encrypt data.".to_string())?;
    Ok((
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(ciphertext),
    ))
}

fn decrypt_bytes(key: &[u8], nonce: &str, ciphertext: &str, aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != KEY_BYTES {
        return Err("Encryption key has an invalid length.".to_string());
    }
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| "Encrypted data has a malformed nonce.".to_string())?;
    if nonce_bytes.len() != NONCE_BYTES {
        return Err("Encrypted data has an invalid nonce length.".to_string());
    }
    let ciphertext_bytes = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| "Encrypted data is malformed.".to_string())?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Could not initialize decryption.".to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext_bytes,
                aad,
            },
        )
        .map_err(|_| {
            "Data authentication failed; the key may be incorrect or the data may be damaged."
                .to_string()
        })
}

fn wrap_key(secret: &str, data_key: &str, aad: &[u8]) -> Result<WrappedKey, String> {
    if secret.is_empty() {
        return Err("A password or recovery key is required.".to_string());
    }
    let mut key_bytes = decode_key(data_key)?;
    let salt = random_bytes::<SALT_BYTES>();
    let argon2 = make_argon2(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM)?;
    let mut wrapping_key = [0u8; KEY_BYTES];
    if argon2
        .hash_password_into(secret.as_bytes(), &salt, &mut wrapping_key)
        .is_err()
    {
        key_bytes.zeroize();
        wrapping_key.zeroize();
        return Err("Could not derive a key for protecting the database key.".to_string());
    }
    let encrypted_key = encrypt_bytes(&wrapping_key, &key_bytes, aad);
    key_bytes.zeroize();
    wrapping_key.zeroize();
    let (nonce, ciphertext) = encrypted_key?;

    Ok(WrappedKey {
        version: 1,
        algorithm: "AES-256-GCM".to_string(),
        kdf: "Argon2id".to_string(),
        memory_kib: ARGON_MEMORY_KIB,
        iterations: ARGON_ITERATIONS,
        parallelism: ARGON_PARALLELISM,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce,
        ciphertext,
    })
}

fn unwrap_key(secret: &str, envelope: &WrappedKey, aad: &[u8]) -> Result<String, String> {
    if secret.is_empty() {
        return Err("A password or recovery key is required.".to_string());
    }
    if envelope.version != 1
        || envelope.algorithm != "AES-256-GCM"
        || envelope.kdf != "Argon2id"
        || envelope.memory_kib != ARGON_MEMORY_KIB
        || envelope.iterations != ARGON_ITERATIONS
        || envelope.parallelism != ARGON_PARALLELISM
    {
        return Err(
            "This database key format is not supported by this version of SmartEMR.".to_string(),
        );
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&envelope.salt)
        .map_err(|_| "The key envelope has a malformed salt.".to_string())?;
    if salt.len() != SALT_BYTES {
        return Err("The key envelope has an invalid salt length.".to_string());
    }
    let argon2 = make_argon2(
        envelope.memory_kib,
        envelope.iterations,
        envelope.parallelism,
    )?;
    let mut wrapping_key = [0u8; KEY_BYTES];
    if argon2
        .hash_password_into(secret.as_bytes(), &salt, &mut wrapping_key)
        .is_err()
    {
        wrapping_key.zeroize();
        return Err("Could not derive the database key.".to_string());
    }
    let decrypted_key = decrypt_bytes(&wrapping_key, &envelope.nonce, &envelope.ciphertext, aad);
    wrapping_key.zeroize();
    let mut data_key = decrypted_key?;
    if data_key.len() != KEY_BYTES {
        data_key.zeroize();
        return Err("The unwrapped database key has an invalid length.".to_string());
    }
    let encoded = URL_SAFE_NO_PAD.encode(&data_key);
    data_key.zeroize();
    Ok(encoded)
}

#[tauri::command]
pub fn generate_data_encryption_key() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<KEY_BYTES>())
}

#[tauri::command]
pub fn generate_recovery_key() -> String {
    let raw = URL_SAFE_NO_PAD.encode(random_bytes::<KEY_BYTES>());
    let mut grouped = String::with_capacity(raw.len() + 8);
    for (index, character) in raw.chars().enumerate() {
        if index > 0 && index % 6 == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    grouped
}

#[tauri::command]
pub fn generate_password_reset_code() -> String {
    const CODE_SPACE: u64 = 900_000;
    let accepted_range = (u32::MAX as u64 + 1) / CODE_SPACE * CODE_SPACE;
    loop {
        let sample = u32::from_ne_bytes(random_bytes::<4>()) as u64;
        if sample < accepted_range {
            return format!("{:06}", 100_000 + sample % CODE_SPACE);
        }
    }
}

#[tauri::command]
pub fn hash_account_password(password: String) -> Result<String, String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters.".to_string());
    }
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = make_argon2(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM)?;
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Could not secure the account password.".to_string())
}

#[tauri::command]
pub fn verify_account_password(password: String, password_hash: String) -> bool {
    if !is_supported_password_hash(&password_hash) {
        return false;
    }
    let Ok(parsed_hash) = PasswordHash::new(&password_hash) else {
        return false;
    };
    let Ok(argon2) = make_argon2(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM) else {
        return false;
    };
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn is_supported_password_hash(password_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(password_hash) else {
        return false;
    };
    parsed_hash.algorithm.as_str() == "argon2id"
        && parsed_hash.version == Some(19)
        && parsed_hash.params.get_decimal("m") == Some(ARGON_MEMORY_KIB)
        && parsed_hash.params.get_decimal("t") == Some(ARGON_ITERATIONS)
        && parsed_hash.params.get_decimal("p") == Some(ARGON_PARALLELISM)
}

#[tauri::command]
pub fn wrap_data_key_with_password(password: String, data_key: String) -> Result<String, String> {
    let wrapped = wrap_key(&password, &data_key, PASSWORD_WRAP_AAD)?;
    serde_json::to_string(&wrapped)
        .map_err(|_| "Could not serialize the password key envelope.".to_string())
}

#[tauri::command]
pub fn unwrap_data_key_with_password(
    password: String,
    wrapped_key_json: String,
) -> Result<String, String> {
    let wrapped: WrappedKey = serde_json::from_str(&wrapped_key_json)
        .map_err(|_| "The password key envelope is damaged.".to_string())?;
    unwrap_key(&password, &wrapped, PASSWORD_WRAP_AAD)
}

#[tauri::command]
pub fn wrap_data_key_with_recovery_key(
    recovery_key: String,
    data_key: String,
) -> Result<String, String> {
    let normalized = recovery_key
        .chars()
        .filter(|character| *character != '-' && !character.is_whitespace())
        .collect::<String>();
    let wrapped = wrap_key(&normalized, &data_key, RECOVERY_WRAP_AAD)?;
    serde_json::to_string(&wrapped)
        .map_err(|_| "Could not serialize the recovery key envelope.".to_string())
}

#[tauri::command]
pub fn unwrap_data_key_with_recovery_key(
    recovery_key: String,
    wrapped_key_json: String,
) -> Result<String, String> {
    let normalized = recovery_key
        .chars()
        .filter(|character| *character != '-' && !character.is_whitespace())
        .collect::<String>();
    let wrapped: WrappedKey = serde_json::from_str(&wrapped_key_json)
        .map_err(|_| "The recovery key envelope is damaged.".to_string())?;
    unwrap_key(&normalized, &wrapped, RECOVERY_WRAP_AAD)
}

#[tauri::command]
pub fn encrypt_application_state(
    data_key: String,
    account: String,
    plaintext: String,
) -> Result<String, String> {
    let mut key = decode_key(&data_key)?;
    let aad = format!("{STATE_AAD_PREFIX}{account}");
    let (nonce, ciphertext) = encrypt_bytes(&key, plaintext.as_bytes(), aad.as_bytes())?;
    key.zeroize();
    let envelope = EncryptedPayload {
        version: 2,
        algorithm: "AES-256-GCM".to_string(),
        nonce,
        ciphertext,
    };
    serde_json::to_string(&envelope)
        .map_err(|_| "Could not serialize the encrypted state.".to_string())
}

#[tauri::command]
pub fn decrypt_application_state(
    data_key: String,
    account: String,
    encrypted_payload: String,
) -> Result<String, String> {
    let mut key = decode_key(&data_key)?;
    let envelope: EncryptedPayload = serde_json::from_str(&encrypted_payload)
        .map_err(|_| "The encrypted state envelope is damaged.".to_string())?;
    if envelope.version != 2 || envelope.algorithm != "AES-256-GCM" {
        key.zeroize();
        return Err(
            "This encrypted state format is not supported by this version of SmartEMR.".to_string(),
        );
    }
    let aad = format!("{STATE_AAD_PREFIX}{account}");
    let plaintext = decrypt_bytes(&key, &envelope.nonce, &envelope.ciphertext, aad.as_bytes());
    key.zeroize();
    String::from_utf8(plaintext?).map_err(|_| "The decrypted state is not valid UTF-8.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_wrap_encrypts_and_reopens_the_same_data_key() {
        let key = generate_data_encryption_key();
        let wrapped = wrap_key("correct horse battery staple", &key, PASSWORD_WRAP_AAD)
            .expect("key wrapping should work");
        let recovered = unwrap_key("correct horse battery staple", &wrapped, PASSWORD_WRAP_AAD)
            .expect("the correct password should unwrap the key");
        assert_eq!(recovered, key);
        assert!(unwrap_key("wrong password", &wrapped, PASSWORD_WRAP_AAD).is_err());
    }

    #[test]
    fn recovery_wrap_is_separate_from_password_wrap() {
        let key = generate_data_encryption_key();
        let recovery = generate_recovery_key();
        let wrapped = wrap_key(&recovery.replace('-', ""), &key, RECOVERY_WRAP_AAD)
            .expect("recovery wrapping should work");
        assert_eq!(
            unwrap_key(&recovery.replace('-', ""), &wrapped, RECOVERY_WRAP_AAD)
                .expect("recovery key should unwrap the key"),
            key
        );
        assert!(unwrap_key("not-the-recovery-key", &wrapped, RECOVERY_WRAP_AAD).is_err());
    }

    #[test]
    fn reset_codes_are_six_digit_numeric_values() {
        let code = generate_password_reset_code();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        assert!((100_000..=999_999).contains(&code.parse::<u32>().unwrap()));
    }

    #[test]
    fn state_encryption_authenticates_ciphertext_and_account_binding() {
        let key = generate_data_encryption_key();
        let encrypted = encrypt_application_state(
            key.clone(),
            "user-one".to_string(),
            "{\"data\":{}}".to_string(),
        )
        .expect("state encryption should work");
        assert_eq!(
            decrypt_application_state(key.clone(), "user-one".to_string(), encrypted.clone())
                .expect("state should decrypt for its account"),
            "{\"data\":{}}"
        );
        assert!(
            decrypt_application_state(key.clone(), "user-two".to_string(), encrypted.clone())
                .is_err()
        );

        let mut envelope: EncryptedPayload =
            serde_json::from_str(&encrypted).expect("valid envelope");
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .expect("valid ciphertext");
        ciphertext[0] ^= 1;
        envelope.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        let tampered = serde_json::to_string(&envelope).expect("serialize envelope");
        assert!(decrypt_application_state(key, "user-one".to_string(), tampered).is_err());
    }

    #[test]
    fn account_password_hash_is_salted_and_verifies() {
        let first =
            hash_account_password("a strong password".to_string()).expect("hash should work");
        let second =
            hash_account_password("a strong password".to_string()).expect("hash should work");
        assert_ne!(first, second);
        assert!(verify_account_password(
            "a strong password".to_string(),
            first.clone()
        ));
        assert!(!verify_account_password("incorrect".to_string(), first));
    }

    #[test]
    fn password_verification_rejects_unbounded_hash_parameters() {
        let hash = hash_account_password("a strong password".to_string())
            .expect("hash should work")
            .replace("m=65536", "m=4294967295");
        assert!(!verify_account_password(
            "a strong password".to_string(),
            hash
        ));
    }
}
