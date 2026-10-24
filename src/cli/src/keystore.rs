//! RFC-006 / RFC-005: Sovereign Keystore Engine (.gmkey)
//!
//! Provides native Rust decryption and encryption for passphrase-protected
//! `.gmkey` files, ensuring complete cryptographic parity with the in-browser
//! W3C WebCrypto implementation.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use grey_misnomer_core::auth::Keypair;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub iterations: u32,
    pub hash: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoContainer {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

/// Standardized `.gmkey` JSON schema envelope (RFC-006)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmkeyEnvelope {
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub created_at: String,
    pub crypto: CryptoContainer,
}

/// Decrypts a `.gmkey` envelope using the provided passphrase.
/// Reconstructs the ciphertext + MAC buffer, verifies the tag under AES-256-GCM,
/// and returns the unlocked Ed25519 `Keypair`.
pub fn decrypt_gmkey(envelope: &GmkeyEnvelope, passphrase: &str) -> Result<Keypair> {
    if envelope.version != 1 {
        bail!(
            "Unsupported keystore version: {}. Only version 1 is supported.",
            envelope.version
        );
    }
    if envelope.crypto.cipher != "aes-256-gcm" {
        bail!(
            "Unsupported cipher: '{}'. Only 'aes-256-gcm' is supported.",
            envelope.crypto.cipher
        );
    }
    if envelope.crypto.kdf != "pbkdf2" {
        bail!(
            "Unsupported KDF: '{}'. Only 'pbkdf2' is supported.",
            envelope.crypto.kdf
        );
    }
    if envelope.crypto.kdfparams.hash != "SHA-256" && envelope.crypto.kdfparams.hash != "sha-256" {
        bail!(
            "Unsupported KDF hash algorithm: '{}'. Only 'SHA-256' is supported.",
            envelope.crypto.kdfparams.hash
        );
    }

    let salt = hex::decode(&envelope.crypto.kdfparams.salt).context("Invalid hex for salt")?;
    let iv_bytes =
        hex::decode(&envelope.crypto.cipherparams.iv).context("Invalid hex for cipher IV")?;
    if iv_bytes.len() != 12 {
        bail!(
            "Invalid IV length: expected 12 bytes (24 hex characters), found {}",
            iv_bytes.len()
        );
    }

    let ciphertext_bytes =
        hex::decode(&envelope.crypto.ciphertext).context("Invalid hex for ciphertext")?;
    let mac_bytes = hex::decode(&envelope.crypto.mac).context("Invalid hex for MAC tag")?;
    if mac_bytes.len() != 16 {
        bail!(
            "Invalid MAC tag length: expected 16 bytes (32 hex characters), found {}",
            mac_bytes.len()
        );
    }

    // 1. Derive 256-bit AES key via PBKDF2-HMAC-SHA256
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        &salt,
        envelope.crypto.kdfparams.iterations,
        &mut derived_key,
    );

    // 2. Prepare payload: ciphertext concatenated with 16-byte MAC tag
    let mut payload = Vec::with_capacity(ciphertext_bytes.len() + mac_bytes.len());
    payload.extend_from_slice(&ciphertext_bytes);
    payload.extend_from_slice(&mac_bytes);

    // 3. Decrypt and authenticate with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-GCM cipher: {e}"))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let decrypted_bytes = cipher.decrypt(nonce, payload.as_ref()).map_err(|_| {
        anyhow::anyhow!("Keystore decryption failed: invalid passphrase or corrupted MAC tag")
    })?;

    // 4. Parse decrypted secret key (either 64-char hex string or 32 raw bytes)
    if let Ok(utf8_str) = std::str::from_utf8(&decrypted_bytes) {
        let trimmed = utf8_str.trim();
        if trimmed.len() == 64 {
            if let Ok(kp) = Keypair::from_hex(trimmed) {
                return Ok(kp);
            }
        }
    }
    if decrypted_bytes.len() == 32 {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decrypted_bytes);
        return Ok(Keypair::from_bytes(&key_bytes));
    }

    bail!("Decrypted payload does not contain a valid 32-byte Ed25519 seed or 64-character hex secret")
}

/// Encrypts an Ed25519 `Keypair` into a `.gmkey` envelope using PBKDF2-HMAC-SHA256 and AES-256-GCM.
pub fn encrypt_gmkey(
    kp: &Keypair,
    passphrase: &str,
    label: &str,
    role: &str,
) -> Result<GmkeyEnvelope> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let iterations = 100_000u32;
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        &salt,
        iterations,
        &mut derived_key,
    );

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-GCM cipher: {e}"))?;
    let nonce = Nonce::from_slice(&iv);

    let secret_hex = kp.secret_hex();
    let ciphertext_and_tag = cipher
        .encrypt(nonce, secret_hex.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

    let tag_pos = ciphertext_and_tag.len().saturating_sub(16);
    let ciphertext = &ciphertext_and_tag[..tag_pos];
    let mac = &ciphertext_and_tag[tag_pos..];

    let id = format!(
        "{:x}-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        OsRng.next_u64()
    );

    Ok(GmkeyEnvelope {
        version: 1,
        id,
        label: label.to_string(),
        role: role.to_string(),
        pubkey: kp.pubkey().to_hex(),
        created_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        crypto: CryptoContainer {
            cipher: "aes-256-gcm".to_string(),
            ciphertext: hex::encode(ciphertext),
            cipherparams: CipherParams {
                iv: hex::encode(iv),
            },
            kdf: "pbkdf2".to_string(),
            kdfparams: KdfParams {
                iterations,
                hash: "SHA-256".to_string(),
                salt: hex::encode(salt),
            },
            mac: hex::encode(mac),
        },
    })
}

/// Helper to load a `Keypair` either from a raw `--key <HEX/SEED>` flag
/// or from a `--keystore <FILE.gmkey>` with `--passphrase <PASS>` / `GM_PASSPHRASE` env.
pub fn resolve_keypair(
    key_opt: Option<&str>,
    keystore_opt: Option<&str>,
    passphrase_opt: Option<&str>,
) -> Result<Keypair> {
    if let Some(keystore_path) = keystore_opt {
        let path = Path::new(keystore_path);
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read keystore file '{}'", path.display()))?;
        let envelope: GmkeyEnvelope = serde_json::from_str(&content)
            .with_context(|| format!("Invalid .gmkey JSON schema in '{}'", path.display()))?;

        let pass = match passphrase_opt {
            Some(p) => p.to_string(),
            None => std::env::var("GM_PASSPHRASE").unwrap_or_default(),
        };

        if pass.is_empty() {
            bail!(
                "Passphrase required to decrypt '{}'. Provide via --passphrase or GM_PASSPHRASE env.",
                path.display()
            );
        }

        return decrypt_gmkey(&envelope, &pass);
    }

    if let Some(key_str) = key_opt {
        if key_str.len() == 64 {
            if let Ok(bytes) = hex::decode(key_str) {
                if bytes.len() == 32 {
                    let mut b32 = [0u8; 32];
                    b32.copy_from_slice(&bytes);
                    return Ok(Keypair::from_bytes(&b32));
                }
            }
        }
        return Ok(Keypair::from_seed_str(key_str));
    }

    bail!("No signing key provided. Specify --key <SEED/HEX> or --keystore <FILE.gmkey> --passphrase <PASS>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmkey_encrypt_decrypt_roundtrip() {
        let kp = Keypair::generate();
        let pass = "CorrectHorseBatteryStaple123!";

        let envelope = encrypt_gmkey(&kp, pass, "Sequencer Node Alpha", "Sequencer")
            .expect("encryption succeeds");

        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.pubkey, kp.pubkey().to_hex());
        assert_eq!(envelope.crypto.cipher, "aes-256-gcm");

        let decrypted = decrypt_gmkey(&envelope, pass).expect("decryption succeeds");
        assert_eq!(decrypted.pubkey(), kp.pubkey());
        assert_eq!(decrypted.secret_hex(), kp.secret_hex());

        // Wrong password must fail
        let wrong_res = decrypt_gmkey(&envelope, "WrongPassword");
        match wrong_res {
            Err(err) => {
                assert!(err.to_string().contains("invalid passphrase or corrupted MAC tag"));
            }
            Ok(_) => panic!("Expected decryption error for wrong password"),
        }
    }
}
