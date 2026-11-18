use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};
use crate::model::{now_unix_ms, SnapshotSignature, Vault};

pub const FILE_MAGIC: [u8; 8] = *b"CDECK\x00\x01\x00";
pub const LEGACY_FILE_MAGIC: [u8; 8] = *b"WSAFE\x00\x01\x00";
pub const HEADER_LEN: usize = 96;
pub const PADDING_BUCKET: usize = 4096;
pub const FLAG_KEYFILE_USED: u32 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB (default: 65536 = 64 MiB, strong: 131072 = 128 MiB).
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::strong()
    }
}

impl KdfParams {
    pub fn strong() -> Self {
        Self {
            m_cost_kib: 131_072, // 128 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }

    pub fn balanced() -> Self {
        Self {
            m_cost_kib: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }

    /// Fast preset for unit tests only.
    pub fn test_fast() -> Self {
        Self {
            m_cost_kib: 1024, // 1 MiB
            t_cost: 1,
            p_cost: 1,
        }
    }

    pub fn validate(&self) -> Result<()> {
        const MAX_M_COST_KIB: u32 = 1_048_576; // 1 GiB cap to prevent OOM from corrupted headers
        const MAX_T_COST: u32 = 64;
        const MAX_P_COST: u32 = 64;
        if !(8..=MAX_M_COST_KIB).contains(&self.m_cost_kib)
            || !(1..=MAX_T_COST).contains(&self.t_cost)
            || !(1..=MAX_P_COST).contains(&self.p_cost)
        {
            return Err(VaultError::InvalidFormat(format!(
                "out-of-bounds Argon2id parameters: m={} KiB, t={}, p={}",
                self.m_cost_kib, self.t_cost, self.p_cost
            )));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub password: Zeroizing<String>,
    pub keyfile_bytes: Option<Zeroizing<Vec<u8>>>,
}

impl Credentials {
    pub fn from_password(password: impl Into<String>) -> Self {
        Self {
            password: Zeroizing::new(password.into()),
            keyfile_bytes: None,
        }
    }

    pub fn with_keyfile(mut self, bytes: Vec<u8>) -> Self {
        self.keyfile_bytes = Some(Zeroizing::new(bytes));
        self
    }

    pub fn from_password_and_keyfile_path(
        password: impl Into<String>,
        keyfile: Option<&Path>,
    ) -> Result<Self> {
        let mut creds = Self::from_password(password);
        if let Some(kf) = keyfile {
            let data = fs::read(kf)?;
            creds = creds.with_keyfile(data);
        }
        Ok(creds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerification {
    VerifiedTrusted,
    VerifiedUnknownDevice,
    InvalidSignature,
    Unsigned,
}

struct DerivedKeys {
    aes_key: Zeroizing<[u8; 32]>,
    chacha_key: Zeroizing<[u8; 32]>,
}

fn derive_keys(
    creds: &Credentials,
    salt: &[u8; 32],
    kdf: KdfParams,
) -> Result<DerivedKeys> {
    if creds.password.is_empty() && creds.keyfile_bytes.is_none() {
        return Err(VaultError::Validation(
            "password or keyfile is required".into(),
        ));
    }
    kdf.validate()?;

    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| VaultError::Crypto(format!("invalid Argon2id params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(creds.password.as_bytes(), salt, argon_out.as_mut())
        .map_err(|e| VaultError::Crypto(format!("Argon2id failure: {e}")))?;

    let mut kf_digest = Zeroizing::new([0u8; 32]);
    let hkdf_salt: Option<&[u8]> = if let Some(kf) = &creds.keyfile_bytes {
        let hash = blake3::hash(kf.as_slice());
        kf_digest.copy_from_slice(hash.as_bytes());
        Some(kf_digest.as_slice())
    } else {
        None
    };

    let hk = Hkdf::<Sha512>::new(hkdf_salt, argon_out.as_slice());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"wsafe-v1-aes256gcm-xchacha20poly1305", okm.as_mut())
        .map_err(|e| VaultError::Crypto(format!("HKDF expansion failed: {e}")))?;

    let mut aes_key = Zeroizing::new([0u8; 32]);
    let mut chacha_key = Zeroizing::new([0u8; 32]);
    aes_key.copy_from_slice(&okm[0..32]);
    chacha_key.copy_from_slice(&okm[32..64]);

    Ok(DerivedKeys {
        aes_key,
        chacha_key,
    })
}

/// Canonical view of the vault for Ed25519 signing (excludes `snapshot_signature`).
#[derive(Serialize)]
struct VaultSignable<'a> {
    format_version: u32,
    vault_name: &'a crate::model::LwwField<String>,
    device_id: &'a uuid::Uuid,
    device_name: &'a str,
    trusted_devices: &'a std::collections::BTreeMap<uuid::Uuid, crate::model::DeviceIdentity>,
    cards: &'a std::collections::BTreeMap<uuid::Uuid, crate::model::Card>,
    blobs: &'a std::collections::BTreeMap<String, Vec<u8>>,
}

fn canonical_vault_bytes(vault: &Vault) -> Result<Vec<u8>> {
    let view = VaultSignable {
        format_version: vault.format_version,
        vault_name: &vault.vault_name,
        device_id: &vault.device_id,
        device_name: &vault.device_name,
        trusted_devices: &vault.trusted_devices,
        cards: &vault.cards,
        blobs: &vault.blobs,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&view, &mut buf)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Sign the vault's current state using its Ed25519 signing key.
pub fn sign_vault(vault: &mut Vault) -> Result<()> {
    let signing_key = SigningKey::from_bytes(&vault.signing_seed);
    let verifying_key = signing_key.verifying_key();
    let payload = canonical_vault_bytes(vault)?;
    let sig = signing_key.sign(&payload);

    vault.snapshot_signature = Some(SnapshotSignature {
        signer_device_id: vault.device_id,
        signer_name: vault.device_name.clone(),
        signer_pubkey: verifying_key.to_bytes(),
        signed_at_ms: now_unix_ms(),
        signature: sig.to_bytes().to_vec(),
    });
    Ok(())
}

/// Verify the Ed25519 signature on a decrypted vault.
pub fn verify_vault_signature(vault: &Vault) -> SignatureVerification {
    let Some(snap) = &vault.snapshot_signature else {
        return SignatureVerification::Unsigned;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&snap.signer_pubkey) else {
        return SignatureVerification::InvalidSignature;
    };
    let Ok(sig) = Signature::from_slice(&snap.signature) else {
        return SignatureVerification::InvalidSignature;
    };
    let Ok(payload) = canonical_vault_bytes(vault) else {
        return SignatureVerification::InvalidSignature;
    };
    if verifying_key.verify(&payload, &sig).is_err() {
        return SignatureVerification::InvalidSignature;
    }
    match vault.trusted_devices.get(&snap.signer_device_id) {
        Some(dev) if dev.ed25519_pubkey == snap.signer_pubkey => {
            SignatureVerification::VerifiedTrusted
        }
        _ => SignatureVerification::VerifiedUnknownDevice,
    }
}

fn pad_to_bucket(compressed: &[u8]) -> Vec<u8> {
    let raw_len = compressed.len();
    let total_needed = 4 + raw_len;
    let padded_len = total_needed.div_ceil(PADDING_BUCKET) * PADDING_BUCKET;
    let mut out = vec![0u8; padded_len];
    out[0..4].copy_from_slice(&(raw_len as u32).to_le_bytes());
    out[4..4 + raw_len].copy_from_slice(compressed);
    if padded_len > total_needed {
        OsRng.fill_bytes(&mut out[total_needed..]);
    }
    out
}

fn unpad_from_bucket(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < 4 {
        return Err(VaultError::InvalidFormat("truncated padded payload".into()));
    }
    let raw_len = u32::from_le_bytes(padded[0..4].try_into().unwrap()) as usize;
    if 4 + raw_len > padded.len() {
        return Err(VaultError::InvalidFormat("invalid padded payload length".into()));
    }
    Ok(&padded[4..4 + raw_len])
}

#[derive(Debug, Clone, Copy)]
pub struct VaultHeaderInfo {
    pub version: u32,
    pub kdf: KdfParams,
    pub keyfile_used: bool,
}

pub fn peek_header(bytes: &[u8]) -> Result<VaultHeaderInfo> {
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::InvalidFormat("file too short for header".into()));
    }
    if bytes[0..8] != FILE_MAGIC && bytes[0..8] != LEGACY_FILE_MAGIC {
        return Err(VaultError::InvalidFormat("not a .cdeck vault file".into()));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != Vault::CURRENT_FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let m_cost_kib = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let kdf = KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
    };
    kdf.validate()?;
    Ok(VaultHeaderInfo {
        version,
        kdf,
        keyfile_used: (flags & FLAG_KEYFILE_USED) != 0,
    })
}

/// Sign and encrypt a vault into the `.wsafe` binary format (Argon2id + HKDF + AES-256-GCM + XChaCha20-Poly1305).
pub fn encrypt_vault(
    vault: &mut Vault,
    creds: &Credentials,
    kdf: KdfParams,
) -> Result<Vec<u8>> {
    sign_vault(vault)?;

    let mut cbor = Zeroizing::new(Vec::new());
    ciborium::into_writer(vault, &mut *cbor)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;

    let compressed = Zeroizing::new(
        zstd::encode_all(cbor.as_slice(), 3)
            .map_err(|e| VaultError::Serialization(format!("zstd compress: {e}")))?,
    );
    let mut padded = pad_to_bucket(&compressed);

    let mut salt = [0u8; 32];
    let mut inner_nonce = [0u8; 12];
    let mut outer_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut inner_nonce);
    OsRng.fill_bytes(&mut outer_nonce);

    let flags: u32 = if creds.keyfile_bytes.is_some() {
        FLAG_KEYFILE_USED
    } else {
        0
    };

    let mut header = [0u8; HEADER_LEN];
    header[0..8].copy_from_slice(&FILE_MAGIC);
    header[8..12].copy_from_slice(&Vault::CURRENT_FORMAT_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&kdf.m_cost_kib.to_le_bytes());
    header[16..20].copy_from_slice(&kdf.t_cost.to_le_bytes());
    header[20..24].copy_from_slice(&kdf.p_cost.to_le_bytes());
    header[24..28].copy_from_slice(&flags.to_le_bytes());
    header[28..60].copy_from_slice(&salt);
    header[60..72].copy_from_slice(&inner_nonce);
    header[72..96].copy_from_slice(&outer_nonce);

    let keys = derive_keys(creds, &salt, kdf)?;

    let aes = Aes256Gcm::new_from_slice(keys.aes_key.as_slice())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let mut inner_ct = aes
        .encrypt(
            AesNonce::from_slice(&inner_nonce),
            Payload {
                msg: &padded,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("inner AES-256-GCM encryption failed".into()))?;
    padded.zeroize();

    let chacha = XChaCha20Poly1305::new_from_slice(keys.chacha_key.as_slice())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let outer_ct = chacha
        .encrypt(
            XNonce::from_slice(&outer_nonce),
            Payload {
                msg: &inner_ct,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("outer XChaCha20-Poly1305 encryption failed".into()))?;
    inner_ct.zeroize();

    let mut out = Vec::with_capacity(HEADER_LEN + outer_ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&outer_ct);
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct DecryptedVault {
    pub vault: Vault,
    pub header: VaultHeaderInfo,
    pub signature: SignatureVerification,
}

/// Decrypt a `.wsafe` vault file and verify its AEAD tags + Ed25519 signature.
pub fn decrypt_vault(bytes: &[u8], creds: &Credentials) -> Result<DecryptedVault> {
    let header_info = peek_header(bytes)?;
    let header = &bytes[0..HEADER_LEN];
    let outer_ct = &bytes[HEADER_LEN..];

    let mut salt = [0u8; 32];
    let mut inner_nonce = [0u8; 12];
    let mut outer_nonce = [0u8; 24];
    salt.copy_from_slice(&header[28..60]);
    inner_nonce.copy_from_slice(&header[60..72]);
    outer_nonce.copy_from_slice(&header[72..96]);

    let keys = derive_keys(creds, &salt, header_info.kdf)?;

    let chacha = XChaCha20Poly1305::new_from_slice(keys.chacha_key.as_slice())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let mut inner_ct = chacha
        .decrypt(
            XNonce::from_slice(&outer_nonce),
            Payload {
                msg: outer_ct,
                aad: header,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;

    let aes = Aes256Gcm::new_from_slice(keys.aes_key.as_slice())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let padded = Zeroizing::new(
        aes.decrypt(
            AesNonce::from_slice(&inner_nonce),
            Payload {
                msg: &inner_ct,
                aad: header,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    inner_ct.zeroize();

    let compressed = unpad_from_bucket(padded.as_slice())?;
    let cbor = Zeroizing::new(
        zstd::decode_all(compressed)
            .map_err(|e| VaultError::InvalidFormat(format!("zstd decompress: {e}")))?,
    );
    let vault: Vault = ciborium::from_reader(cbor.as_slice())
        .map_err(|e| VaultError::InvalidFormat(format!("cbor decode: {e}")))?;

    let signature = verify_vault_signature(&vault);
    Ok(DecryptedVault {
        vault,
        header: header_info,
        signature,
    })
}

/// Atomically save an encrypted `.wsafe` file with `0600` permissions.
pub fn save_vault_file(
    path: &Path,
    vault: &mut Vault,
    creds: &Credentials,
    kdf: KdfParams,
) -> Result<()> {
    let bytes = encrypt_vault(vault, creds, kdf)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault"),
        uuid::Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

pub fn load_vault_file(path: &Path, creds: &Credentials) -> Result<DecryptedVault> {
    let bytes = fs::read(path)?;
    decrypt_vault(&bytes, creds)
}
