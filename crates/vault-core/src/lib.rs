pub mod crypto;
pub mod error;
pub mod kdbx_import;
pub mod merge;
pub mod model;
pub mod password_gen;

pub use crypto::{
    decrypt_vault, encrypt_vault, load_vault_file, peek_header, save_vault_file, sign_vault,
    verify_vault_signature, Credentials, DecryptedVault, KdfParams, SignatureVerification,
    VaultHeaderInfo,
};
pub use error::{Result, VaultError};
pub use kdbx_import::import_kdbx;
pub use merge::{
    merge_vaults, DedupeScope, MergeChange, MergeChangeKind, MergeOptions, MergeOutcome,
    SourceSummary, SourceVaultInput,
};
pub use model::{
    AttachmentRef, Card, CardKind, CustomFieldValue, DeviceIdentity, FieldRevision, Hlc, LwwField,
    SnapshotSignature, Vault,
};
pub use password_gen::{
    estimate_entropy_bits, generate_password, strength_from_entropy, GeneratedPassword,
    GeneratorMode, PasswordGenConfig, StrengthLevel,
};
