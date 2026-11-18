use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Hybrid Logical Clock for deterministic, total-ordered field-level CRDT merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub unix_ms: u64,
    pub counter: u32,
    pub device_id: Uuid,
}

impl Hlc {
    pub fn new(unix_ms: u64, counter: u32, device_id: Uuid) -> Self {
        Self {
            unix_ms,
            counter,
            device_id,
        }
    }

    pub fn now(device_id: Uuid) -> Self {
        Self {
            unix_ms: now_unix_ms(),
            counter: 0,
            device_id,
        }
    }

    /// Advance the local clock monotonically past any observed HLC.
    pub fn tick(prev: Option<Hlc>, device_id: Uuid) -> Self {
        let physical = now_unix_ms();
        match prev {
            Some(p) if p.unix_ms >= physical => Self {
                unix_ms: p.unix_ms,
                counter: p.counter.saturating_add(1),
                device_id,
            },
            _ => Self {
                unix_ms: physical,
                counter: 0,
                device_id,
            },
        }
    }
}

/// A historical revision of a single field when overwritten by a newer edit or merge conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRevision<T> {
    pub value: T,
    pub hlc: Hlc,
    pub author_device: String,
}

/// Last-Write-Wins Register with bounded per-field revision history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwField<T> {
    pub value: T,
    pub hlc: Hlc,
    pub author_device: String,
    #[serde(default)]
    pub history: Vec<FieldRevision<T>>,
}

impl<T: Clone + PartialEq> LwwField<T> {
    pub fn new(value: T, hlc: Hlc, author_device: impl Into<String>) -> Self {
        Self {
            value,
            hlc,
            author_device: author_device.into(),
            history: Vec::new(),
        }
    }

    pub fn set(&mut self, new_value: T, device_id: Uuid, device_name: &str, max_history: usize) -> bool {
        if self.value == new_value {
            return false;
        }
        let next_hlc = Hlc::tick(Some(self.hlc), device_id);
        let prev = FieldRevision {
            value: self.value.clone(),
            hlc: self.hlc,
            author_device: self.author_device.clone(),
        };
        self.history.insert(0, prev);
        if max_history > 0 && self.history.len() > max_history {
            self.history.truncate(max_history);
        }
        self.value = new_value;
        self.hlc = next_hlc;
        self.author_device = device_name.to_string();
        true
    }

    /// Merge another LWW field into self. Returns `true` if `self.value` changed.
    pub fn merge_from(&mut self, other: &LwwField<T>, max_history: usize) -> bool {
        let mut changed = false;

        // Combine histories without duplicating identical (hlc, value) entries
        let mut all_revs: Vec<FieldRevision<T>> = Vec::with_capacity(
            self.history.len() + other.history.len() + 1,
        );
        all_revs.extend(self.history.iter().cloned());
        all_revs.extend(other.history.iter().cloned());

        if other.hlc > self.hlc {
            if self.value != other.value {
                all_revs.push(FieldRevision {
                    value: self.value.clone(),
                    hlc: self.hlc,
                    author_device: self.author_device.clone(),
                });
                changed = true;
            }
            self.value = other.value.clone();
            self.hlc = other.hlc;
            self.author_device = other.author_device.clone();
        } else if other.hlc < self.hlc && other.value != self.value {
            all_revs.push(FieldRevision {
                value: other.value.clone(),
                hlc: other.hlc,
                author_device: other.author_device.clone(),
            });
        }

        // Deduplicate & sort newest first, excluding current value if same HLC
        all_revs.sort_by(|a, b| b.hlc.cmp(&a.hlc));
        all_revs.dedup_by(|a, b| a.hlc == b.hlc && a.value == b.value);
        all_revs.retain(|r| r.hlc != self.hlc);
        if max_history > 0 && all_revs.len() > max_history {
            all_revs.truncate(max_history);
        }
        self.history = all_revs;
        changed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CardKind {
    #[default]
    Login,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CustomFieldValue {
    pub value: String,
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub blake3_hex: String,
    pub filename: String,
    pub size: u64,
}

fn default_empty_lww_string() -> LwwField<String> {
    LwwField::new(String::new(), Hlc::new(0, 0, Uuid::nil()), "")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    pub id: Uuid,
    pub kind: LwwField<CardKind>,
    pub title: LwwField<String>,
    pub username: LwwField<String>,
    pub password: LwwField<String>,
    #[serde(default = "default_empty_lww_string")]
    pub email: LwwField<String>,
    pub url: LwwField<String>,
    pub notes_markdown: LwwField<String>,
    pub folder: LwwField<String>,
    pub tags: LwwField<Vec<String>>,
    pub favorite: LwwField<bool>,
    #[serde(default = "default_empty_lww_string")]
    pub icon_color: LwwField<String>,
    #[serde(default)]
    pub custom_fields: BTreeMap<String, LwwField<CustomFieldValue>>,
    #[serde(default)]
    pub attachments: BTreeMap<String, LwwField<AttachmentRef>>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub deleted: Option<Hlc>,
}

impl Card {
    pub fn new_login(device_id: Uuid, device_name: &str, title: impl Into<String>) -> Self {
        Self::new(CardKind::Login, device_id, device_name, title)
    }

    pub fn new_note(device_id: Uuid, device_name: &str, title: impl Into<String>) -> Self {
        Self::new(CardKind::Note, device_id, device_name, title)
    }

    pub fn new(
        kind: CardKind,
        device_id: Uuid,
        device_name: &str,
        title: impl Into<String>,
    ) -> Self {
        let hlc = Hlc::now(device_id);
        let created_at_ms = hlc.unix_ms;
        Self {
            id: Uuid::new_v4(),
            kind: LwwField::new(kind, hlc, device_name),
            title: LwwField::new(title.into(), hlc, device_name),
            username: LwwField::new(String::new(), hlc, device_name),
            password: LwwField::new(String::new(), hlc, device_name),
            email: LwwField::new(String::new(), hlc, device_name),
            url: LwwField::new(String::new(), hlc, device_name),
            notes_markdown: LwwField::new(String::new(), hlc, device_name),
            folder: LwwField::new(String::new(), hlc, device_name),
            tags: LwwField::new(Vec::new(), hlc, device_name),
            favorite: LwwField::new(false, hlc, device_name),
            icon_color: LwwField::new(String::new(), hlc, device_name),
            custom_fields: BTreeMap::new(),
            attachments: BTreeMap::new(),
            created_at_ms,
            deleted: None,
        }
    }

    /// Highest HLC across all fields of this card.
    pub fn max_field_hlc(&self) -> Hlc {
        let mut max_hlc = self
            .kind
            .hlc
            .max(self.title.hlc)
            .max(self.username.hlc)
            .max(self.password.hlc)
            .max(self.email.hlc)
            .max(self.url.hlc)
            .max(self.notes_markdown.hlc)
            .max(self.folder.hlc)
            .max(self.tags.hlc)
            .max(self.favorite.hlc)
            .max(self.icon_color.hlc);
        for f in self.custom_fields.values() {
            max_hlc = max_hlc.max(f.hlc);
        }
        for a in self.attachments.values() {
            max_hlc = max_hlc.max(a.hlc);
        }
        max_hlc
    }

    pub fn max_hlc(&self) -> Hlc {
        let m = self.max_field_hlc();
        match self.deleted {
            Some(d) => m.max(d),
            None => m,
        }
    }

    pub fn is_deleted(&self) -> bool {
        match self.deleted {
            Some(del_hlc) => del_hlc >= self.max_field_hlc(),
            None => false,
        }
    }

    pub fn mark_deleted(&mut self, device_id: Uuid) {
        let next = Hlc::tick(Some(self.max_hlc()), device_id);
        self.deleted = Some(next);
    }

    pub fn restore(&mut self, device_id: Uuid, device_name: &str) {
        self.deleted = None;
        let next = Hlc::tick(Some(self.max_hlc()), device_id);
        self.title.hlc = next;
        self.title.author_device = device_name.to_string();
    }

    pub fn total_revisions(&self) -> usize {
        self.title.history.len()
            + self.username.history.len()
            + self.password.history.len()
            + self.email.history.len()
            + self.url.history.len()
            + self.notes_markdown.history.len()
            + self.folder.history.len()
            + self.tags.history.len()
    }

    pub fn is_completely_empty(&self) -> bool {
        self.title.value.trim().is_empty()
            && self.username.value.trim().is_empty()
            && self.password.value.trim().is_empty()
            && self.email.value.trim().is_empty()
            && self.url.value.trim().is_empty()
            && self.notes_markdown.value.trim().is_empty()
            && self.folder.value.trim().is_empty()
            && self.tags.value.is_empty()
            && self.custom_fields.iter().all(|(k, v)| {
                k.trim().is_empty() && v.value.value.trim().is_empty()
            })
            && self.attachments.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub device_name: String,
    pub ed25519_pubkey: [u8; 32],
    pub first_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSignature {
    pub signer_device_id: Uuid,
    pub signer_name: String,
    pub signer_pubkey: [u8; 32],
    pub signed_at_ms: u64,
    pub signature: Vec<u8>,
}

/// Canonical vault body signed by Ed25519 (excludes the signature field itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub format_version: u32,
    pub vault_name: LwwField<String>,
    pub device_id: Uuid,
    pub device_name: String,
    /// 32-byte Ed25519 signing seed for this vault/device.
    pub signing_seed: [u8; 32],
    /// Trusted Ed25519 device public keys seen in this vault or merged into it.
    #[serde(default)]
    pub trusted_devices: BTreeMap<Uuid, DeviceIdentity>,
    #[serde(default)]
    pub cards: BTreeMap<Uuid, Card>,
    /// Content-addressed attachment blobs keyed by BLAKE3 hex digest.
    #[serde(default)]
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// Ed25519 signature over the canonical CBOR of the vault content.
    #[serde(default)]
    pub snapshot_signature: Option<SnapshotSignature>,
}

impl Vault {
    pub const CURRENT_FORMAT_VERSION: u32 = 1;

    pub fn new(vault_name: impl Into<String>, device_name: impl Into<String>) -> Self {
        use rand::RngCore;
        let device_id = Uuid::new_v4();
        let device_name = device_name.into();
        let mut signing_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut signing_seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let pubkey = signing_key.verifying_key().to_bytes();

        let hlc = Hlc::now(device_id);
        let mut trusted_devices = BTreeMap::new();
        trusted_devices.insert(
            device_id,
            DeviceIdentity {
                device_id,
                device_name: device_name.clone(),
                ed25519_pubkey: pubkey,
                first_seen_ms: hlc.unix_ms,
            },
        );

        Self {
            format_version: Self::CURRENT_FORMAT_VERSION,
            vault_name: LwwField::new(vault_name.into(), hlc, &device_name),
            device_id,
            device_name,
            signing_seed,
            trusted_devices,
            cards: BTreeMap::new(),
            blobs: BTreeMap::new(),
            snapshot_signature: None,
        }
    }

    pub fn active_cards(&self) -> impl Iterator<Item = &Card> {
        self.cards.values().filter(|c| !c.is_deleted())
    }

    pub fn trashed_cards(&self) -> impl Iterator<Item = &Card> {
        self.cards.values().filter(|c| c.is_deleted())
    }

    pub fn add_card(&mut self, card: Card) -> Uuid {
        let id = card.id;
        self.cards.insert(id, card);
        id
    }

    /// Store an attachment blob deduplicated by BLAKE3 hash.
    pub fn store_blob(&mut self, data: &[u8]) -> String {
        let hex = blake3::hash(data).to_hex().to_string();
        self.blobs.entry(hex.clone()).or_insert_with(|| data.to_vec());
        hex
    }

    /// Remove blobs no longer referenced by any card (including trash).
    pub fn gc_blobs(&mut self) {
        let mut referenced = std::collections::BTreeSet::new();
        for card in self.cards.values() {
            for att in card.attachments.values() {
                referenced.insert(att.value.blake3_hex.clone());
                for rev in &att.history {
                    referenced.insert(rev.value.blake3_hex.clone());
                }
            }
        }
        self.blobs.retain(|k, _| referenced.contains(k));
    }

    /// Promote legacy KeePass-imported `E-Mail` / `Email` custom fields into `Card.email`.
    pub fn normalize_legacy_email_fields(&mut self) -> bool {
        let mut changed = false;
        for card in self.cards.values_mut() {
            if card.email.value.trim().is_empty() {
                let email_key = card
                    .custom_fields
                    .keys()
                    .find(|k| matches!(k.trim().to_ascii_lowercase().as_str(), "email" | "e-mail" | "e_mail"))
                    .cloned();
                if let Some(k) = email_key {
                    if let Some(cf) = card.custom_fields.remove(&k) {
                        card.email = LwwField::new(cf.value.value, cf.hlc, cf.author_device);
                        changed = true;
                    }
                }
            }
        }
        changed
    }
}
