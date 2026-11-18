use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{verify_vault_signature, SignatureVerification};
use crate::model::{Card, CardKind, Hlc, LwwField, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupeScope {
    Global,
    Folder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeOptions {
    pub dedupe_enabled: bool,
    pub match_title: bool,
    pub match_username: bool,
    pub match_url: bool,
    pub case_sensitive: bool,
    pub scope: DedupeScope,
    pub max_field_history: usize,
}

impl Default for MergeOptions {
    fn default() -> Self {
        Self {
            dedupe_enabled: true,
            match_title: true,
            match_username: true,
            match_url: false,
            case_sensitive: false,
            scope: DedupeScope::Global,
            max_field_history: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeChangeKind {
    Added,
    Updated,
    Deduplicated,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeChange {
    pub kind: MergeChangeKind,
    pub card_id: Uuid,
    pub card_kind: CardKind,
    pub title: String,
    pub username: String,
    pub folder: String,
    pub source_label: String,
    /// Names of fields that changed (e.g. ["Password", "Notes"]). Never raw secret values!
    pub changed_fields: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct SourceVaultInput {
    pub label: String,
    pub vault: Vault,
}

#[derive(Debug, Clone)]
pub struct SourceSummary {
    pub label: String,
    pub device_name: String,
    pub card_count: usize,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone)]
pub struct MergeOutcome {
    pub merged: Vault,
    pub sources: Vec<SourceSummary>,
    pub changes: Vec<MergeChange>,
}

fn norm(s: &str, case_sensitive: bool) -> String {
    let trimmed = s.trim();
    if case_sensitive {
        trimmed.to_string()
    } else {
        trimmed.to_lowercase()
    }
}

fn dedupe_key(card: &Card, opts: &MergeOptions) -> Option<String> {
    if !opts.dedupe_enabled || card.is_deleted() {
        return None;
    }
    let title = norm(&card.title.value, opts.case_sensitive);
    if title.is_empty() && opts.match_title {
        return None;
    }
    let mut parts = Vec::new();
    parts.push(match card.kind.value {
        CardKind::Login => "L".to_string(),
        CardKind::Note => "N".to_string(),
    });
    if opts.scope == DedupeScope::Folder {
        parts.push(norm(&card.folder.value, opts.case_sensitive));
    }
    if opts.match_title {
        parts.push(title);
    }
    if opts.match_username {
        parts.push(norm(&card.username.value, opts.case_sensitive));
    }
    if opts.match_url {
        parts.push(norm(&card.url.value, opts.case_sensitive));
    }
    Some(parts.join("\x1f"))
}

fn merge_card_fields(
    target: &mut Card,
    incoming: &Card,
    max_history: usize,
) -> Vec<String> {
    let mut changed = Vec::new();

    if target.kind.merge_from(&incoming.kind, max_history) {
        changed.push("Type".into());
    }
    if target.title.merge_from(&incoming.title, max_history) {
        changed.push("Title".into());
    }
    if target.username.merge_from(&incoming.username, max_history) {
        changed.push("Username".into());
    }
    if target.password.merge_from(&incoming.password, max_history) {
        changed.push("Password".into());
    }
    if target.email.merge_from(&incoming.email, max_history) {
        changed.push("Email".into());
    }
    if target.url.merge_from(&incoming.url, max_history) {
        changed.push("URL".into());
    }
    if target.notes_markdown.merge_from(&incoming.notes_markdown, max_history) {
        changed.push("Notes".into());
    }
    if target.folder.merge_from(&incoming.folder, max_history) {
        changed.push("Folder".into());
    }
    if target.tags.merge_from(&incoming.tags, max_history) {
        changed.push("Tags".into());
    }
    if target.favorite.merge_from(&incoming.favorite, max_history) {
        changed.push("Favorite".into());
    }
    if target.icon_color.merge_from(&incoming.icon_color, max_history) {
        changed.push("Icon Color".into());
    }

    for (k, inc_field) in &incoming.custom_fields {
        match target.custom_fields.get_mut(k) {
            Some(existing) => {
                if existing.merge_from(inc_field, max_history) {
                    changed.push(format!("Field:{k}"));
                }
            }
            None => {
                target.custom_fields.insert(k.clone(), inc_field.clone());
                changed.push(format!("Field:{k}"));
            }
        }
    }

    for (k, inc_att) in &incoming.attachments {
        match target.attachments.get_mut(k) {
            Some(existing) => {
                if existing.merge_from(inc_att, max_history) {
                    changed.push(format!("Attachment:{k}"));
                }
            }
            None => {
                target.attachments.insert(k.clone(), inc_att.clone());
                changed.push(format!("Attachment:{k}"));
            }
        }
    }

    // Merge tombstone state
    match (target.deleted, incoming.deleted) {
        (Some(a), Some(b)) => {
            target.deleted = Some(a.max(b));
        }
        (None, Some(b)) => {
            target.deleted = Some(b);
        }
        (Some(_), None) => {}
        (None, None) => {}
    }

    // Keep earliest creation timestamp
    if incoming.created_at_ms > 0
        && (target.created_at_ms == 0 || incoming.created_at_ms < target.created_at_ms)
    {
        target.created_at_ms = incoming.created_at_ms;
    }

    changed
}

/// Symmetrically merge multiple decrypted vaults using field-level HLC CRDT + optional heuristic dedupe.
pub fn merge_vaults(
    inputs: &[SourceVaultInput],
    merged_vault_name: Option<&str>,
    local_device_name: &str,
    opts: &MergeOptions,
) -> MergeOutcome {
    let base_name = merged_vault_name
        .map(|s| s.to_string())
        .or_else(|| inputs.first().map(|i| i.vault.vault_name.value.clone()))
        .unwrap_or_else(|| "Merged Vault".to_string());

    let mut merged = Vault::new(base_name, local_device_name);
    let mut sources = Vec::with_capacity(inputs.len());
    let mut changes = Vec::new();
    let mut dedupe_index: HashMap<String, Uuid> = HashMap::new();

    for src in inputs {
        let sig = verify_vault_signature(&src.vault);
        sources.push(SourceSummary {
            label: src.label.clone(),
            device_name: src.vault.device_name.clone(),
            card_count: src.vault.active_cards().count(),
            signature: sig,
        });

        // Merge trusted devices
        for (dev_id, dev_info) in &src.vault.trusted_devices {
            merged
                .trusted_devices
                .entry(*dev_id)
                .or_insert_with(|| dev_info.clone());
        }

        // Merge content-addressed blobs
        for (hex, bytes) in &src.vault.blobs {
            merged.blobs.entry(hex.clone()).or_insert_with(|| bytes.clone());
        }

        // Merge vault name LWW
        merged
            .vault_name
            .merge_from(&src.vault.vault_name, opts.max_field_history);

        for card in src.vault.cards.values() {
            if let Some(existing) = merged.cards.get_mut(&card.id) {
                let was_deleted = existing.is_deleted();
                let changed_fields =
                    merge_card_fields(existing, card, opts.max_field_history);
                let now_deleted = existing.is_deleted();

                if !was_deleted && now_deleted {
                    changes.push(MergeChange {
                        kind: MergeChangeKind::Deleted,
                        card_id: existing.id,
                        card_kind: existing.kind.value,
                        title: existing.title.value.clone(),
                        username: existing.username.value.clone(),
                        folder: existing.folder.value.clone(),
                        source_label: src.label.clone(),
                        changed_fields,
                        details: "Marked deleted by newer tombstone".into(),
                    });
                } else if !changed_fields.is_empty() {
                    changes.push(MergeChange {
                        kind: MergeChangeKind::Updated,
                        card_id: existing.id,
                        card_kind: existing.kind.value,
                        title: existing.title.value.clone(),
                        username: existing.username.value.clone(),
                        folder: existing.folder.value.clone(),
                        source_label: src.label.clone(),
                        changed_fields,
                        details: "Merged newer field updates".into(),
                    });
                }
                continue;
            }

            // Heuristic dedupe check if UUID wasn't already present
            if let Some(key) = dedupe_key(card, opts) {
                if let Some(&target_id) = dedupe_index.get(&key) {
                    if let Some(existing) = merged.cards.get_mut(&target_id) {
                        let changed_fields =
                            merge_card_fields(existing, card, opts.max_field_history);
                        changes.push(MergeChange {
                            kind: MergeChangeKind::Deduplicated,
                            card_id: existing.id,
                            card_kind: existing.kind.value,
                            title: existing.title.value.clone(),
                            username: existing.username.value.clone(),
                            folder: existing.folder.value.clone(),
                            source_label: src.label.clone(),
                            changed_fields,
                            details: "Deduplicated matching card by heuristic key".into(),
                        });
                        continue;
                    }
                }
                dedupe_index.insert(key, card.id);
            }

            let cloned = card.clone();
            let is_del = cloned.is_deleted();
            if !is_del {
                changes.push(MergeChange {
                    kind: MergeChangeKind::Added,
                    card_id: cloned.id,
                    card_kind: cloned.kind.value,
                    title: cloned.title.value.clone(),
                    username: cloned.username.value.clone(),
                    folder: cloned.folder.value.clone(),
                    source_label: src.label.clone(),
                    changed_fields: Vec::new(),
                    details: format!("Imported from {}", src.label),
                });
            }
            merged.cards.insert(cloned.id, cloned);
        }
    }

    if let Some(name) = merged_vault_name {
        let hlc = Hlc::tick(Some(merged.vault_name.hlc), merged.device_id);
        merged.vault_name = LwwField::new(name.to_string(), hlc, local_device_name);
    }

    merged.gc_blobs();

    MergeOutcome {
        merged,
        sources,
        changes,
    }
}
