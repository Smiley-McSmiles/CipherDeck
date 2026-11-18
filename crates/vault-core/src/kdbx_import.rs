use std::fs::File;
use std::path::Path;

use keepass::db::{Entry, Group, Value};
use keepass::{Database, DatabaseKey};
use uuid::Uuid;

use crate::error::{Result, VaultError};
use crate::model::{
    now_unix_ms, Card, CardKind, CustomFieldValue, Hlc, LwwField, Vault,
};

fn entry_mtime_ms(entry: &Entry) -> u64 {
    if let Some(dt) = entry.times.get_last_modification() {
        let ts = dt.and_utc().timestamp_millis();
        if ts > 0 {
            return ts as u64;
        }
    }
    now_unix_ms()
}

fn entry_ctime_ms(entry: &Entry) -> u64 {
    if let Some(dt) = entry.times.get_creation() {
        let ts = dt.and_utc().timestamp_millis();
        if ts > 0 {
            return ts as u64;
        }
    }
    entry_mtime_ms(entry)
}

fn value_as_str(val: &Value) -> String {
    match val {
        Value::Unprotected(s) => s.clone(),
        Value::Protected(sec) => String::from_utf8_lossy(sec.unsecure()).to_string(),
        Value::Bytes(b) => String::from_utf8_lossy(b).to_string(),
    }
}

fn is_protected(val: &Value) -> bool {
    matches!(val, Value::Protected(_))
}

fn import_group_with_exact_path(
    group: &Group,
    exact_path: &[String],
    device_id: Uuid,
    device_name: &str,
    recycle_bin_uuid: Option<Uuid>,
    vault: &mut Vault,
) {
    if Some(group.uuid) == recycle_bin_uuid {
        for entry in &group.entries {
            let mut card = convert_entry(entry, "", device_id, device_name);
            card.deleted = Some(Hlc::new(entry_mtime_ms(entry), 0, device_id));
            vault.cards.insert(card.id, card);
        }
        return;
    }

    let folder_str = exact_path.join("/");
    for entry in &group.entries {
        let card = convert_entry(entry, &folder_str, device_id, device_name);
        vault.cards.insert(card.id, card);
    }
    for sub in &group.groups {
        let mut next_path = exact_path.to_vec();
        next_path.push(sub.name.clone());
        import_group_with_exact_path(
            sub,
            &next_path,
            device_id,
            device_name,
            recycle_bin_uuid,
            vault,
        );
    }
}

fn convert_entry(
    entry: &Entry,
    folder_str: &str,
    device_id: Uuid,
    device_name: &str,
) -> Card {
    let mtime = entry_mtime_ms(entry);
    let ctime = entry_ctime_ms(entry);
    let hlc = Hlc::new(mtime, 0, device_id);

    let title = entry.get_title().unwrap_or_default().to_string();
    let username = entry.get_username().unwrap_or_default().to_string();
    let password = entry.get_password().unwrap_or_default().to_string();
    let url = entry.get_url().unwrap_or_default().to_string();
    let notes = entry.get("Notes").unwrap_or_default().to_string();

    let kind = if username.is_empty() && password.is_empty() && url.is_empty() && !notes.is_empty()
    {
        CardKind::Note
    } else {
        CardKind::Login
    };

    let mut card = Card {
        id: entry.uuid,
        kind: LwwField::new(kind, hlc, device_name),
        title: LwwField::new(title, hlc, device_name),
        username: LwwField::new(username, hlc, device_name),
        password: LwwField::new(password, hlc, device_name),
        email: LwwField::new(String::new(), hlc, device_name),
        url: LwwField::new(url, hlc, device_name),
        notes_markdown: LwwField::new(notes, hlc, device_name),
        folder: LwwField::new(folder_str.to_string(), hlc, device_name),
        tags: LwwField::new(entry.tags.clone(), hlc, device_name),
        favorite: LwwField::new(false, hlc, device_name),
        icon_color: LwwField::new(String::new(), hlc, device_name),
        custom_fields: std::collections::BTreeMap::new(),
        attachments: std::collections::BTreeMap::new(),
        created_at_ms: ctime,
        deleted: None,
    };

    for (k, v) in &entry.fields {
        if matches!(
            k.as_str(),
            "Title" | "UserName" | "Password" | "URL" | "Notes"
        ) {
            continue;
        }
        let key_norm = k.trim().to_ascii_lowercase();
        if matches!(key_norm.as_str(), "email" | "e-mail" | "e_mail") && card.email.value.is_empty() {
            card.email = LwwField::new(value_as_str(v), hlc, device_name);
            continue;
        }
        card.custom_fields.insert(
            k.clone(),
            LwwField::new(
                CustomFieldValue {
                    value: value_as_str(v),
                    secret: is_protected(v),
                },
                hlc,
                device_name,
            ),
        );
    }

    card
}

/// Import a KeePass `.kdbx` (KDBX 3 / 4) database into a new `Vault`.
pub fn import_kdbx(
    path: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    device_name: &str,
) -> Result<Vault> {
    let mut db_key = DatabaseKey::new();
    if let Some(pw) = password {
        if !pw.is_empty() {
            db_key = db_key.with_password(pw);
        }
    }
    if let Some(kf_path) = keyfile {
        let mut kf_file = File::open(kf_path)?;
        db_key = db_key
            .with_keyfile(&mut kf_file)
            .map_err(|e| VaultError::KdbxImport(format!("failed to read keyfile: {e}")))?;
    }

    let mut file = File::open(path)?;
    let db = Database::open(&mut file, db_key)
        .map_err(|e| VaultError::KdbxImport(format!("failed to unlock KDBX: {e}")))?;

    let db_name = db
        .meta
        .database_name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Imported Vault")
                .to_string()
        });

    let mut vault = Vault::new(db_name, device_name);
    let dev_id = vault.device_id;
    let recycle_bin_uuid = db.meta.recyclebin_uuid;

    for entry in &db.root.entries {
        let card = convert_entry(entry, "", dev_id, device_name);
        vault.cards.insert(card.id, card);
    }
    for sub in &db.root.groups {
        let sub_path = vec![sub.name.clone()];
        import_group_with_exact_path(
            sub,
            &sub_path,
            dev_id,
            device_name,
            recycle_bin_uuid,
            &mut vault,
        );
    }

    for del in &db.deleted_objects.objects {
        let del_ms = del.deletion_time.and_utc().timestamp_millis().max(0) as u64;
        let hlc = Hlc::new(del_ms, 0, dev_id);
        vault.cards.entry(del.uuid).or_insert_with(|| {
            let mut c = Card::new_login(dev_id, device_name, "");
            c.id = del.uuid;
            c.deleted = Some(hlc);
            c
        });
    }

    Ok(vault)
}
