use std::collections::BTreeMap;
use tempfile::TempDir;
use uuid::Uuid;
use vault_core::{
    decrypt_vault, encrypt_vault, generate_password, load_vault_file, merge_vaults,
    save_vault_file, Card, CardKind, Credentials, GeneratorMode, Hlc, KdfParams, LwwField,
    MergeChangeKind, MergeOptions, PasswordGenConfig, SignatureVerification, SourceVaultInput,
    StrengthLevel, Vault, VaultError,
};

#[test]
fn cascade_encrypt_decrypt_sign_and_padding() {
    let mut vault = Vault::new("Personal Safe", "Desktop");
    let dev_id = vault.device_id;
    let mut card = Card::new_login(dev_id, "Desktop", "GitHub");
    card.username
        .set("alice".into(), dev_id, "Desktop", 8);
    card.password
        .set("S3cur3-P@ss!".into(), dev_id, "Desktop", 8);
    card.url
        .set("https://github.com".into(), dev_id, "Desktop", 8);
    vault.add_card(card);

    let creds = Credentials::from_password("master-pw-123").with_keyfile(b"keyfile-bytes".to_vec());
    let ct = encrypt_vault(&mut vault, &creds, KdfParams::test_fast()).unwrap();

    // Header (96) + padded_len (multiple of 4096) + AES-GCM tag (16) + XChaCha20-Poly1305 tag (16)
    let payload_len = ct.len() - vault_core::crypto::HEADER_LEN - 32;
    assert_eq!(payload_len % vault_core::crypto::PADDING_BUCKET, 0);

    let dec = decrypt_vault(&ct, &creds).unwrap();
    assert_eq!(dec.signature, SignatureVerification::VerifiedTrusted);
    assert_eq!(dec.vault.active_cards().count(), 1);
    let loaded = dec.vault.active_cards().next().unwrap();
    assert_eq!(loaded.title.value, "GitHub");
    assert_eq!(loaded.password.value, "S3cur3-P@ss!");

    // Wrong password fails
    let bad_pw = Credentials::from_password("wrong").with_keyfile(b"keyfile-bytes".to_vec());
    assert!(matches!(
        decrypt_vault(&ct, &bad_pw),
        Err(VaultError::AuthenticationFailed)
    ));

    // Missing keyfile fails
    let no_kf = Credentials::from_password("master-pw-123");
    assert!(matches!(
        decrypt_vault(&ct, &no_kf),
        Err(VaultError::AuthenticationFailed)
    ));

    // Flip 1 bit in header salt (AAD) -> fails authentication
    let mut tampered_header = ct.clone();
    tampered_header[30] ^= 0x01;
    assert!(matches!(
        decrypt_vault(&tampered_header, &creds),
        Err(VaultError::AuthenticationFailed)
    ));

    // Flip 1 bit in m_cost_kib MSB (would otherwise request 16 GiB) -> rejected safely
    let mut tampered_kdf = ct.clone();
    tampered_kdf[15] ^= 0x01;
    assert!(matches!(
        decrypt_vault(&tampered_kdf, &creds),
        Err(VaultError::InvalidFormat(_))
    ));

    // Flip 1 bit in ciphertext -> fails authentication
    let mut tampered_ct = ct.clone();
    let last = tampered_ct.len() - 1;
    tampered_ct[last] ^= 0x80;
    assert!(matches!(
        decrypt_vault(&tampered_ct, &creds),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn atomic_save_and_load_with_0600_permissions() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.cdeck");
    let mut vault = Vault::new("Atomic Vault", "Laptop");
    let dev_id = vault.device_id;
    let mut note = Card::new_note(dev_id, "Laptop", "Recovery Codes");
    note.notes_markdown
        .set("# Codes\n- `1234-5678`".into(), dev_id, "Laptop", 8);
    vault.add_card(note);

    let creds = Credentials::from_password("pw");
    save_vault_file(&path, &mut vault, &creds, KdfParams::test_fast()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let dec = load_vault_file(&path, &creds).unwrap();
    assert_eq!(dec.signature, SignatureVerification::VerifiedTrusted);
    assert_eq!(dec.vault.active_cards().count(), 1);
}

#[test]
fn field_level_crdt_merge_keeps_both_device_edits_and_tombstones() {
    let dev_desktop = Uuid::new_v4();
    let dev_phone = Uuid::new_v4();
    let card_id = Uuid::new_v4();
    let deleted_id = Uuid::new_v4();

    let t0 = Hlc::new(1_700_000_000_000, 0, dev_desktop);
    let t1_pw = Hlc::new(1_700_000_010_000, 0, dev_phone);
    let t2_notes = Hlc::new(1_700_000_020_000, 0, dev_desktop);
    let t3_del = Hlc::new(1_700_000_030_000, 0, dev_phone);

    let make_base_card = |id: Uuid| Card {
        id,
        kind: LwwField::new(CardKind::Login, t0, "Desktop"),
        title: LwwField::new("Fastmail".into(), t0, "Desktop"),
        username: LwwField::new("user@fastmail.com".into(), t0, "Desktop"),
        password: LwwField::new("old-pw".into(), t0, "Desktop"),
        email: LwwField::new(String::new(), t0, "Desktop"),
        url: LwwField::new("https://fastmail.com".into(), t0, "Desktop"),
        notes_markdown: LwwField::new("Initial note".into(), t0, "Desktop"),
        folder: LwwField::new("Email".into(), t0, "Desktop"),
        tags: LwwField::new(vec!["mail".into()], t0, "Desktop"),
        favorite: LwwField::new(false, t0, "Desktop"),
        icon_color: LwwField::new(String::new(), t0, "Desktop"),
        custom_fields: BTreeMap::new(),
        attachments: BTreeMap::new(),
        created_at_ms: t0.unix_ms,
        deleted: None,
    };

    // Desktop edited notes_markdown at t2, still has old-pw
    let mut desktop_vault = Vault::new("Main", "Desktop");
    let mut c_desktop = make_base_card(card_id);
    c_desktop.notes_markdown = LwwField::new("Updated markdown from Desktop".into(), t2_notes, "Desktop");
    desktop_vault.cards.insert(card_id, c_desktop);
    desktop_vault.cards.insert(deleted_id, make_base_card(deleted_id));

    // Phone edited password at t1, and deleted deleted_id at t3
    let mut phone_vault = Vault::new("Main", "Phone");
    let mut c_phone = make_base_card(card_id);
    c_phone.password = LwwField::new("SUPER-NEW-PHONE-PW".into(), t1_pw, "Phone");
    phone_vault.cards.insert(card_id, c_phone);

    let mut c_del = make_base_card(deleted_id);
    c_del.deleted = Some(t3_del);
    phone_vault.cards.insert(deleted_id, c_del);

    let outcome = merge_vaults(
        &[
            SourceVaultInput {
                label: "Desktop".into(),
                vault: desktop_vault,
            },
            SourceVaultInput {
                label: "Phone".into(),
                vault: phone_vault,
            },
        ],
        Some("Merged"),
        "Desktop",
        &MergeOptions::default(),
    );

    let merged_card = outcome.merged.cards.get(&card_id).unwrap();
    assert!(!merged_card.is_deleted());
    // Both edits survive!
    assert_eq!(merged_card.password.value, "SUPER-NEW-PHONE-PW");
    assert_eq!(merged_card.notes_markdown.value, "Updated markdown from Desktop");
    // Old password preserved in field history
    assert_eq!(merged_card.password.history.len(), 1);
    assert_eq!(merged_card.password.history[0].value, "old-pw");

    // Deleted card stays deleted
    assert!(outcome.merged.cards.get(&deleted_id).unwrap().is_deleted());
    assert_eq!(outcome.merged.active_cards().count(), 1);

    // Raw password must never appear in MergeChange log
    for ch in &outcome.changes {
        assert!(!ch.details.contains("SUPER-NEW-PHONE-PW"));
        assert!(!ch.details.contains("old-pw"));
    }
}

#[test]
fn heuristic_dedupe_merges_distinct_uuids() {
    let mut v1 = Vault::new("A", "Desktop");
    let mut c1 = Card::new_login(v1.device_id, "Desktop", "GitLab");
    c1.username.value = "dev".into();
    c1.password.value = "pw1".into();
    v1.add_card(c1);

    let mut v2 = Vault::new("B", "Phone");
    let mut c2 = Card::new_login(v2.device_id, "Phone", "  gitlab ");
    c2.username.value = "DEV".into();
    c2.password.value = "pw2".into();
    c2.password.hlc = Hlc::new(u64::MAX / 2, 0, v2.device_id);
    v2.add_card(c2);

    let outcome = merge_vaults(
        &[
            SourceVaultInput {
                label: "A".into(),
                vault: v1,
            },
            SourceVaultInput {
                label: "B".into(),
                vault: v2,
            },
        ],
        None,
        "Desktop",
        &MergeOptions::default(),
    );

    assert_eq!(outcome.merged.active_cards().count(), 1);
    let only = outcome.merged.active_cards().next().unwrap();
    assert_eq!(only.password.value, "pw2");
    assert!(outcome
        .changes
        .iter()
        .any(|c| c.kind == MergeChangeKind::Deduplicated));
}

#[test]
fn password_generator_constraints_and_entropy() {
    let cfg = PasswordGenConfig {
        mode: GeneratorMode::RandomChars,
        length: 24,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: false,
        exclude_ambiguous: true,
        ..Default::default()
    };
    let gen = generate_password(&cfg);
    assert_eq!(gen.password.len(), 24);
    for ch in ['0', 'O', '1', 'l', 'I'] {
        assert!(!gen.password.contains(ch), "contained ambiguous char {ch}");
    }
    assert!(gen.entropy_bits > 100.0);
    assert_eq!(gen.strength, StrengthLevel::VeryStrong);

    let pp = generate_password(&PasswordGenConfig {
        mode: GeneratorMode::Passphrase,
        word_count: 5,
        separator: "-".into(),
        capitalize_words: true,
        append_number: true,
        ..Default::default()
    });
    assert_eq!(pp.password.split('-').count(), 5);
    assert!(pp.entropy_bits > 40.0);
}
