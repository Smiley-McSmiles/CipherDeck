use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_core::{
    generate_password, import_kdbx, load_vault_file, merge_vaults, save_vault_file, Credentials,
    GeneratorMode, KdfParams, MergeChangeKind, MergeOptions, PasswordGenConfig,
    SignatureVerification, SourceVaultInput, Vault,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "cipherdeck",
    version,
    about = "CipherDeck (.cdeck) — Cascade-encrypted CRDT password & notes vault. Run with no arguments to launch the GUI."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new empty .cdeck vault
    Init {
        output: PathBuf,
        #[arg(long, default_value = "My CipherDeck")]
        name: String,
        #[arg(long, default_value = "Desktop")]
        device: String,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Inspect an existing .cdeck vault (counts, KDF params, Ed25519 signature status)
    Info {
        vault: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Import a KeePass .kdbx (v3/v4) database into a .cdeck vault
    ImportKdbx {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        kdbx_password: Option<String>,
        #[arg(long)]
        kdbx_keyfile: Option<PathBuf>,
        #[arg(long)]
        out_password: Option<String>,
        #[arg(long)]
        out_keyfile: Option<PathBuf>,
        #[arg(long, default_value = "Desktop")]
        device: String,
    },
    /// Merge two or more .cdeck vaults with field-level CRDT + heuristic deduplication
    Merge {
        inputs: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        no_dedupe: bool,
        #[arg(long)]
        match_url: bool,
        #[arg(long)]
        case_sensitive: bool,
        #[arg(long, default_value = "Desktop")]
        device: String,
    },
    /// Generate a strong CSPRNG password or passphrase
    Gen {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_upper: bool,
        #[arg(long)]
        no_lower: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        no_ambiguous: bool,
        #[arg(long)]
        passphrase: bool,
        #[arg(long, default_value_t = 5)]
        words: usize,
        #[arg(long, default_value = "-")]
        separator: String,
    },
}

fn prompt_password(prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
    let pw = Zeroizing::new(rpassword::prompt_password(prompt)?);
    if confirm {
        let pw2 = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if pw.as_str() != pw2.as_str() {
            bail!("passwords did not match");
        }
    }
    Ok(pw)
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Init {
            output,
            name,
            device,
            keyfile,
            password,
        } => {
            if output.exists() {
                bail!("refusing to overwrite existing file: {}", output.display());
            }
            let pw = match password {
                Some(p) => Zeroizing::new(p),
                None => prompt_password("New vault master password: ", true)?,
            };
            let creds = Credentials::from_password_and_keyfile_path(
                pw.as_str(),
                keyfile.as_deref(),
            )?;
            let mut vault = Vault::new(name, device);
            save_vault_file(&output, &mut vault, &creds, KdfParams::strong())?;
            println!("Created {} (0600)", output.display());
        }
        Command::Info {
            vault,
            keyfile,
            password,
        } => {
            let pw = match password {
                Some(p) => Zeroizing::new(p),
                None => prompt_password("Vault password: ", false)?,
            };
            let creds = Credentials::from_password_and_keyfile_path(
                pw.as_str(),
                keyfile.as_deref(),
            )?;
            let dec = load_vault_file(&vault, &creds)?;
            let sig = match dec.signature {
                SignatureVerification::VerifiedTrusted => "Ed25519 Verified (Trusted Device)",
                SignatureVerification::VerifiedUnknownDevice => "Ed25519 Valid (Unknown Device)",
                SignatureVerification::InvalidSignature => "INVALID SIGNATURE",
                SignatureVerification::Unsigned => "Unsigned",
            };
            println!("Vault:       {}", dec.vault.vault_name.value);
            println!("Device:      {}", dec.vault.device_name);
            println!(
                "Active:      {} cards ({} trashed)",
                dec.vault.active_cards().count(),
                dec.vault.trashed_cards().count()
            );
            println!(
                "Argon2id:    {} MiB, {} iter, {} lanes",
                dec.header.kdf.m_cost_kib / 1024,
                dec.header.kdf.t_cost,
                dec.header.kdf.p_cost
            );
            println!("Signature:   {sig}");
        }
        Command::ImportKdbx {
            input,
            output,
            kdbx_password,
            kdbx_keyfile,
            out_password,
            out_keyfile,
            device,
        } => {
            if output.exists() {
                bail!("refusing to overwrite existing file: {}", output.display());
            }
            let kdbx_pw = match kdbx_password {
                Some(p) => Zeroizing::new(p),
                None => prompt_password("KDBX password (Enter if keyfile-only): ", false)?,
            };
            let mut vault = import_kdbx(
                &input,
                Some(kdbx_pw.as_str()),
                kdbx_keyfile.as_deref(),
                &device,
            )
            .context("KDBX import failed")?;

            let out_pw = match out_password {
                Some(p) => Zeroizing::new(p),
                None => prompt_password("New .cdeck password: ", true)?,
            };
            let creds = Credentials::from_password_and_keyfile_path(
                out_pw.as_str(),
                out_keyfile.as_deref(),
            )?;
            let count = vault.active_cards().count();
            save_vault_file(&output, &mut vault, &creds, KdfParams::strong())?;
            println!("Imported {count} cards into {} (0600)", output.display());
        }
        Command::Merge {
            inputs,
            output,
            password,
            keyfile,
            name,
            dry_run,
            no_dedupe,
            match_url,
            case_sensitive,
            device,
        } => {
            if inputs.len() < 2 {
                bail!("provide at least 2 .cdeck files to merge");
            }
            if !dry_run && inputs.iter().any(|p| p == &output) {
                bail!("output path cannot be one of the input files");
            }
            let pw = match password {
                Some(p) => Zeroizing::new(p),
                None => prompt_password("Shared vault password: ", false)?,
            };
            let creds = Credentials::from_password_and_keyfile_path(
                pw.as_str(),
                keyfile.as_deref(),
            )?;

            let mut loaded = Vec::with_capacity(inputs.len());
            for path in &inputs {
                let dec = load_vault_file(path, &creds)
                    .with_context(|| format!("failed to unlock {}", path.display()))?;
                loaded.push(SourceVaultInput {
                    label: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("vault")
                        .to_string(),
                    vault: dec.vault,
                });
            }

            let opts = MergeOptions {
                dedupe_enabled: !no_dedupe,
                match_url,
                case_sensitive,
                ..Default::default()
            };
            let mut outcome = merge_vaults(&loaded, name.as_deref(), &device, &opts);

            for src in &outcome.sources {
                println!(
                    "Source: {} ({} active cards, sig={:?})",
                    src.label, src.card_count, src.signature
                );
            }
            let added = outcome
                .changes
                .iter()
                .filter(|c| c.kind == MergeChangeKind::Added)
                .count();
            let updated = outcome
                .changes
                .iter()
                .filter(|c| c.kind == MergeChangeKind::Updated)
                .count();
            let deduped = outcome
                .changes
                .iter()
                .filter(|c| c.kind == MergeChangeKind::Deduplicated)
                .count();
            let deleted = outcome
                .changes
                .iter()
                .filter(|c| c.kind == MergeChangeKind::Deleted)
                .count();
            println!(
                "Result: {} active cards (Added: {added}, Updated: {updated}, Deduplicated: {deduped}, Deleted: {deleted})",
                outcome.merged.active_cards().count()
            );

            if !dry_run {
                save_vault_file(&output, &mut outcome.merged, &creds, KdfParams::strong())?;
                println!("Saved merged vault to {} (0600)", output.display());
            } else {
                println!("Dry-run complete; nothing written.");
            }
        }
        Command::Gen {
            length,
            no_upper,
            no_lower,
            no_digits,
            no_symbols,
            no_ambiguous,
            passphrase,
            words,
            separator,
        } => {
            let cfg = PasswordGenConfig {
                mode: if passphrase {
                    GeneratorMode::Passphrase
                } else {
                    GeneratorMode::RandomChars
                },
                length,
                uppercase: !no_upper,
                lowercase: !no_lower,
                digits: !no_digits,
                symbols: !no_symbols,
                exclude_ambiguous: no_ambiguous,
                word_count: words,
                separator,
                ..Default::default()
            };
            let res = generate_password(&cfg);
            println!("{}", res.password.as_str());
            eprintln!(
                "Entropy: {:.1} bits ({})",
                res.entropy_bits,
                res.strength.label()
            );
        }
    }
    Ok(())
}
