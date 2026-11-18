use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use gtk::gio;
use gtk::glib;
use vault_core::{
    import_kdbx, load_vault_file, merge_vaults, save_vault_file, Credentials, DedupeScope,
    KdfParams, MergeChangeKind, MergeOptions, MergeOutcome, SignatureVerification,
    SourceVaultInput,
};

#[derive(Clone)]
struct MergeSourceEntry {
    path: PathBuf,
    per_file_pw: String,
    per_file_kf: Option<PathBuf>,
}

pub fn present_merge_dialog<F>(
    parent: &adw::ApplicationWindow,
    initial_paths: Vec<PathBuf>,
    on_saved: F,
) where
    F: Fn(PathBuf, Credentials) + 'static,
{
    let dialog = adw::Dialog::builder()
        .title("Merge & Deduplicate Vaults")
        .content_width(760)
        .content_height(680)
        .build();

    let nav = adw::NavigationView::new();
    dialog.set_child(Some(&nav));

    let sources: Rc<RefCell<Vec<MergeSourceEntry>>> = Rc::new(RefCell::new(
        initial_paths
            .into_iter()
            .map(|p| MergeSourceEntry {
                path: p,
                per_file_pw: String::new(),
                per_file_kf: None,
            })
            .collect(),
    ));
    let on_saved = Rc::new(on_saved);

    // Setup Page
    let setup_toolbar = adw::ToolbarView::new();
    let setup_hb = adw::HeaderBar::new();
    setup_toolbar.add_top_bar(&setup_hb);

    let add_btn = gtk::Button::with_label("Add File…");
    add_btn.set_icon_name("list-add-symbolic");
    setup_hb.pack_start(&add_btn);

    let preview_btn = gtk::Button::with_label("Preview Merge");
    preview_btn.add_css_class("suggested-action");
    setup_hb.pack_end(&preview_btn);

    let scroll = gtk::ScrolledWindow::new();
    scroll.set_vexpand(true);
    let clamp = adw::Clamp::builder()
        .maximum_size(700)
        .margin_top(16)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 16);
    clamp.set_child(Some(&content));
    scroll.set_child(Some(&clamp));
    setup_toolbar.set_content(Some(&scroll));

    // 1. Source files group
    let files_group = adw::PreferencesGroup::builder()
        .title("Source Archives (.cdeck or .kdbx)")
        .description("Add two or more vaults to merge symmetrically at field level. Raw passwords are never shown in previews.")
        .build();
    let files_list = gtk::ListBox::new();
    files_list.set_selection_mode(gtk::SelectionMode::None);
    files_list.add_css_class("boxed-list");
    files_group.add(&files_list);
    content.append(&files_group);

    // 2. Shared credentials group
    let cred_group = adw::PreferencesGroup::builder()
        .title("Shared Credentials")
        .description("Used for every file without a per-file override")
        .build();
    let shared_pw_row = adw::PasswordEntryRow::builder()
        .title("Master Password")
        .build();
    cred_group.add(&shared_pw_row);

    let shared_kf_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let shared_kf_row = adw::ActionRow::builder()
        .title("Keyfile (Optional)")
        .subtitle("None selected")
        .build();
    let shared_kf_btn = gtk::Button::with_label("Choose…");
    shared_kf_btn.set_valign(gtk::Align::Center);
    shared_kf_row.add_suffix(&shared_kf_btn);
    cred_group.add(&shared_kf_row);
    content.append(&cred_group);

    // 3. Deduplication options (roll-down)
    let opts_group = adw::PreferencesGroup::builder()
        .title("Merge &amp; Deduplication Rules")
        .build();
    let opts_exp = adw::ExpanderRow::builder()
        .title("Heuristic Deduplication")
        .subtitle("Match entries imported separately without shared UUIDs")
        .build();
    let sw_dedupe = adw::SwitchRow::builder()
        .title("Enable Heuristic Deduplication")
        .active(true)
        .build();
    let sw_title = adw::SwitchRow::builder()
        .title("Match Title")
        .active(true)
        .build();
    let sw_user = adw::SwitchRow::builder()
        .title("Match Username")
        .active(true)
        .build();
    let sw_url = adw::SwitchRow::builder()
        .title("Match URL")
        .active(false)
        .build();
    let sw_case = adw::SwitchRow::builder()
        .title("Case-Sensitive Matching")
        .active(false)
        .build();
    let scope_row = adw::ComboRow::builder()
        .title("Deduplication Scope")
        .model(&gtk::StringList::new(&["Global (entire vault)", "Within same folder"]))
        .build();
    opts_exp.add_row(&sw_dedupe);
    opts_exp.add_row(&sw_title);
    opts_exp.add_row(&sw_user);
    opts_exp.add_row(&sw_url);
    opts_exp.add_row(&sw_case);
    opts_exp.add_row(&scope_row);
    opts_group.add(&opts_exp);
    content.append(&opts_group);

    // 4. Output vault name
    let out_group = adw::PreferencesGroup::builder().title("Merged Vault").build();
    let out_name_row = adw::EntryRow::builder()
        .title("Vault Name")
        .text("Merged CipherDeck")
        .build();
    out_group.add(&out_name_row);
    content.append(&out_group);

    let status_lbl = gtk::Label::new(None);
    status_lbl.add_css_class("caption");
    status_lbl.add_css_class("dim-label");
    content.append(&status_lbl);

    let setup_page = adw::NavigationPage::builder()
        .title("Merge Vaults")
        .child(&setup_toolbar)
        .build();
    nav.add(&setup_page);

    let rebuild_files: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
    {
        let sources = sources.clone();
        let files_list = files_list.clone();
        let preview_btn = preview_btn.clone();
        let rebuild_ref = rebuild_files.clone();
        let parent_win = parent.clone();

        let fn_rc: Rc<dyn Fn()> = Rc::new(move || {
            while let Some(child) = files_list.first_child() {
                files_list.remove(&child);
            }
            let list = sources.borrow();
            preview_btn.set_sensitive(list.len() >= 2);
            if list.is_empty() {
                let empty = adw::ActionRow::builder()
                    .title("No source files added yet")
                    .subtitle("Click Add File… to select .cdeck or .kdbx files")
                    .build();
                files_list.append(&empty);
                return;
            }
            for (idx, entry) in list.iter().enumerate() {
                let fname = entry
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("vault")
                    .to_string();
                let ext = entry
                    .path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_uppercase();
                let exp = adw::ExpanderRow::builder()
                    .title(glib::markup_escape_text(&fname))
                    .subtitle(glib::markup_escape_text(&format!("{} · {}", ext, entry.path.display())))
                    .build();

                let rem_btn = gtk::Button::from_icon_name("user-trash-symbolic");
                rem_btn.set_valign(gtk::Align::Center);
                rem_btn.add_css_class("flat");
                {
                    let sources = sources.clone();
                    let rebuild_ref = rebuild_ref.clone();
                    rem_btn.connect_clicked(move |_| {
                        sources.borrow_mut().remove(idx);
                        if let Some(f) = rebuild_ref.borrow().as_ref() {
                            f();
                        }
                    });
                }
                exp.add_suffix(&rem_btn);

                let pw_override = adw::PasswordEntryRow::builder()
                    .title("Password Override (optional)")
                    .build();
                pw_override.set_text(&entry.per_file_pw);
                {
                    let sources = sources.clone();
                    pw_override.connect_changed(move |r| {
                        if let Some(s) = sources.borrow_mut().get_mut(idx) {
                            s.per_file_pw = r.text().to_string();
                        }
                    });
                }
                exp.add_row(&pw_override);

                let kf_sub = entry
                    .per_file_kf
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("Use shared keyfile");
                let kf_row = adw::ActionRow::builder()
                    .title("Keyfile Override")
                    .subtitle(kf_sub)
                    .build();
                let kf_pick = gtk::Button::with_label("Choose…");
                kf_pick.set_valign(gtk::Align::Center);
                {
                    let sources = sources.clone();
                    let rebuild_ref = rebuild_ref.clone();
                    let parent_win = parent_win.clone();
                    kf_pick.connect_clicked(move |_| {
                        let fd = gtk::FileDialog::builder().title("Select Keyfile").build();
                        let sources = sources.clone();
                        let rebuild_ref = rebuild_ref.clone();
                        fd.open(Some(&parent_win), gio::Cancellable::NONE, move |res| {
                            if let Ok(file) = res {
                                if let Some(path) = file.path() {
                                    if let Some(s) = sources.borrow_mut().get_mut(idx) {
                                        s.per_file_kf = Some(path);
                                    }
                                    if let Some(f) = rebuild_ref.borrow().as_ref() {
                                        f();
                                    }
                                }
                            }
                        });
                    });
                }
                kf_row.add_suffix(&kf_pick);
                exp.add_row(&kf_row);

                files_list.append(&exp);
            }
        });
        *rebuild_files.borrow_mut() = Some(fn_rc.clone());
        fn_rc();
    }

    // Add file button
    {
        let parent_win = parent.clone();
        let sources = sources.clone();
        let rebuild_files = rebuild_files.clone();
        add_btn.connect_clicked(move |_| {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("CipherDeck & KeePass (*.cdeck, *.kdbx)"));
            filter.add_pattern("*.cdeck");
            filter.add_pattern("*.wsafe");
            filter.add_pattern("*.kdbx");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&filter);

            let fd = gtk::FileDialog::builder()
                .title("Select Vaults to Merge")
                .filters(&filters)
                .build();
            let sources = sources.clone();
            let rebuild_files = rebuild_files.clone();
            fd.open_multiple(Some(&parent_win), gio::Cancellable::NONE, move |res| {
                if let Ok(list) = res {
                    for i in 0..list.n_items() {
                        if let Some(obj) = list.item(i) {
                            if let Ok(file) = obj.downcast::<gio::File>() {
                                if let Some(p) = file.path() {
                                    let mut vec = sources.borrow_mut();
                                    if !vec.iter().any(|e| e.path == p) {
                                        vec.push(MergeSourceEntry {
                                            path: p,
                                            per_file_pw: String::new(),
                                            per_file_kf: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    if let Some(f) = rebuild_files.borrow().as_ref() {
                        f();
                    }
                }
            });
        });
    }

    // Shared keyfile button
    {
        let parent_win = parent.clone();
        let shared_kf_path = shared_kf_path.clone();
        let shared_kf_row = shared_kf_row.clone();
        shared_kf_btn.connect_clicked(move |_| {
            let fd = gtk::FileDialog::builder().title("Select Shared Keyfile").build();
            let shared_kf_path = shared_kf_path.clone();
            let shared_kf_row = shared_kf_row.clone();
            fd.open(Some(&parent_win), gio::Cancellable::NONE, move |res| {
                if let Ok(file) = res {
                    if let Some(p) = file.path() {
                        shared_kf_row.set_subtitle(&p.display().to_string());
                        *shared_kf_path.borrow_mut() = Some(p);
                    }
                }
            });
        });
    }

    // Preview Merge button -> background worker
    {
        let sources = sources.clone();
        let shared_pw_row = shared_pw_row.clone();
        let shared_kf_path = shared_kf_path.clone();
        let sw_dedupe = sw_dedupe.clone();
        let sw_title = sw_title.clone();
        let sw_user = sw_user.clone();
        let sw_url = sw_url.clone();
        let sw_case = sw_case.clone();
        let scope_row = scope_row.clone();
        let out_name_row = out_name_row.clone();
        let status_lbl = status_lbl.clone();
        let preview_btn = preview_btn.clone();
        let nav = nav.clone();
        let parent_win = parent.clone();
        let dialog_ref = dialog.clone();
        let on_saved = on_saved.clone();

        preview_btn.connect_clicked(move |btn| {
            let entries = sources.borrow().clone();
            let shared_pw = shared_pw_row.text().to_string();
            let shared_kf = shared_kf_path.borrow().clone();
            let vault_name = out_name_row.text().to_string();
            let opts = MergeOptions {
                dedupe_enabled: sw_dedupe.is_active(),
                match_title: sw_title.is_active(),
                match_username: sw_user.is_active(),
                match_url: sw_url.is_active(),
                case_sensitive: sw_case.is_active(),
                scope: if scope_row.selected() == 1 {
                    DedupeScope::Folder
                } else {
                    DedupeScope::Global
                },
                max_field_history: 16,
            };

            btn.set_sensitive(false);
            status_lbl.set_text("Unlocking archives and computing field-level CRDT merge…");

            let (tx, rx) = std::sync::mpsc::channel::<Result<(MergeOutcome, Credentials), String>>();
            std::thread::spawn(move || {
                let res = (|| -> Result<(MergeOutcome, Credentials), String> {
                    let mut loaded = Vec::with_capacity(entries.len());
                    for e in &entries {
                        let pw = if !e.per_file_pw.is_empty() {
                            e.per_file_pw.clone()
                        } else {
                            shared_pw.clone()
                        };
                        let kf = e.per_file_kf.as_deref().or(shared_kf.as_deref());
                        let label = e
                            .path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("vault")
                            .to_string();

                        let is_kdbx = e
                            .path
                            .extension()
                            .and_then(|s| s.to_str())
                            .map(|s| s.eq_ignore_ascii_case("kdbx"))
                            .unwrap_or(false);

                        let vault = if is_kdbx {
                            import_kdbx(&e.path, Some(&pw), kf, "Desktop")
                                .map_err(|err| format!("{label}: {err}"))?
                        } else {
                            let creds = Credentials::from_password_and_keyfile_path(&pw, kf)
                                .map_err(|err| format!("{label}: {err}"))?;
                            load_vault_file(&e.path, &creds)
                                .map_err(|err| format!("{label}: {err}"))?
                                .vault
                        };
                        loaded.push(SourceVaultInput { label, vault });
                    }
                    let outcome = merge_vaults(
                        &loaded,
                        if vault_name.trim().is_empty() {
                            None
                        } else {
                            Some(vault_name.trim())
                        },
                        "Desktop",
                        &opts,
                    );
                    let save_creds = Credentials::from_password_and_keyfile_path(
                        &shared_pw,
                        shared_kf.as_deref(),
                    )
                    .map_err(|err| err.to_string())?;
                    Ok((outcome, save_creds))
                })();
                let _ = tx.send(res);
            });

            let btn_clone = btn.clone();
            let status_lbl = status_lbl.clone();
            let nav = nav.clone();
            let parent_win = parent_win.clone();
            let dialog_ref = dialog_ref.clone();
            let on_saved = on_saved.clone();
            let entries_for_check = sources.borrow().clone();

            glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                match rx.try_recv() {
                    Ok(Ok((outcome, save_creds))) => {
                        btn_clone.set_sensitive(true);
                        status_lbl.set_text("");
                        let res_page = build_merge_results_page(
                            &parent_win,
                            &dialog_ref,
                            outcome,
                            save_creds,
                            &entries_for_check,
                            on_saved.clone(),
                        );
                        nav.push(&res_page);
                        glib::ControlFlow::Break
                    }
                    Ok(Err(err)) => {
                        btn_clone.set_sensitive(true);
                        status_lbl.set_text(&format!("Error: {err}"));
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        btn_clone.set_sensitive(true);
                        status_lbl.set_text("Merge worker stopped unexpectedly.");
                        glib::ControlFlow::Break
                    }
                }
            });
        });
    }

    dialog.present(Some(parent));
}

fn build_merge_results_page<F>(
    parent: &adw::ApplicationWindow,
    dialog: &adw::Dialog,
    outcome: MergeOutcome,
    save_creds: Credentials,
    sources: &[MergeSourceEntry],
    on_saved: Rc<F>,
) -> adw::NavigationPage
where
    F: Fn(PathBuf, Credentials) + 'static,
{
    let tv = adw::ToolbarView::new();
    let hb = adw::HeaderBar::new();
    tv.add_top_bar(&hb);

    let save_btn = gtk::Button::with_label("Save Merged .cdeck…");
    save_btn.add_css_class("suggested-action");
    hb.pack_end(&save_btn);

    let scroll = gtk::ScrolledWindow::new();
    scroll.set_vexpand(true);
    let clamp = adw::Clamp::builder()
        .maximum_size(700)
        .margin_top(16)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 14);
    clamp.set_child(Some(&bx));
    scroll.set_child(Some(&clamp));
    tv.set_content(Some(&scroll));

    // Source verification summary
    let src_group = adw::PreferencesGroup::builder()
        .title("Verified Sources")
        .build();
    for s in &outcome.sources {
        let sig_txt = match s.signature {
            SignatureVerification::VerifiedTrusted => "Ed25519 Verified",
            SignatureVerification::VerifiedUnknownDevice => "Ed25519 Signed (New Device)",
            SignatureVerification::InvalidSignature => "Invalid Signature!",
            SignatureVerification::Unsigned => "Imported / Unsigned",
        };
        let row = adw::ActionRow::builder()
            .title(&s.label)
            .subtitle(format!("{} active cards · Device: {} · {}", s.card_count, s.device_name, sig_txt))
            .build();
        src_group.add(&row);
    }
    bx.append(&src_group);

    // Change log list
    let ch_group = adw::PreferencesGroup::builder()
        .title(format!(
            "Merge Plan — {} Active Cards ({} changes)",
            outcome.merged.active_cards().count(),
            outcome.changes.len()
        ))
        .build();
    let ch_list = gtk::ListBox::new();
    ch_list.set_selection_mode(gtk::SelectionMode::None);
    ch_list.add_css_class("boxed-list");

    if outcome.changes.is_empty() {
        ch_list.append(
            &adw::ActionRow::builder()
                .title("No differences detected")
                .build(),
        );
    } else {
        for ch in &outcome.changes {
            let badge_txt = match ch.kind {
                MergeChangeKind::Added => "ADDED",
                MergeChangeKind::Updated => "UPDATED",
                MergeChangeKind::Deduplicated => "DEDUPED",
                MergeChangeKind::Deleted => "DELETED",
            };
            let badge_cls = match ch.kind {
                MergeChangeKind::Added => "badge-added",
                MergeChangeKind::Updated => "badge-updated",
                MergeChangeKind::Deduplicated => "badge-dedupe",
                MergeChangeKind::Deleted => "badge-deleted",
            };
            let fields_str = if ch.changed_fields.is_empty() {
                ch.details.clone()
            } else {
                format!("Fields: {} · {}", ch.changed_fields.join(", "), ch.details)
            };
            let title_text = if ch.title.is_empty() {
                "(Untitled)".to_string()
            } else {
                ch.title.clone()
            };
            let row = adw::ActionRow::builder()
                .title(&title_text)
                .subtitle(&format!("{} · {}", ch.source_label, fields_str))
                .build();
            let pill = gtk::Label::new(Some(badge_txt));
            pill.set_valign(gtk::Align::Center);
            pill.add_css_class("label-chip");
            pill.add_css_class(badge_cls);
            row.add_suffix(&pill);
            ch_list.append(&row);
        }
    }
    ch_group.add(&ch_list);
    bx.append(&ch_group);

    let merged_rc = Rc::new(RefCell::new(outcome.merged));
    let input_paths: Vec<PathBuf> = sources.iter().map(|s| s.path.clone()).collect();
    let parent_win = parent.clone();
    let dialog_ref = dialog.clone();

    save_btn.connect_clicked(move |_| {
        let fd = gtk::FileDialog::builder()
            .title("Save Merged Vault")
            .initial_name("merged.cdeck")
            .build();
        let merged_rc = merged_rc.clone();
        let save_creds = save_creds.clone();
        let input_paths = input_paths.clone();
        let parent_win = parent_win.clone();
        let dialog_ref = dialog_ref.clone();
        let on_saved = on_saved.clone();

        let parent_win_c = parent_win.clone();
        fd.save(Some(&parent_win), gio::Cancellable::NONE, move |res| {
            if let Ok(file) = res {
                if let Some(path) = file.path() {
                    if input_paths.iter().any(|p| p == &path) {
                        let alert = adw::AlertDialog::builder()
                            .heading("Refusing to Overwrite Source")
                            .body("Choose a new output filename instead of overwriting an input archive.")
                            .build();
                        alert.add_response("ok", "OK");
                        alert.present(Some(&parent_win_c));
                        return;
                    }
                    let mut v = merged_rc.borrow().clone();
                    if let Err(e) = save_vault_file(&path, &mut v, &save_creds, KdfParams::strong()) {
                        let alert = adw::AlertDialog::builder()
                            .heading("Save Failed")
                            .body(&e.to_string())
                            .build();
                        alert.add_response("ok", "OK");
                        alert.present(Some(&parent_win_c));
                        return;
                    }
                    on_saved(path, save_creds.clone());
                    dialog_ref.close();
                }
            }
        });
    });

    adw::NavigationPage::builder()
        .title("Merge Preview")
        .child(&tv)
        .build()
}
