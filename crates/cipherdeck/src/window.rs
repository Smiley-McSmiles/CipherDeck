use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use uuid::Uuid;
use vault_core::{
    estimate_entropy_bits, import_kdbx, load_vault_file, save_vault_file, strength_from_entropy,
    Card, CardKind, Credentials, KdfParams, SignatureVerification, StrengthLevel, Vault,
};

use crate::card_row::{CardCallbacks, CardRow};
use crate::donate::{present_about_dialog, present_donation_dialog};
use crate::merge_dialog::present_merge_dialog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterKind {
    All,
    Logins,
    Notes,
    Favorites,
    Weak,
    Trash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKind {
    Modified,
    Title,
    Strength,
}

struct AppState {
    vault: Option<Vault>,
    vault_path: Option<PathBuf>,
    last_vault_path: Option<PathBuf>,
    creds: Option<Credentials>,
    sig_status: Option<SignatureVerification>,
    filter: FilterKind,
    folder_filter: Option<String>,
    search: String,
    sort: SortKind,
    clipboard_gen: u64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            vault: None,
            vault_path: None,
            last_vault_path: load_last_vault_path(),
            creds: None,
            sig_status: None,
            filter: FilterKind::All,
            folder_filter: None,
            search: String::new(),
            sort: SortKind::Modified,
            clipboard_gen: 0,
        }
    }
}

fn last_vault_config_path() -> PathBuf {
    glib::user_config_dir()
        .join("cipherdeck")
        .join("last_vault.txt")
}

fn load_last_vault_path() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(last_vault_config_path()).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

fn save_last_vault_path(path: &std::path::Path) {
    let cfg = last_vault_config_path();
    if let Some(parent) = cfg.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(cfg, path.to_string_lossy().as_bytes());
}

fn activate_vault(
    state: &Rc<RefCell<AppState>>,
    path: PathBuf,
    mut vault: Vault,
    creds: Credentials,
    sig: SignatureVerification,
) {
    vault.normalize_legacy_email_fields();
    save_last_vault_path(&path);
    let mut st = state.borrow_mut();
    st.vault = Some(vault);
    st.vault_path = Some(path.clone());
    st.last_vault_path = Some(path);
    st.creds = Some(creds);
    st.sig_status = Some(sig);
}

fn fuzzy_match_str(haystack: &str, needle: &str) -> Option<i32> {
    if needle.is_empty() {
        return Some(0);
    }
    if let Some(pos) = haystack.find(needle) {
        let bonus = if pos == 0 { 100 } else { 50 };
        return Some(bonus + (needle.len() as i32 * 4) - (pos as i32).min(40));
    }
    let mut n_chars = needle.chars().peekable();
    let mut score = 0i32;
    let mut consecutive = 0i32;
    for (idx, h) in haystack.chars().enumerate() {
        if let Some(&nc) = n_chars.peek() {
            if h == nc {
                n_chars.next();
                consecutive += 1;
                score += 2 + consecutive * 3;
                if idx == 0 {
                    score += 5;
                }
            } else {
                consecutive = 0;
            }
        } else {
            break;
        }
    }
    if n_chars.peek().is_none() {
        Some(score)
    } else {
        None
    }
}

fn fuzzy_score_card(card: &Card, query: &str) -> Option<i32> {
    let tokens: Vec<String> = query
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return Some(0);
    }

    let title_l = card.title.value.to_lowercase();
    let user_l = card.username.value.to_lowercase();
    let email_l = card.email.value.to_lowercase();
    let url_l = card.url.value.to_lowercase();
    let folder_l = card.folder.value.to_lowercase();
    let tags_l = card.tags.value.join(" ").to_lowercase();
    let notes_l = card.notes_markdown.value.to_lowercase();
    let custom_l = card
        .custom_fields
        .iter()
        .map(|(k, v)| {
            if v.value.secret {
                k.clone()
            } else {
                format!("{k} {}", v.value.value)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let mut total = 0i32;
    for tok in &tokens {
        let mut best: Option<i32> = None;
        for (field, weight) in [
            (&title_l, 40),
            (&user_l, 25),
            (&email_l, 25),
            (&url_l, 20),
            (&folder_l, 15),
            (&tags_l, 15),
            (&custom_l, 10),
            (&notes_l, 5),
        ] {
            if let Some(s) = fuzzy_match_str(field, tok) {
                let weighted = s + weight;
                best = Some(best.map_or(weighted, |b| b.max(weighted)));
            }
        }
        total += best?;
    }
    Some(total)
}

pub fn build_main_window(app: &adw::Application) -> adw::ApplicationWindow {
    let win = adw::ApplicationWindow::builder()
        .application(app)
        .title("CipherDeck")
        .default_width(980)
        .default_height(740)
        .width_request(380)
        .height_request(460)
        .build();

    let state = Rc::new(RefCell::new(AppState::default()));
    let toasts = adw::ToastOverlay::new();
    win.set_content(Some(&toasts));

    let toolbar = adw::ToolbarView::new();
    toasts.set_child(Some(&toolbar));

    // Header bar
    let hb = adw::HeaderBar::new();
    toolbar.add_top_bar(&hb);

    let title_widget = adw::WindowTitle::new("CipherDeck", "No deck open");
    hb.set_title_widget(Some(&title_widget));

    let add_menu = gio::Menu::new();
    add_menu.append(Some("New Login…"), Some("win.new-login"));
    add_menu.append(Some("New Markdown Note…"), Some("win.new-note"));
    let sec = gio::Menu::new();
    sec.append(Some("Import KeePass (.kdbx)…"), Some("win.import-kdbx"));
    sec.append(Some("Merge Vaults…"), Some("win.merge-vaults"));
    add_menu.append_section(None, &sec);
    let sec2 = gio::Menu::new();
    sec2.append(Some("Open Vault…"), Some("win.open-vault"));
    sec2.append(Some("Create New Vault…"), Some("win.new-vault"));
    add_menu.append_section(None, &sec2);

    let add_btn = adw::SplitButton::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("New Login (Ctrl+N)")
        .menu_model(&add_menu)
        .action_name("win.new-login")
        .build();
    hb.pack_start(&add_btn);

    let filter_toggle = gtk::ToggleButton::builder()
        .icon_name("view-sort-descending-symbolic")
        .tooltip_text("Toggle Filters")
        .build();
    hb.pack_start(&filter_toggle);

    let lock_btn = gtk::Button::builder()
        .icon_name("system-lock-screen-symbolic")
        .tooltip_text("Lock Vault (Ctrl+L)")
        .action_name("win.lock-vault")
        .visible(false)
        .build();
    hb.pack_end(&lock_btn);

    let app_menu = gio::Menu::new();
    app_menu.append(Some("Donate"), Some("win.donate"));
    app_menu.append(Some("About CipherDeck"), Some("win.about"));
    let menu_btn = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .tooltip_text("Main Menu")
        .menu_model(&app_menu)
        .build();
    hb.pack_end(&menu_btn);

    let search_toggle = gtk::ToggleButton::builder()
        .icon_name("system-search-symbolic")
        .tooltip_text("Search (Ctrl+F)")
        .build();
    hb.pack_end(&search_toggle);

    // Search bar + Roll-down Filter bar
    let search_bar = gtk::SearchBar::new();
    let search_entry = gtk::SearchEntry::builder()
        .placeholder_text("Search titles, usernames, URLs, tags, or notes…")
        .hexpand(true)
        .build();
    search_bar.set_child(Some(&search_entry));
    search_bar.connect_entry(&search_entry);
    search_toggle
        .bind_property("active", &search_bar, "search-mode-enabled")
        .bidirectional()
        .sync_create()
        .build();
    toolbar.add_top_bar(&search_bar);

    let filter_rev = gtk::Revealer::new();
    filter_rev.set_transition_type(gtk::RevealerTransitionType::SlideDown);
    let filter_bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    filter_bar.add_css_class("filter-bar");

    let chips_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let chip_all = gtk::ToggleButton::with_label("All");
    chip_all.set_active(true);
    let chip_logins = gtk::ToggleButton::with_label("Logins");
    chip_logins.set_group(Some(&chip_all));
    let chip_notes = gtk::ToggleButton::with_label("Notes");
    chip_notes.set_group(Some(&chip_all));
    let chip_fav = gtk::ToggleButton::with_label("Favorites");
    chip_fav.set_group(Some(&chip_all));
    let chip_weak = gtk::ToggleButton::with_label("Weak");
    chip_weak.set_group(Some(&chip_all));
    let chip_trash = gtk::ToggleButton::with_label("Trash");
    chip_trash.set_group(Some(&chip_all));

    for c in [
        &chip_all,
        &chip_logins,
        &chip_notes,
        &chip_fav,
        &chip_weak,
        &chip_trash,
    ] {
        c.add_css_class("filter-chip");
        chips_box.append(c);
    }
    filter_bar.append(&chips_box);

    let f_spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    f_spacer.set_hexpand(true);
    filter_bar.append(&f_spacer);

    let folder_drop = gtk::DropDown::from_strings(&["All Folders"]);
    filter_bar.append(&folder_drop);

    let sort_drop = gtk::DropDown::from_strings(&["Sort: Modified", "Sort: Title", "Sort: Strength"]);
    filter_bar.append(&sort_drop);

    filter_rev.set_child(Some(&filter_bar));
    toolbar.add_top_bar(&filter_rev);

    filter_toggle.connect_toggled({
        let filter_rev = filter_rev.clone();
        move |b| filter_rev.set_reveal_child(b.is_active())
    });

    // Main Stack: Welcome vs Vault List
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    toolbar.set_content(Some(&stack));

    // Welcome / Lock-screen Page
    let welcome_box = gtk::Box::new(gtk::Orientation::Vertical, 16);
    welcome_box.set_valign(gtk::Align::Center);
    welcome_box.set_margin_start(24);
    welcome_box.set_margin_end(24);
    let status_page = adw::StatusPage::builder()
        .icon_name("io.github.woosah.CipherDeck")
        .title("CipherDeck")
        .description("Argon2id · AES-256-GCM + XChaCha20-Poly1305 Cascade · Ed25519 Signed\nField-level CRDT sync with zero-metadata padding")
        .build();

    // Inline password login card for the last-used vault
    let login_clamp = adw::Clamp::builder().maximum_size(400).build();
    let login_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
    login_box.add_css_class("card");
    login_box.set_margin_bottom(4);

    let login_inner = gtk::Box::new(gtk::Orientation::Vertical, 10);
    login_inner.set_margin_top(16);
    login_inner.set_margin_bottom(16);
    login_inner.set_margin_start(16);
    login_inner.set_margin_end(16);

    let login_vault_lbl = gtk::Label::new(None);
    login_vault_lbl.add_css_class("heading");
    login_vault_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    let login_path_lbl = gtk::Label::new(None);
    login_path_lbl.add_css_class("caption");
    login_path_lbl.add_css_class("dim-label");
    login_path_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    let login_pw_entry = gtk::PasswordEntry::builder()
        .placeholder_text("Master password")
        .show_peek_icon(true)
        .build();

    let login_err_lbl = gtk::Label::new(None);
    login_err_lbl.add_css_class("error");
    login_err_lbl.add_css_class("caption");
    login_err_lbl.set_wrap(true);
    login_err_lbl.set_visible(false);

    let login_btn = gtk::Button::with_label("Unlock Vault");
    login_btn.add_css_class("pill");
    login_btn.add_css_class("suggested-action");

    login_inner.append(&login_vault_lbl);
    login_inner.append(&login_path_lbl);
    login_inner.append(&login_pw_entry);
    login_inner.append(&login_err_lbl);
    login_inner.append(&login_btn);
    login_box.append(&login_inner);
    login_clamp.set_child(Some(&login_box));
    login_clamp.set_visible(false);

    let welcome_btns = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    welcome_btns.set_halign(gtk::Align::Center);
    let w_open = gtk::Button::with_label("Open .cdeck…");
    w_open.add_css_class("pill");
    w_open.add_css_class("suggested-action");
    w_open.set_action_name(Some("win.open-vault"));

    let w_new = gtk::Button::with_label("Create New Deck…");
    w_new.add_css_class("pill");
    w_new.set_action_name(Some("win.new-vault"));

    let w_import = gtk::Button::with_label("Import .kdbx…");
    w_import.add_css_class("pill");
    w_import.set_action_name(Some("win.import-kdbx"));

    let w_merge = gtk::Button::with_label("Merge Vaults…");
    w_merge.add_css_class("pill");
    w_merge.set_action_name(Some("win.merge-vaults"));

    welcome_btns.append(&w_open);
    welcome_btns.append(&w_new);
    welcome_btns.append(&w_import);
    welcome_btns.append(&w_merge);
    welcome_box.append(&status_page);
    welcome_box.append(&login_clamp);
    welcome_box.append(&welcome_btns);
    stack.add_named(&welcome_box, Some("welcome"));

    // Vault Card List
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_vexpand(true);
    let clamp = adw::Clamp::builder().maximum_size(860).build();
    let card_list = gtk::ListBox::new();
    card_list.set_selection_mode(gtk::SelectionMode::None);
    card_list.add_css_class("vault-list");
    clamp.set_child(Some(&card_list));
    scroll.set_child(Some(&clamp));
    stack.add_named(&scroll, Some("vault"));

    // Status bar
    let statusbar = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    statusbar.add_css_class("statusbar");
    let status_icon = gtk::Image::from_icon_name("emblem-ok-symbolic");
    let status_lbl = gtk::Label::new(Some("Argon2id + AES-256-GCM / XChaCha20-Poly1305 · Ed25519"));
    status_lbl.add_css_class("caption");
    status_lbl.add_css_class("dim-label");
    statusbar.append(&status_icon);
    statusbar.append(&status_lbl);

    let sb_spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    sb_spacer.set_hexpand(true);
    statusbar.append(&sb_spacer);

    let clip_lbl = gtk::Label::new(None);
    clip_lbl.add_css_class("caption");
    clip_lbl.add_css_class("numeric");
    statusbar.append(&clip_lbl);

    let merge_sb_btn = gtk::Button::with_label("Merge Archives…");
    merge_sb_btn.add_css_class("flat");
    merge_sb_btn.set_action_name(Some("win.merge-vaults"));
    statusbar.append(&merge_sb_btn);

    toolbar.add_bottom_bar(&statusbar);

    // Refresh UI closure
    let refresh_ui: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
    let auto_save_timer: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));
    let active_rows: Rc<RefCell<Vec<(Uuid, CardRow)>>> = Rc::new(RefCell::new(Vec::new()));
    let expanded_card_id: Rc<RefCell<Option<Uuid>>> = Rc::new(RefCell::new(None));
    let pending_expand_id: Rc<RefCell<Option<Uuid>>> = Rc::new(RefCell::new(None));

    let persist_vault: Rc<dyn Fn()> = {
        let state = state.clone();
        let toasts = toasts.clone();
        let auto_save_timer = auto_save_timer.clone();
        Rc::new(move || {
            if let Some(src) = auto_save_timer.borrow_mut().take() {
                src.remove();
            }
            let mut st = state.borrow_mut();
            let Some(path) = st.vault_path.clone() else {
                return;
            };
            let Some(creds) = st.creds.clone() else {
                return;
            };
            if let Some(vault) = st.vault.as_mut() {
                if let Err(e) = save_vault_file(&path, vault, &creds, KdfParams::strong()) {
                    toasts.add_toast(adw::Toast::new(&format!("Save failed: {e}")));
                }
            }
        })
    };

    let schedule_auto_persist: Rc<dyn Fn()> = {
        let auto_save_timer = auto_save_timer.clone();
        let persist_vault = persist_vault.clone();
        Rc::new(move || {
            if let Some(src) = auto_save_timer.borrow_mut().take() {
                src.remove();
            }
            let timer_ref = auto_save_timer.clone();
            let persist_c = persist_vault.clone();
            let src = glib::timeout_add_local_once(
                std::time::Duration::from_millis(1500),
                move || {
                    *timer_ref.borrow_mut() = None;
                    persist_c();
                },
            );
            *auto_save_timer.borrow_mut() = Some(src);
        })
    };

    {
        let state = state.clone();
        let stack = stack.clone();
        let card_list = card_list.clone();
        let title_widget = title_widget.clone();
        let lock_btn = lock_btn.clone();
        let status_lbl = status_lbl.clone();
        let toasts = toasts.clone();
        let clip_lbl = clip_lbl.clone();
        let win_ref = win.clone();
        let refresh_ref = refresh_ui.clone();
        let persist_vault = persist_vault.clone();
        let schedule_auto_persist = schedule_auto_persist.clone();
        let active_rows = active_rows.clone();
        let expanded_card_id = expanded_card_id.clone();
        let pending_expand_id = pending_expand_id.clone();
        let folder_drop = folder_drop.clone();
        let search_entry_outer = search_entry.clone();
        let search_toggle_outer = search_toggle.clone();
        let filter_toggle_outer = filter_toggle.clone();
        let login_clamp = login_clamp.clone();
        let login_vault_lbl = login_vault_lbl.clone();
        let login_path_lbl = login_path_lbl.clone();
        let login_pw_entry = login_pw_entry.clone();
        let login_err_lbl = login_err_lbl.clone();
        let w_open = w_open.clone();

        let fn_rc: Rc<dyn Fn()> = Rc::new(move || {
            active_rows.borrow_mut().clear();
            *expanded_card_id.borrow_mut() = None;
            while let Some(child) = card_list.first_child() {
                card_list.remove(&child);
            }
            let st = state.borrow();
            let Some(vault) = st.vault.as_ref() else {
                stack.set_visible_child_name("welcome");
                title_widget.set_title("CipherDeck");
                lock_btn.set_visible(false);
                search_toggle_outer.set_active(false);
                filter_toggle_outer.set_active(false);
                if let Some(last_path) = st.last_vault_path.as_ref() {
                    let fname = last_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("vault");
                    title_widget.set_subtitle(&format!("Locked · {fname}"));
                    login_vault_lbl.set_text(&format!("Unlock {fname}"));
                    login_path_lbl.set_text(&last_path.to_string_lossy());
                    login_pw_entry.set_text("");
                    login_err_lbl.set_visible(false);
                    login_clamp.set_visible(true);
                    w_open.remove_css_class("suggested-action");
                    login_pw_entry.grab_focus();
                } else {
                    title_widget.set_subtitle("No deck open");
                    login_clamp.set_visible(false);
                    w_open.add_css_class("suggested-action");
                }
                return;
            };

            stack.set_visible_child_name("vault");
            lock_btn.set_visible(true);

            let active_total = vault.active_cards().count();
            let login_count = vault
                .active_cards()
                .filter(|c| c.kind.value == CardKind::Login)
                .count();
            let note_count = vault
                .active_cards()
                .filter(|c| c.kind.value == CardKind::Note)
                .count();
            title_widget.set_title(&vault.vault_name.value);
            title_widget.set_subtitle(&format!(
                "{active_total} cards · {login_count} logins · {note_count} notes"
            ));

            let sig_str = match st.sig_status {
                Some(SignatureVerification::VerifiedTrusted) => "Ed25519 Verified",
                Some(SignatureVerification::VerifiedUnknownDevice) => "Ed25519 Signed (New Device)",
                Some(SignatureVerification::InvalidSignature) => "INVALID SIGNATURE",
                _ => "Unsigned",
            };
            status_lbl.set_text(&format!(
                "Argon2id + AES-256-GCM / XChaCha20-Poly1305 · {sig_str}"
            ));

            // Update folder dropdown list
            let mut folders = BTreeSet::new();
            for c in vault.active_cards() {
                if !c.folder.value.trim().is_empty() {
                    folders.insert(c.folder.value.clone());
                }
            }
            let mut folder_items = vec!["All Folders".to_string()];
            folder_items.extend(folders);
            let refs: Vec<&str> = folder_items.iter().map(|s| s.as_str()).collect();
            folder_drop.set_model(Some(&gtk::StringList::new(&refs)));

            let query = st.search.trim().to_string();
            let filter = st.filter;
            let folder_f = st.folder_filter.clone();
            let sort = st.sort;

            let mut scored: Vec<(i32, Card)> = vault
                .cards
                .values()
                .filter_map(|c| {
                    let deleted = c.is_deleted();
                    if filter == FilterKind::Trash {
                        if !deleted {
                            return None;
                        }
                    } else if deleted {
                        return None;
                    }
                    match filter {
                        FilterKind::Logins => {
                            if c.kind.value != CardKind::Login {
                                return None;
                            }
                        }
                        FilterKind::Notes => {
                            if c.kind.value != CardKind::Note {
                                return None;
                            }
                        }
                        FilterKind::Favorites => {
                            if !c.favorite.value {
                                return None;
                            }
                        }
                        FilterKind::Weak => {
                            if c.kind.value != CardKind::Login || c.password.value.is_empty() {
                                return None;
                            }
                            let bits = estimate_entropy_bits(&c.password.value);
                            if !matches!(strength_from_entropy(bits), StrengthLevel::Weak | StrengthLevel::Fair) {
                                return None;
                            }
                        }
                        _ => {}
                    }
                    if let Some(ref ff) = folder_f {
                        if &c.folder.value != ff {
                            return None;
                        }
                    }
                    let score = if query.is_empty() {
                        0
                    } else {
                        fuzzy_score_card(c, &query)?
                    };
                    Some((score, c.clone()))
                })
                .collect();

            if !query.is_empty() {
                scored.sort_by(|(sa, a), (sb, b)| {
                    sb.cmp(sa).then_with(|| b.max_hlc().cmp(&a.max_hlc()))
                });
            } else {
                match sort {
                    SortKind::Modified => {
                        scored.sort_by(|(_, a), (_, b)| b.max_hlc().cmp(&a.max_hlc()));
                    }
                    SortKind::Title => {
                        scored.sort_by(|(_, a), (_, b)| {
                            a.title
                                .value
                                .to_lowercase()
                                .cmp(&b.title.value.to_lowercase())
                        });
                    }
                    SortKind::Strength => {
                        scored.sort_by(|(_, a), (_, b)| {
                            let ea = estimate_entropy_bits(&a.password.value);
                            let eb = estimate_entropy_bits(&b.password.value);
                            ea.partial_cmp(&eb).unwrap_or(std::cmp::Ordering::Equal)
                        });
                    }
                }
            }
            let visible: Vec<Card> = scored.into_iter().map(|(_, c)| c).collect();

            drop(st);

            let cb = CardCallbacks {
                on_copy_secret: {
                    let win_ref = win_ref.clone();
                    let toasts = toasts.clone();
                    let state = state.clone();
                    let clip_lbl = clip_lbl.clone();
                    Rc::new(move |label, secret| {
                        win_ref.clipboard().set_text(&secret);
                        toasts.add_toast(adw::Toast::new(&format!(
                            "{label} copied (clears in 20s)"
                        )));
                        let gen = {
                            let mut st = state.borrow_mut();
                            st.clipboard_gen += 1;
                            st.clipboard_gen
                        };
                        clip_lbl.set_text("Clipboard clears in 20s");
                        let win_c = win_ref.clone();
                        let state_c = state.clone();
                        let clip_c = clip_lbl.clone();
                        glib::timeout_add_seconds_local_once(20, move || {
                            if state_c.borrow().clipboard_gen == gen {
                                win_c.clipboard().set_text("");
                                clip_c.set_text("");
                            }
                        });
                    })
                },
                on_copy_text: {
                    let win_ref = win_ref.clone();
                    let toasts = toasts.clone();
                    Rc::new(move |label, text| {
                        win_ref.clipboard().set_text(&text);
                        toasts.add_toast(adw::Toast::new(&format!("{label} copied")));
                    })
                },
                on_save_card: {
                    let state = state.clone();
                    let persist_vault = persist_vault.clone();
                    let refresh_ref = refresh_ref.clone();
                    let toasts = toasts.clone();
                    Rc::new(move |updated| {
                        {
                            let mut st = state.borrow_mut();
                            if let Some(v) = st.vault.as_mut() {
                                v.cards.insert(updated.id, updated);
                            }
                        }
                        persist_vault();
                        toasts.add_toast(adw::Toast::new("Card saved & encrypted"));
                        if let Some(f) = refresh_ref.borrow().as_ref() {
                            f();
                        }
                    })
                },
                on_auto_save: {
                    let state = state.clone();
                    let schedule_auto_persist = schedule_auto_persist.clone();
                    Rc::new(move |updated| {
                        {
                            let mut st = state.borrow_mut();
                            if let Some(v) = st.vault.as_mut() {
                                v.cards.insert(updated.id, updated);
                            }
                        }
                        schedule_auto_persist();
                    })
                },
                on_delete_empty: {
                    let state = state.clone();
                    let expanded_card_id = expanded_card_id.clone();
                    let schedule_auto_persist = schedule_auto_persist.clone();
                    let refresh_ref = refresh_ref.clone();
                    Rc::new(move |id| {
                        let removed = {
                            let mut st = state.borrow_mut();
                            st.vault
                                .as_mut()
                                .and_then(|v| v.cards.remove(&id))
                                .is_some()
                        };
                        if *expanded_card_id.borrow() == Some(id) {
                            *expanded_card_id.borrow_mut() = None;
                        }
                        if removed {
                            schedule_auto_persist();
                            if let Some(f) = refresh_ref.borrow().as_ref() {
                                f();
                            }
                        }
                    })
                },
                on_expand_changed: {
                    let expanded_card_id = expanded_card_id.clone();
                    let active_rows = active_rows.clone();
                    Rc::new(move |id, is_expanded| {
                        if is_expanded {
                            let prev = *expanded_card_id.borrow();
                            *expanded_card_id.borrow_mut() = Some(id);
                            if let Some(prev_id) = prev {
                                if prev_id != id {
                                    let prev_card_row = active_rows
                                        .borrow()
                                        .iter()
                                        .find(|(rid, _)| *rid == prev_id)
                                        .map(|(_, r)| r.clone());
                                    if let Some(r) = prev_card_row {
                                        r.set_expanded(false);
                                    }
                                }
                            }
                        } else if *expanded_card_id.borrow() == Some(id) {
                            *expanded_card_id.borrow_mut() = None;
                        }
                    })
                },
                on_toggle_trash: {
                    let state = state.clone();
                    let persist_vault = persist_vault.clone();
                    let refresh_ref = refresh_ref.clone();
                    let toasts = toasts.clone();
                    Rc::new(move |id: Uuid, to_trash: bool| {
                        {
                            let mut st = state.borrow_mut();
                            if let Some(v) = st.vault.as_mut() {
                                let dev_id = v.device_id;
                                let dev_name = v.device_name.clone();
                                if let Some(card) = v.cards.get_mut(&id) {
                                    if to_trash {
                                        card.mark_deleted(dev_id);
                                    } else {
                                        card.restore(dev_id, &dev_name);
                                    }
                                }
                            }
                        }
                        persist_vault();
                        toasts.add_toast(adw::Toast::new(if to_trash {
                            "Moved to Trash"
                        } else {
                            "Restored from Trash"
                        }));
                        if let Some(f) = refresh_ref.borrow().as_ref() {
                            f();
                        }
                    })
                },
                on_jump_card: {
                    let state = state.clone();
                    let search_entry = search_entry_outer.clone();
                    let search_toggle = search_toggle_outer.clone();
                    let refresh_ref = refresh_ref.clone();
                    Rc::new(move |target| {
                        state.borrow_mut().search = target.clone();
                        search_toggle.set_active(true);
                        search_entry.set_text(&target);
                        if let Some(f) = refresh_ref.borrow().as_ref() {
                            f();
                        }
                    })
                },
            };

            let expand_target = pending_expand_id.borrow_mut().take();
            for card in visible {
                let cid = card.id;
                let row = CardRow::new(card, cb.clone());
                card_list.append(&row.row);
                let should_expand = expand_target == Some(cid);
                if should_expand {
                    row.set_expanded(true);
                    let t_card_row_title = row.row.clone();
                    let active_rows_c = active_rows.clone();
                    glib::idle_add_local_once(move || {
                        let _ = t_card_row_title;
                        if let Some((_, r)) = active_rows_c.borrow().iter().find(|(id, _)| *id == cid) {
                            r.focus_title();
                        }
                    });
                }
                active_rows.borrow_mut().push((cid, row));
            }
        });
        *refresh_ui.borrow_mut() = Some(fn_rc.clone());
        fn_rc();
    }

    // Inline login handler for the last-used vault
    let try_unlock_last: Rc<dyn Fn()> = {
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        let login_pw_entry = login_pw_entry.clone();
        let login_err_lbl = login_err_lbl.clone();
        Rc::new(move || {
            let Some(path) = state.borrow().last_vault_path.clone() else {
                return;
            };
            let pw = login_pw_entry.text().to_string();
            let creds = Credentials::from_password(pw);
            match load_vault_file(&path, &creds) {
                Ok(dec) => {
                    login_pw_entry.set_text("");
                    login_err_lbl.set_visible(false);
                    activate_vault(&state, path, dec.vault, creds, dec.signature);
                    if let Some(f) = refresh_ui.borrow().as_ref() {
                        f();
                    }
                    toasts.add_toast(adw::Toast::new("Vault unlocked"));
                }
                Err(e) => {
                    login_err_lbl.set_text(&e.to_string());
                    login_err_lbl.set_visible(true);
                    login_pw_entry.grab_focus();
                    login_pw_entry.select_region(0, -1);
                }
            }
        })
    };
    login_btn.connect_clicked({
        let try_unlock_last = try_unlock_last.clone();
        move |_| try_unlock_last()
    });
    login_pw_entry.connect_activate({
        let try_unlock_last = try_unlock_last.clone();
        move |_| try_unlock_last()
    });
    login_pw_entry.connect_changed({
        let login_err_lbl = login_err_lbl.clone();
        move |_| {
            if login_err_lbl.is_visible() {
                login_err_lbl.set_visible(false);
            }
        }
    });

    // Filter chip wiring
    let wire_filter = |btn: &gtk::ToggleButton, kind: FilterKind| {
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        btn.connect_toggled(move |b| {
            if b.is_active() {
                state.borrow_mut().filter = kind;
                if let Some(f) = refresh_ui.borrow().as_ref() {
                    f();
                }
            }
        });
    };
    wire_filter(&chip_all, FilterKind::All);
    wire_filter(&chip_logins, FilterKind::Logins);
    wire_filter(&chip_notes, FilterKind::Notes);
    wire_filter(&chip_fav, FilterKind::Favorites);
    wire_filter(&chip_weak, FilterKind::Weak);
    wire_filter(&chip_trash, FilterKind::Trash);

    sort_drop.connect_selected_notify({
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        move |d| {
            state.borrow_mut().sort = match d.selected() {
                1 => SortKind::Title,
                2 => SortKind::Strength,
                _ => SortKind::Modified,
            };
            if let Some(f) = refresh_ui.borrow().as_ref() {
                f();
            }
        }
    });

    search_entry.connect_search_changed({
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        move |e| {
            state.borrow_mut().search = e.text().to_string();
            if let Some(f) = refresh_ui.borrow().as_ref() {
                f();
            }
        }
    });

    // Helper: unlock an existing .wsafe file
    let open_wsafe_prompt: Rc<dyn Fn(PathBuf)> = {
        let win = win.clone();
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        Rc::new(move |path: PathBuf| {
            let dialog = adw::AlertDialog::builder()
                .heading("Unlock Vault")
                .body(&format!(
                    "Enter master password for {}",
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("vault")
                ))
                .build();
            let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
            let pw_entry = gtk::PasswordEntry::builder()
                .placeholder_text("Master password")
                .show_peek_icon(true)
                .build();
            bx.append(&pw_entry);
            dialog.set_extra_child(Some(&bx));
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("unlock", "Unlock");
            dialog.set_response_appearance("unlock", adw::ResponseAppearance::Suggested);
            dialog.set_default_response(Some("unlock"));

            let win_c = win.clone();
            let state = state.clone();
            let refresh_ui = refresh_ui.clone();
            let toasts = toasts.clone();
            dialog.choose(&win, gio::Cancellable::NONE, move |resp| {
                if resp == "unlock" {
                    let creds = Credentials::from_password(pw_entry.text().to_string());
                    match load_vault_file(&path, &creds) {
                        Ok(dec) => {
                            activate_vault(&state, path, dec.vault, creds, dec.signature);
                            if let Some(f) = refresh_ui.borrow().as_ref() {
                                f();
                            }
                            toasts.add_toast(adw::Toast::new("Vault unlocked"));
                        }
                        Err(e) => {
                            let err = adw::AlertDialog::builder()
                                .heading("Unlock Failed")
                                .body(&e.to_string())
                                .build();
                            err.add_response("ok", "OK");
                            err.present(Some(&win_c));
                        }
                    }
                }
            });
        })
    };

    // Window actions
    let act_open = gio::SimpleAction::new("open-vault", None);
    act_open.connect_activate({
        let win = win.clone();
        let open_wsafe_prompt = open_wsafe_prompt.clone();
        move |_, _| {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("CipherDeck (*.cdeck, *.wsafe)"));
            filter.add_pattern("*.cdeck");
            filter.add_pattern("*.wsafe");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&filter);
            let fd = gtk::FileDialog::builder()
                .title("Open .cdeck Vault")
                .filters(&filters)
                .build();
            let open_wsafe_prompt = open_wsafe_prompt.clone();
            fd.open(Some(&win), gio::Cancellable::NONE, move |res| {
                if let Ok(file) = res {
                    if let Some(p) = file.path() {
                        open_wsafe_prompt(p);
                    }
                }
            });
        }
    });
    win.add_action(&act_open);

    let act_new_vault = gio::SimpleAction::new("new-vault", None);
    act_new_vault.connect_activate({
        let win = win.clone();
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        move |_, _| {
            let dialog = adw::AlertDialog::builder()
                .heading("Create New Vault")
                .body("Protected with Argon2id + AES-256-GCM / XChaCha20-Poly1305 & Ed25519")
                .build();
            let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
            let name_e = gtk::Entry::builder().placeholder_text("Deck name (e.g. Personal Deck)").text("Personal Deck").build();
            let pw_e = gtk::PasswordEntry::builder().placeholder_text("Master password").show_peek_icon(true).build();
            bx.append(&name_e);
            bx.append(&pw_e);
            dialog.set_extra_child(Some(&bx));
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("create", "Choose File & Create");
            dialog.set_response_appearance("create", adw::ResponseAppearance::Suggested);

            let win_c = win.clone();
            let state = state.clone();
            let refresh_ui = refresh_ui.clone();
            let toasts = toasts.clone();
            dialog.choose(&win, gio::Cancellable::NONE, move |resp| {
                if resp == "create" {
                    let pw = pw_e.text().to_string();
                    if pw.is_empty() {
                        toasts.add_toast(adw::Toast::new("Master password cannot be empty"));
                        return;
                    }
                    let vname = name_e.text().to_string();
                    let fd = gtk::FileDialog::builder()
                        .title("Save New CipherDeck")
                        .initial_name("personal.cdeck")
                        .build();
                    let win_c2 = win_c.clone();
                    let state = state.clone();
                    let refresh_ui = refresh_ui.clone();
                    let toasts = toasts.clone();
                    fd.save(Some(&win_c), gio::Cancellable::NONE, move |res| {
                        if let Ok(file) = res {
                            if let Some(path) = file.path() {
                                let creds = Credentials::from_password(pw);
                                let mut vault = Vault::new(vname, "Desktop");
                                match save_vault_file(&path, &mut vault, &creds, KdfParams::strong()) {
                                    Ok(()) => {
                                        activate_vault(
                                            &state,
                                            path,
                                            vault,
                                            creds,
                                            SignatureVerification::VerifiedTrusted,
                                        );
                                        if let Some(f) = refresh_ui.borrow().as_ref() {
                                            f();
                                        }
                                        toasts.add_toast(adw::Toast::new("New vault created (0600)"));
                                    }
                                    Err(e) => {
                                        let err = adw::AlertDialog::builder().heading("Error").body(&e.to_string()).build();
                                        err.add_response("ok", "OK");
                                        err.present(Some(&win_c2));
                                    }
                                }
                            }
                        }
                    });
                }
            });
        }
    });
    win.add_action(&act_new_vault);

    // One-Click KDBX Import action
    let act_import_kdbx = gio::SimpleAction::new("import-kdbx", None);
    act_import_kdbx.connect_activate({
        let win = win.clone();
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        move |_, _| {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("KeePass Database (*.kdbx)"));
            filter.add_pattern("*.kdbx");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&filter);
            let fd = gtk::FileDialog::builder()
                .title("Select KeePass .kdbx to Import")
                .filters(&filters)
                .build();
            let win_c = win.clone();
            let state = state.clone();
            let refresh_ui = refresh_ui.clone();
            let toasts = toasts.clone();
            fd.open(Some(&win), gio::Cancellable::NONE, move |res| {
                if let Ok(file) = res {
                    if let Some(kdbx_path) = file.path() {
                        let dialog = adw::AlertDialog::builder()
                            .heading("Import KeePass Database")
                            .body(&format!(
                                "Unlock {} and save as a new .cdeck vault",
                                kdbx_path.file_name().and_then(|s| s.to_str()).unwrap_or("database")
                            ))
                            .build();
                        let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
                        let kdbx_pw = gtk::PasswordEntry::builder().placeholder_text("KDBX password").show_peek_icon(true).build();
                        let new_pw = gtk::PasswordEntry::builder().placeholder_text("New .cdeck master password (leave blank to reuse)").show_peek_icon(true).build();
                        bx.append(&kdbx_pw);
                        bx.append(&new_pw);
                        dialog.set_extra_child(Some(&bx));
                        dialog.add_response("cancel", "Cancel");
                        dialog.add_response("import", "Import & Save…");
                        dialog.set_response_appearance("import", adw::ResponseAppearance::Suggested);

                        let win_c2 = win_c.clone();
                        let state = state.clone();
                        let refresh_ui = refresh_ui.clone();
                        let toasts = toasts.clone();
                        dialog.choose(&win_c, gio::Cancellable::NONE, move |resp| {
                            if resp == "import" {
                                let kpw = kdbx_pw.text().to_string();
                                let out_pw = {
                                    let p = new_pw.text().to_string();
                                    if p.is_empty() { kpw.clone() } else { p }
                                };
                                match import_kdbx(&kdbx_path, Some(&kpw), None, "Desktop") {
                                    Ok(mut vault) => {
                                        let default_name = format!(
                                            "{}.cdeck",
                                            kdbx_path.file_stem().and_then(|s| s.to_str()).unwrap_or("imported")
                                        );
                                        let fd_save = gtk::FileDialog::builder()
                                            .title("Save Imported .cdeck")
                                            .initial_name(&default_name)
                                            .build();
                                        let win_c3 = win_c2.clone();
                                        let state = state.clone();
                                        let refresh_ui = refresh_ui.clone();
                                        let toasts = toasts.clone();
                                        fd_save.save(Some(&win_c2), gio::Cancellable::NONE, move |sres| {
                                            if let Ok(sfile) = sres {
                                                if let Some(out_path) = sfile.path() {
                                                    let creds = Credentials::from_password(out_pw);
                                                    if let Err(e) = save_vault_file(&out_path, &mut vault, &creds, KdfParams::strong()) {
                                                        let err = adw::AlertDialog::builder().heading("Save Failed").body(&e.to_string()).build();
                                                        err.add_response("ok", "OK");
                                                        err.present(Some(&win_c3));
                                                        return;
                                                    }
                                                    let count = vault.active_cards().count();
                                                    activate_vault(
                                                        &state,
                                                        out_path,
                                                        vault,
                                                        creds,
                                                        SignatureVerification::VerifiedTrusted,
                                                    );
                                                    if let Some(f) = refresh_ui.borrow().as_ref() {
                                                        f();
                                                    }
                                                    toasts.add_toast(adw::Toast::new(&format!("Imported {count} cards into .cdeck")));
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        let err = adw::AlertDialog::builder().heading("Import Failed").body(&e.to_string()).build();
                                        err.add_response("ok", "OK");
                                        err.present(Some(&win_c2));
                                    }
                                }
                            }
                        });
                    }
                }
            });
        }
    });
    win.add_action(&act_import_kdbx);

    // New Login / New Note actions (inline card creation directly in the window)
    let spawn_new_card = {
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        let expanded_card_id = expanded_card_id.clone();
        let pending_expand_id = pending_expand_id.clone();
        let search_entry = search_entry.clone();
        Rc::new(move |kind: CardKind| {
            let new_id = {
                let mut st = state.borrow_mut();
                let Some(v) = st.vault.as_mut() else {
                    toasts.add_toast(adw::Toast::new("Open or create a vault first"));
                    return;
                };
                if let Some(prev_id) = expanded_card_id.borrow_mut().take() {
                    if v.cards.get(&prev_id).is_some_and(|c| c.is_completely_empty()) {
                        v.cards.remove(&prev_id);
                    }
                }
                let dev_id = v.device_id;
                let dev_name = v.device_name.clone();
                let card = Card::new(kind, dev_id, &dev_name, "");
                let id = v.add_card(card);
                st.filter = FilterKind::All;
                st.folder_filter = None;
                st.search.clear();
                id
            };
            if !search_entry.text().is_empty() {
                search_entry.set_text("");
            }
            *pending_expand_id.borrow_mut() = Some(new_id);
            if let Some(f) = refresh_ui.borrow().as_ref() {
                f();
            }
        })
    };

    // Clicking off an expanded completely-empty card deletes it
    {
        let win_c = win.clone();
        let active_rows = active_rows.clone();
        let expanded_card_id = expanded_card_id.clone();
        let click_ctrl = gtk::GestureClick::new();
        click_ctrl.set_propagation_phase(gtk::PropagationPhase::Capture);
        click_ctrl.connect_pressed(move |_, _, x, y| {
            let Some(exp_id) = *expanded_card_id.borrow() else {
                return;
            };
            let target_row = active_rows
                .borrow()
                .iter()
                .find(|(rid, _)| *rid == exp_id)
                .map(|(_, r)| r.clone());
            if let Some(r) = target_row {
                if r.card.borrow().is_completely_empty() {
                    if let Some(bounds) = r.row.compute_bounds(&win_c) {
                        let pt = gtk::graphene::Point::new(x as f32, y as f32);
                        if !bounds.contains_point(&pt) {
                            r.set_expanded(false);
                        }
                    }
                }
            }
        });
        win.add_controller(click_ctrl);
    }

    let act_new_login = gio::SimpleAction::new("new-login", None);
    act_new_login.connect_activate({
        let spawn_new_card = spawn_new_card.clone();
        move |_, _| spawn_new_card(CardKind::Login)
    });
    win.add_action(&act_new_login);

    let act_new_note = gio::SimpleAction::new("new-note", None);
    act_new_note.connect_activate({
        let spawn_new_card = spawn_new_card.clone();
        move |_, _| spawn_new_card(CardKind::Note)
    });
    win.add_action(&act_new_note);

    let act_lock = gio::SimpleAction::new("lock-vault", None);
    act_lock.connect_activate({
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let persist_vault = persist_vault.clone();
        let auto_save_timer = auto_save_timer.clone();
        let toasts = toasts.clone();
        let win_c = win.clone();
        let clip_lbl = clip_lbl.clone();
        move |_, _| {
            if auto_save_timer.borrow().is_some() {
                persist_vault();
            }
            {
                let mut st = state.borrow_mut();
                if let Some(p) = st.vault_path.take() {
                    st.last_vault_path = Some(p);
                }
                st.vault = None;
                st.creds = None;
                st.sig_status = None;
                st.clipboard_gen += 1;
            }
            win_c.clipboard().set_text("");
            clip_lbl.set_text("");
            if let Some(f) = refresh_ui.borrow().as_ref() {
                f();
            }
            toasts.add_toast(adw::Toast::new("Vault locked & keys zeroized"));
        }
    });
    win.add_action(&act_lock);

    let act_merge = gio::SimpleAction::new("merge-vaults", None);
    act_merge.connect_activate({
        let win = win.clone();
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        move |_, _| {
            let initial = state
                .borrow()
                .vault_path
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            let state = state.clone();
            let refresh_ui = refresh_ui.clone();
            let toasts = toasts.clone();
            present_merge_dialog(&win, initial, move |saved_path, creds| {
                if let Ok(dec) = load_vault_file(&saved_path, &creds) {
                    activate_vault(&state, saved_path, dec.vault, creds, dec.signature);
                    if let Some(f) = refresh_ui.borrow().as_ref() {
                        f();
                    }
                    toasts.add_toast(adw::Toast::new("Merged vault saved & opened (0600)"));
                }
            });
        }
    });
    win.add_action(&act_merge);

    // Drag & Drop .cdeck / .wsafe / .kdbx files onto window
    let drop_target = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
    drop_target.connect_drop({
        let open_wsafe_prompt = open_wsafe_prompt.clone();
        let win = win.clone();
        let state = state.clone();
        let refresh_ui = refresh_ui.clone();
        let toasts = toasts.clone();
        move |_, val, _, _| {
            if let Ok(fl) = val.get::<gdk::FileList>() {
                let paths: Vec<PathBuf> = fl.files().iter().filter_map(|f| f.path()).collect();
                if paths.len() == 1
                    && matches!(
                        paths[0].extension().and_then(|s| s.to_str()),
                        Some("cdeck" | "wsafe")
                    )
                {
                    open_wsafe_prompt(paths[0].clone());
                    return true;
                } else if !paths.is_empty() {
                    let state = state.clone();
                    let refresh_ui = refresh_ui.clone();
                    let toasts = toasts.clone();
                    present_merge_dialog(&win, paths, move |saved_path, creds| {
                        if let Ok(dec) = load_vault_file(&saved_path, &creds) {
                            activate_vault(&state, saved_path, dec.vault, creds, dec.signature);
                            if let Some(f) = refresh_ui.borrow().as_ref() {
                                f();
                            }
                            toasts.add_toast(adw::Toast::new("Merged vault saved & opened"));
                        }
                    });
                    return true;
                }
            }
            false
        }
    });
    win.add_controller(drop_target);

    // Save, Quit, and Search actions
    let act_save = gio::SimpleAction::new("save-vault", None);
    act_save.connect_activate({
        let state = state.clone();
        let persist_vault = persist_vault.clone();
        let toasts = toasts.clone();
        move |_, _| {
            if state.borrow().vault.is_some() {
                persist_vault();
                toasts.add_toast(adw::Toast::new("Deck saved & encrypted"));
            }
        }
    });
    win.add_action(&act_save);

    let act_quit = gio::SimpleAction::new("quit", None);
    act_quit.connect_activate({
        let win_c = win.clone();
        let persist_vault = persist_vault.clone();
        move |_, _| {
            persist_vault();
            win_c.close();
        }
    });
    win.add_action(&act_quit);

    let act_donate = gio::SimpleAction::new("donate", None);
    act_donate.connect_activate({
        let win_c = win.clone();
        let toasts_c = toasts.clone();
        move |_, _| {
            present_donation_dialog(&win_c, &win_c, &toasts_c);
        }
    });
    win.add_action(&act_donate);

    let act_about = gio::SimpleAction::new("about", None);
    act_about.connect_activate({
        let win_c = win.clone();
        let toasts_c = toasts.clone();
        move |_, _| {
            present_about_dialog(&win_c, &toasts_c);
        }
    });
    win.add_action(&act_about);

    let act_focus_search = gio::SimpleAction::new("focus-search", None);
    act_focus_search.connect_activate({
        let search_toggle = search_toggle.clone();
        let search_entry = search_entry.clone();
        move |_, _| {
            search_toggle.set_active(true);
            search_entry.grab_focus();
            search_entry.select_region(0, -1);
        }
    });
    win.add_action(&act_focus_search);

    win.connect_close_request({
        let persist_vault = persist_vault.clone();
        move |_| {
            persist_vault();
            glib::Propagation::Proceed
        }
    });

    // Type-to-search: start typing anywhere (outside text inputs) to fuzzy search the deck
    let key_ctrl = gtk::EventControllerKey::new();
    key_ctrl.set_propagation_phase(gtk::PropagationPhase::Bubble);
    key_ctrl.connect_key_pressed({
        let win_c = win.clone();
        let state = state.clone();
        let search_toggle = search_toggle.clone();
        let search_entry = search_entry.clone();
        move |_, keyval, _, modifiers| {
            if state.borrow().vault.is_none() {
                return glib::Propagation::Proceed;
            }
            if keyval == gdk::Key::Escape && search_toggle.is_active() {
                search_entry.set_text("");
                search_toggle.set_active(false);
                return glib::Propagation::Stop;
            }
            let blocked_mods = gdk::ModifierType::CONTROL_MASK
                | gdk::ModifierType::ALT_MASK
                | gdk::ModifierType::SUPER_MASK
                | gdk::ModifierType::META_MASK;
            if modifiers.intersects(blocked_mods) {
                return glib::Propagation::Proceed;
            }
            if let Some(focus) = gtk::prelude::GtkWindowExt::focus(&win_c) {
                if focus.is::<gtk::Editable>()
                    || focus.is::<gtk::TextView>()
                    || focus.is::<gtk::Text>()
                {
                    return glib::Propagation::Proceed;
                }
            }
            if let Some(ch) = keyval.to_unicode() {
                if !ch.is_control() {
                    search_toggle.set_active(true);
                    let mut cur = search_entry.text().to_string();
                    cur.push(ch);
                    search_entry.set_text(&cur);
                    search_entry.grab_focus();
                    search_entry.set_position(-1);
                    return glib::Propagation::Stop;
                }
            }
            glib::Propagation::Proceed
        }
    });
    win.add_controller(key_ctrl);

    // Keyboard shortcuts
    app.set_accels_for_action("win.new-login", &["<Ctrl>n"]);
    app.set_accels_for_action("win.new-note", &["<Ctrl><Shift>n"]);
    app.set_accels_for_action("win.save-vault", &["<Ctrl>s"]);
    app.set_accels_for_action("win.open-vault", &["<Ctrl>o"]);
    app.set_accels_for_action("win.lock-vault", &["<Ctrl>l"]);
    app.set_accels_for_action("win.merge-vaults", &["<Ctrl>m"]);
    app.set_accels_for_action("win.focus-search", &["<Ctrl>f"]);
    app.set_accels_for_action("win.quit", &["<Ctrl>q"]);

    win
}
