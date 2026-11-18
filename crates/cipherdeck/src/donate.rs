use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

pub const DONATION_OPTIONS: &[(&str, &str)] = &[
    ("BTC", "bc1qy2gtdhnfxp9dcs6v9jda748npmsjx3jgwp99mx"),
    (
        "XMR",
        "82xtMVSmesuLjPtgHfBCEhM5Fpqh1SLLNf9pzHRRNPqQZsvrnmoM1ZGC7AiLyPfsufdyrMWHrWYV2hsC8jc5rEBVLMHWTLy",
    ),
    ("CashApp", "$SmileyMcSmiles"),
];

fn copy_donation_text(app_win: &adw::ApplicationWindow, toasts: &adw::ToastOverlay, text: &str) {
    app_win.clipboard().set_text(text);
    toasts.add_toast(adw::Toast::new("Copied to clipboard."));
}

pub fn build_donation_content(
    app_win: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
) -> gtk::Widget {
    let group = adw::PreferencesGroup::builder()
        .description("Tap an option to copy it to the clipboard.")
        .build();

    for &(title, text) in DONATION_OPTIONS {
        let subtitle = if text.len() < 40 {
            text.to_string()
        } else {
            format!("{}…{}", &text[..18], &text[text.len() - 10..])
        };
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(&subtitle)
            .activatable(true)
            .build();
        row.add_suffix(&gtk::Image::from_icon_name("edit-copy-symbolic"));
        let win_c = app_win.clone();
        let toasts_c = toasts.clone();
        row.connect_activated(move |_| {
            copy_donation_text(&win_c, &toasts_c, text);
        });
        group.add(&row);
    }

    let clamp = adw::Clamp::builder()
        .maximum_size(480)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(12)
        .margin_end(12)
        .build();
    clamp.set_child(Some(&group));
    clamp.upcast()
}

pub fn present_donation_dialog(
    parent: &impl IsA<gtk::Widget>,
    app_win: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
) {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    scrolled.set_child(Some(&build_donation_content(app_win, toasts)));
    toolbar.set_content(Some(&scrolled));

    let dialog = adw::Dialog::builder()
        .title("Donate")
        .content_width(420)
        .content_height(320)
        .child(&toolbar)
        .build();
    dialog.present(Some(parent));
}

fn find_descendants<P: Fn(&gtk::Widget) -> bool>(root: &gtk::Widget, pred: &P, out: &mut Vec<gtk::Widget>) {
    let mut child = root.first_child();
    while let Some(w) = child {
        if pred(&w) {
            out.push(w.clone());
        }
        find_descendants(&w, pred, out);
        child = w.next_sibling();
    }
}

fn find_row_by_label(root: &gtk::Widget, text: &str) -> Option<gtk::ListBoxRow> {
    let mut labels = Vec::new();
    find_descendants(
        root,
        &|w| {
            w.downcast_ref::<gtk::Label>()
                .is_some_and(|l| l.text().trim() == text)
        },
        &mut labels,
    );
    for lbl in labels {
        let mut cur = lbl.parent();
        while let Some(p) = cur {
            if let Ok(row) = p.clone().downcast::<gtk::ListBoxRow>() {
                if row
                    .parent()
                    .and_then(|gp| gp.downcast::<gtk::ListBox>().ok())
                    .is_some()
                {
                    return Some(row);
                }
            }
            cur = p.parent();
        }
    }
    None
}

fn list_box_len(lb: &gtk::ListBox) -> i32 {
    let mut n = 0;
    while lb.row_at_index(n).is_some() {
        n += 1;
    }
    n
}

fn inject_donate_row(
    dialog: &adw::AboutDialog,
    app_win: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
) -> bool {
    let root: gtk::Widget = dialog.clone().upcast();

    let (listbox, index) = if let (Some(legal), Some(creds)) = (
        find_row_by_label(&root, "Legal"),
        find_row_by_label(&root, "Credits"),
    ) {
        if legal.parent() == creds.parent() {
            if let Some(lb) = legal.parent().and_then(|p| p.downcast::<gtk::ListBox>().ok()) {
                (lb, legal.index())
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        let mut listboxes = Vec::new();
        find_descendants(
            &root,
            &|w| {
                w.downcast_ref::<gtk::ListBox>()
                    .is_some_and(|lb| list_box_len(lb) >= 2)
            },
            &mut listboxes,
        );
        let Some(lb) = listboxes
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::ListBox>().ok())
            .max_by_key(list_box_len)
        else {
            return false;
        };
        let len = list_box_len(&lb);
        (lb, len - 1)
    };

    // Guard against duplicate insertion
    let mut already = Vec::new();
    find_descendants(
        &listbox.clone().upcast(),
        &|w| w.widget_name() == "cipherdeck-donate-row",
        &mut already,
    );
    if !already.is_empty() {
        return true;
    }

    let row = adw::ActionRow::builder()
        .title("Donate")
        .activatable(true)
        .name("cipherdeck-donate-row")
        .build();
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

    let dialog_c = dialog.clone();
    let app_win_c = app_win.clone();
    let toasts_c = toasts.clone();
    row.connect_activated(move |_| {
        let mut navs = Vec::new();
        find_descendants(
            &dialog_c.clone().upcast(),
            &|w| w.is::<adw::NavigationView>(),
            &mut navs,
        );
        if let Some(nav) = navs
            .into_iter()
            .find_map(|w| w.downcast::<adw::NavigationView>().ok())
        {
            let toolbar = adw::ToolbarView::new();
            toolbar.add_top_bar(&adw::HeaderBar::new());
            let scrolled = gtk::ScrolledWindow::builder()
                .vexpand(true)
                .hscrollbar_policy(gtk::PolicyType::Never)
                .build();
            scrolled.set_child(Some(&build_donation_content(&app_win_c, &toasts_c)));
            toolbar.set_content(Some(&scrolled));
            nav.push(&adw::NavigationPage::new(&toolbar, "Donate"));
        } else {
            present_donation_dialog(&dialog_c, &app_win_c, &toasts_c);
        }
    });

    listbox.insert(&row, index);
    true
}

pub fn present_about_dialog(app_win: &adw::ApplicationWindow, toasts: &adw::ToastOverlay) {
    let about = adw::AboutDialog::builder()
        .application_name("CipherDeck")
        .application_icon("io.github.woosah.CipherDeck")
        .version(env!("CARGO_PKG_VERSION"))
        .developer_name("Woosah")
        .copyright("© 2026 WOOSAH")
        .license_type(gtk::License::MitX11)
        .website("https://GitHub.com/Smiley-McSmiles/CipherDeck")
        .issue_url("https://GitHub.com/Smiley-McSmiles/CipherDeck/issues")
        .comments("Argon2id · AES-256-GCM + XChaCha20-Poly1305 Cascade · Ed25519 Signed\nField-level CRDT sync with zero-metadata padding")
        .build();
    about.present(Some(app_win));

    let tries = Rc::new(Cell::new(0u8));
    if !inject_donate_row(&about, app_win, toasts) {
        let about_c = about.clone();
        let app_win_c = app_win.clone();
        let toasts_c = toasts.clone();
        let tries_c = tries.clone();
        glib::timeout_add_local(Duration::from_millis(120), move || {
            let n = tries_c.get() + 1;
            tries_c.set(n);
            if inject_donate_row(&about_c, &app_win_c, &toasts_c) || n >= 10 {
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    }
}
