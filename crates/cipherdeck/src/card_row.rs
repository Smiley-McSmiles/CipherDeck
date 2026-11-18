use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use gtk::pango;
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use uuid::Uuid;
use vault_core::{
    estimate_entropy_bits, strength_from_entropy, Card, CardKind, CustomFieldValue, Hlc,
    LwwField, StrengthLevel,
};

use crate::password_gen_widget::build_password_generator_box;

#[derive(Clone)]
pub struct CardCallbacks {
    pub on_copy_secret: Rc<dyn Fn(String, String)>,
    pub on_copy_text: Rc<dyn Fn(String, String)>,
    pub on_save_card: Rc<dyn Fn(Card)>,
    pub on_auto_save: Rc<dyn Fn(Card)>,
    pub on_delete_empty: Rc<dyn Fn(Uuid)>,
    pub on_expand_changed: Rc<dyn Fn(Uuid, bool)>,
    pub on_toggle_trash: Rc<dyn Fn(Uuid, bool)>,
    pub on_jump_card: Rc<dyn Fn(String)>,
}

const ICON_COLORS: &[&str] = &[
    "", "blue", "teal", "green", "amber", "orange", "red", "purple", "pink",
];

fn apply_icon_color_class(icon: &gtk::Image, color: &str) {
    for c in ICON_COLORS.iter().filter(|c| !c.is_empty()) {
        icon.remove_css_class(&format!("icon-color-{c}"));
    }
    if !color.is_empty() {
        icon.add_css_class(&format!("icon-color-{color}"));
    }
}

fn card_title_text(card: &Card) -> String {
    if card.title.value.trim().is_empty() {
        "(Untitled)".to_string()
    } else {
        card.title.value.clone()
    }
}

fn card_subtitle_text(card: &Card) -> String {
    match card.kind.value {
        CardKind::Login => {
            let mut parts = Vec::new();
            if !card.username.value.trim().is_empty() {
                parts.push(card.username.value.clone());
            } else if !card.email.value.trim().is_empty() {
                parts.push(card.email.value.clone());
            }
            if !card.url.value.trim().is_empty() {
                parts.push(card.url.value.clone());
            }
            parts.push(fmt_time_ago(card.max_hlc().unix_ms));
            parts.join(" · ")
        }
        CardKind::Note => {
            let snippet: String = card
                .notes_markdown
                .value
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("Markdown Note")
                .chars()
                .take(64)
                .collect();
            format!("{} · {}", snippet, fmt_time_ago(card.max_hlc().unix_ms))
        }
    }
}

fn fmt_time_ago(unix_ms: u64) -> String {
    if unix_ms == 0 {
        return "—".into();
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let diff_s = now_ms.saturating_sub(unix_ms) / 1000;
    if diff_s < 60 {
        "just now".into()
    } else if diff_s < 3600 {
        format!("{}m ago", diff_s / 60)
    } else if diff_s < 86_400 {
        format!("{}h ago", diff_s / 3600)
    } else {
        format!("{}d ago", diff_s / 86_400)
    }
}

fn stat_tile(label: &str, value: &str) -> gtk::Box {
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 2);
    bx.add_css_class("stat-tile");
    let top = gtk::Label::new(Some(label));
    top.set_xalign(0.0);
    top.add_css_class("caption");
    top.add_css_class("dim-label");
    let val = gtk::Label::new(Some(value));
    val.set_xalign(0.0);
    val.add_css_class("stat-value");
    val.add_css_class("numeric");
    bx.append(&top);
    bx.append(&val);
    bx
}

fn toggle_markdown_checkbox(md: &str, target_idx: usize, checked: bool) -> Option<String> {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_TABLES);

    let mut idx = 0usize;
    for (event, range) in Parser::new_ext(md, opts).into_offset_iter() {
        if matches!(event, Event::TaskListMarker(_)) {
            if idx == target_idx {
                let replacement = if checked { "[x]" } else { "[ ]" };
                let mut out = String::with_capacity(md.len());
                out.push_str(&md[..range.start]);
                out.push_str(replacement);
                out.push_str(&md[range.end..]);
                return Some(out);
            }
            idx += 1;
        }
    }
    None
}

fn make_markdown_label(
    markup: &str,
    inline_codes: Vec<String>,
    cb: &CardCallbacks,
) -> gtk::Label {
    let lbl = gtk::Label::new(None);
    lbl.set_markup(markup);
    lbl.set_xalign(0.0);
    lbl.set_wrap(true);
    lbl.set_wrap_mode(pango::WrapMode::WordChar);
    lbl.set_selectable(true);

    let codes = Rc::new(inline_codes);
    let cb = cb.clone();
    lbl.connect_activate_link(move |_, uri| {
        if let Some(rest) = uri.strip_prefix("copycode:") {
            if let Ok(idx) = rest.parse::<usize>() {
                if let Some(code) = codes.get(idx) {
                    (cb.on_copy_text)("Inline code".into(), code.clone());
                    return glib::Propagation::Stop;
                }
            }
        }
        glib::Propagation::Proceed
    });
    lbl
}

fn build_code_block_widget(lang: &str, code: &str, cb: &CardCallbacks) -> gtk::Box {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
    container.add_css_class("code-block");

    let header = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    header.add_css_class("code-block-header");

    let lang_text = if lang.trim().is_empty() {
        "code"
    } else {
        lang.trim()
    };
    let lang_lbl = gtk::Label::new(Some(lang_text));
    lang_lbl.set_xalign(0.0);
    lang_lbl.set_hexpand(true);
    lang_lbl.add_css_class("code-block-lang");
    header.append(&lang_lbl);

    let copy_btn = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy_btn.add_css_class("flat");
    copy_btn.add_css_class("code-block-copy");
    copy_btn.set_tooltip_text(Some("Copy code block"));
    let code_owned = code.trim_end_matches('\n').to_string();
    let cb_c = cb.clone();
    let code_for_click = code_owned.clone();
    copy_btn.connect_clicked(move |_| {
        (cb_c.on_copy_text)("Code".into(), code_for_click.clone());
    });
    header.append(&copy_btn);
    container.append(&header);

    let body_lbl = gtk::Label::new(Some(&code_owned));
    body_lbl.set_xalign(0.0);
    body_lbl.set_selectable(true);
    body_lbl.add_css_class("code-block-body");

    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .vscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true)
        .child(&body_lbl)
        .build();
    container.append(&scroll);

    container
}

fn render_markdown_into_box(
    md: &str,
    preview_box: &gtk::Box,
    cb: &CardCallbacks,
    on_toggle_task: &Rc<dyn Fn(usize, bool)>,
) {
    while let Some(child) = preview_box.first_child() {
        preview_box.remove(&child);
    }

    if md.trim().is_empty() {
        let empty = gtk::Label::new(Some("Nothing to preview."));
        empty.set_xalign(0.0);
        empty.add_css_class("dim-label");
        preview_box.append(&empty);
        return;
    }

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_TABLES);

    let parser = Parser::new_ext(md, opts);
    let mut out = String::new();
    let mut inline_codes: Vec<String> = Vec::new();
    let mut list_stack: Vec<Option<u64>> = Vec::new();
    let mut in_blockquote = false;
    let mut in_table_row = false;
    let mut table_first_cell = true;
    let mut need_list_prefix = false;

    let mut in_code_block = false;
    let mut code_lang = String::new();
    let mut code_buf = String::new();

    let mut item_prefix_start: Option<usize> = None;
    let mut pending_task: Option<(usize, bool, usize)> = None;
    let mut task_idx: usize = 0;

    let flush_pango = |out: &mut String, inline_codes: &mut Vec<String>| {
        let trimmed = out.trim();
        if !trimmed.is_empty() {
            let codes = std::mem::take(inline_codes);
            let lbl = make_markdown_label(trimmed, codes, cb);
            preview_box.append(&lbl);
        } else {
            inline_codes.clear();
        }
        out.clear();
    };

    let flush_pending_task = |pending_task: &mut Option<(usize, bool, usize)>,
                              out: &mut String,
                              inline_codes: &mut Vec<String>| {
        if let Some((idx, checked, indent_depth)) = pending_task.take() {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            row.add_css_class("markdown-task-row");
            if indent_depth > 0 {
                row.set_margin_start((indent_depth as i32) * 18);
            }

            let check = gtk::CheckButton::builder()
                .active(checked)
                .valign(gtk::Align::Start)
                .build();
            let toggle_cb = on_toggle_task.clone();
            check.connect_toggled(move |b| {
                toggle_cb(idx, b.is_active());
            });
            row.append(&check);

            let trimmed = out.trim();
            let codes = std::mem::take(inline_codes);
            let lbl = make_markdown_label(trimmed, codes, cb);
            lbl.set_hexpand(true);
            row.append(&lbl);

            preview_box.append(&row);
            out.clear();
        }
    };

    for event in parser {
        match event {
            Event::Start(tag) => match tag {
                Tag::Heading { level, .. } => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    match level {
                        HeadingLevel::H1 => out.push_str("<span size='x-large' weight='bold'>"),
                        HeadingLevel::H2 => out.push_str("<span size='large' weight='bold'>"),
                        _ => out.push_str("<b>"),
                    }
                }
                Tag::Paragraph => {
                    if need_list_prefix {
                        need_list_prefix = false;
                    } else if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                Tag::BlockQuote(_) => {
                    in_blockquote = true;
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("<i>│ ");
                }
                Tag::CodeBlock(kind) => {
                    flush_pending_task(&mut pending_task, &mut out, &mut inline_codes);
                    flush_pango(&mut out, &mut inline_codes);
                    in_code_block = true;
                    code_lang = match kind {
                        CodeBlockKind::Fenced(lang) => lang.to_string(),
                        CodeBlockKind::Indented => String::new(),
                    };
                    code_buf.clear();
                }
                Tag::List(start_num) => {
                    if pending_task.is_some() {
                        flush_pending_task(&mut pending_task, &mut out, &mut inline_codes);
                    } else if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    list_stack.push(start_num);
                }
                Tag::Item => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    item_prefix_start = Some(out.len());
                    let indent = "  ".repeat(list_stack.len().saturating_sub(1));
                    out.push_str(&indent);
                    if let Some(last) = list_stack.last_mut() {
                        match last {
                            Some(n) => {
                                out.push_str(&format!("{}. ", *n));
                                *n += 1;
                            }
                            None => out.push_str("• "),
                        }
                    }
                    need_list_prefix = true;
                }
                Tag::Emphasis => out.push_str("<i>"),
                Tag::Strong => out.push_str("<b>"),
                Tag::Strikethrough => out.push_str("<s>"),
                Tag::Link { dest_url, .. } => {
                    let href = glib::markup_escape_text(&dest_url);
                    out.push_str(&format!("<a href=\"{href}\">"));
                }
                Tag::Table(_) => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                Tag::TableHead | Tag::TableRow => {
                    in_table_row = true;
                    table_first_cell = true;
                }
                Tag::TableCell => {
                    if in_table_row && !table_first_cell {
                        out.push_str("  │  ");
                    }
                    table_first_cell = false;
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Heading(level) => match level {
                    HeadingLevel::H1 | HeadingLevel::H2 => out.push_str("</span>\n"),
                    _ => out.push_str("</b>\n"),
                },
                TagEnd::Paragraph => {
                    if pending_task.is_none() {
                        out.push_str("\n\n");
                    }
                }
                TagEnd::BlockQuote(_) => {
                    in_blockquote = false;
                    out.push_str("</i>\n");
                }
                TagEnd::CodeBlock => {
                    let block = build_code_block_widget(&code_lang, &code_buf, cb);
                    preview_box.append(&block);
                    in_code_block = false;
                    code_lang.clear();
                    code_buf.clear();
                }
                TagEnd::List(_) => {
                    list_stack.pop();
                    if list_stack.is_empty() && !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                TagEnd::Item => {
                    need_list_prefix = false;
                    item_prefix_start = None;
                    if pending_task.is_some() {
                        flush_pending_task(&mut pending_task, &mut out, &mut inline_codes);
                    } else if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                TagEnd::Emphasis => out.push_str("</i>"),
                TagEnd::Strong => out.push_str("</b>"),
                TagEnd::Strikethrough => out.push_str("</s>"),
                TagEnd::Link => out.push_str("</a>"),
                TagEnd::TableHead => {
                    in_table_row = false;
                    out.push_str("\n────────────────────────\n");
                }
                TagEnd::TableRow => {
                    in_table_row = false;
                    out.push('\n');
                }
                TagEnd::Table => {
                    out.push('\n');
                }
                _ => {}
            },
            Event::Text(text) => {
                if in_code_block {
                    code_buf.push_str(&text);
                } else {
                    let escaped = glib::markup_escape_text(&text);
                    if in_blockquote {
                        out.push_str(&escaped.replace('\n', "\n│ "));
                    } else {
                        out.push_str(&escaped);
                    }
                }
            }
            Event::Code(code) => {
                let idx = inline_codes.len();
                inline_codes.push(code.to_string());
                out.push_str(&format!("<a href=\"copycode:{idx}\"><tt>"));
                out.push_str(&glib::markup_escape_text(&code));
                out.push_str("</tt></a>");
            }
            Event::SoftBreak => {
                if in_code_block {
                    code_buf.push('\n');
                } else if in_blockquote {
                    out.push_str("\n│ ");
                } else {
                    out.push('\n');
                }
            }
            Event::HardBreak => {
                if in_code_block {
                    code_buf.push('\n');
                } else if in_blockquote {
                    out.push_str("\n│ ");
                } else {
                    out.push('\n');
                }
            }
            Event::Rule => {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("────────────────────────\n");
            }
            Event::TaskListMarker(checked) => {
                if let Some(pos) = item_prefix_start.take() {
                    out.truncate(pos);
                }
                flush_pango(&mut out, &mut inline_codes);
                let indent_depth = list_stack.len().saturating_sub(1);
                pending_task = Some((task_idx, checked, indent_depth));
                task_idx += 1;
            }
            _ => {}
        }
    }

    flush_pending_task(&mut pending_task, &mut out, &mut inline_codes);
    flush_pango(&mut out, &mut inline_codes);
}

fn extract_card_links(md: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = md;
    while let Some(start) = rest.find("[[") {
        let after = &rest[start + 2..];
        if let Some(end) = after.find("]]") {
            let target = after[..end].trim();
            if !target.is_empty() && !links.iter().any(|x| x == target) {
                links.push(target.to_string());
            }
            rest = &after[end + 2..];
        } else {
            break;
        }
    }
    links
}

#[derive(Clone)]
pub struct CardRow {
    pub row: gtk::ListBoxRow,
    pub card: Rc<RefCell<Card>>,
    expanded: Rc<RefCell<bool>>,
    details_built: Rc<RefCell<bool>>,
    revealer: gtk::Revealer,
    callbacks: CardCallbacks,
    title_lbl: gtk::Label,
    sub_lbl: gtk::Label,
    title_entry: Rc<RefCell<Option<adw::EntryRow>>>,
}

impl CardRow {
    pub fn new(card: Card, callbacks: CardCallbacks) -> Self {
        let row = gtk::ListBoxRow::new();
        row.set_activatable(false);
        row.set_selectable(false);
        row.add_css_class("vault-card");

        if card.kind.value == CardKind::Note {
            row.add_css_class("kind-note");
        }
        if card.is_deleted() {
            row.add_css_class("is-trashed");
        } else if card.kind.value == CardKind::Login && !card.password.value.is_empty() {
            let bits = estimate_entropy_bits(&card.password.value);
            if matches!(strength_from_entropy(bits), StrengthLevel::Weak) {
                row.add_css_class("strength-weak");
            }
        }

        let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
        row.set_child(Some(&outer));

        let top = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        outer.append(&top);

        let icon_name = if card.is_deleted() {
            "user-trash-symbolic"
        } else if card.kind.value == CardKind::Note {
            "document-edit-symbolic"
        } else {
            "dialog-password-symbolic"
        };
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.set_pixel_size(16);
        icon.set_valign(gtk::Align::Center);
        icon.add_css_class("state-icon");
        apply_icon_color_class(&icon, &card.icon_color.value);

        let icon_btn = gtk::Button::new();
        icon_btn.set_valign(gtk::Align::Center);
        icon_btn.set_margin_start(10);
        icon_btn.add_css_class("flat");
        icon_btn.add_css_class("circular");
        icon_btn.add_css_class("state-icon-btn");
        icon_btn.set_tooltip_text(Some("Click to change icon color"));
        icon_btn.set_child(Some(&icon));
        top.append(&icon_btn);

        let header_btn = gtk::Button::new();
        header_btn.set_hexpand(true);
        header_btn.add_css_class("flat");
        header_btn.add_css_class("card-header");
        top.append(&header_btn);

        let hb = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        header_btn.set_child(Some(&hb));

        let mid = gtk::Box::new(gtk::Orientation::Vertical, 4);
        mid.set_hexpand(true);
        mid.set_valign(gtk::Align::Center);
        hb.append(&mid);

        let trow = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let title_text = card_title_text(&card);
        let title_lbl = gtk::Label::new(Some(&title_text));
        title_lbl.set_xalign(0.0);
        title_lbl.set_ellipsize(pango::EllipsizeMode::End);
        title_lbl.set_hexpand(true);
        title_lbl.add_css_class("heading");
        trow.append(&title_lbl);

        if card.favorite.value {
            let star = gtk::Image::from_icon_name("starred-symbolic");
            star.set_pixel_size(14);
            trow.append(&star);
        }

        if !card.folder.value.trim().is_empty() {
            let folder_chip = gtk::Label::new(Some(&card.folder.value));
            folder_chip.add_css_class("folder-chip");
            trow.append(&folder_chip);
        }
        if let Some(first_tag) = card.tags.value.first() {
            let tag_chip = gtk::Label::new(Some(first_tag));
            tag_chip.add_css_class("label-chip");
            trow.append(&tag_chip);
        }
        mid.append(&trow);

        let sub_text = card_subtitle_text(&card);
        let sub_lbl = gtk::Label::new(Some(&sub_text));
        sub_lbl.set_xalign(0.0);
        sub_lbl.set_ellipsize(pango::EllipsizeMode::End);
        sub_lbl.add_css_class("caption");
        sub_lbl.add_css_class("dim-label");
        mid.append(&sub_lbl);

        let arrow = gtk::Image::from_icon_name("pan-down-symbolic");
        arrow.set_valign(gtk::Align::Center);
        arrow.add_css_class("expand-arrow");
        hb.append(&arrow);

        // Quick 1-click copy buttons right on the card header
        let quick_copy_user = if card.kind.value == CardKind::Login {
            let btn = gtk::Button::from_icon_name("avatar-default-symbolic");
            btn.set_valign(gtk::Align::Center);
            btn.set_margin_start(2);
            btn.add_css_class("circular");
            btn.add_css_class("flat");
            btn.set_tooltip_text(Some("Copy username"));
            top.append(&btn);
            Some(btn)
        } else {
            None
        };

        let quick_copy = gtk::Button::from_icon_name("edit-copy-symbolic");
        quick_copy.set_valign(gtk::Align::Center);
        quick_copy.set_margin_end(10);
        quick_copy.set_margin_start(2);
        quick_copy.add_css_class("circular");
        quick_copy.add_css_class("flat");
        quick_copy.set_tooltip_text(Some(if card.kind.value == CardKind::Note {
            "Copy note"
        } else {
            "Copy password"
        }));
        top.append(&quick_copy);

        let revealer = gtk::Revealer::new();
        revealer.set_transition_type(gtk::RevealerTransitionType::SlideDown);
        revealer.set_transition_duration(220);
        outer.append(&revealer);

        let card_rc = Rc::new(RefCell::new(card));
        let expanded = Rc::new(RefCell::new(false));
        let details_built = Rc::new(RefCell::new(false));
        let title_entry: Rc<RefCell<Option<adw::EntryRow>>> = Rc::new(RefCell::new(None));

        {
            let card_rc = card_rc.clone();
            let cb = callbacks.clone();
            let icon = icon.clone();
            icon_btn.connect_clicked(move |_| {
                let mut updated = card_rc.borrow().clone();
                let cur = updated.icon_color.value.as_str();
                let idx = ICON_COLORS.iter().position(|c| *c == cur).unwrap_or(0);
                let next_color = ICON_COLORS[(idx + 1) % ICON_COLORS.len()];
                let dev_id = updated.title.hlc.device_id;
                let dev_name = updated.title.author_device.clone();
                updated
                    .icon_color
                    .set(next_color.to_string(), dev_id, &dev_name, 16);
                apply_icon_color_class(&icon, next_color);
                *card_rc.borrow_mut() = updated.clone();
                (cb.on_auto_save)(updated);
            });
        }

        if let Some(qcu) = quick_copy_user {
            let card_rc = card_rc.clone();
            let cb = callbacks.clone();
            qcu.connect_clicked(move |_| {
                let c = card_rc.borrow();
                (cb.on_copy_text)("Username".into(), c.username.value.clone());
            });
        }

        {
            let card_rc = card_rc.clone();
            let cb = callbacks.clone();
            quick_copy.connect_clicked(move |_| {
                let c = card_rc.borrow();
                if c.kind.value == CardKind::Note {
                    (cb.on_copy_text)("Note".into(), c.notes_markdown.value.clone());
                } else {
                    (cb.on_copy_secret)("Password".into(), c.password.value.clone());
                }
            });
        }

        let this = Self {
            row: row.clone(),
            card: card_rc,
            expanded,
            details_built,
            revealer,
            callbacks,
            title_lbl,
            sub_lbl,
            title_entry,
        };

        {
            let this_c = this.clone_handle();
            header_btn.connect_clicked(move |_| {
                let next = !*this_c.expanded.borrow();
                this_c.set_expanded(next);
            });
        }

        this
    }

    fn clone_handle(&self) -> Self {
        Self {
            row: self.row.clone(),
            card: self.card.clone(),
            expanded: self.expanded.clone(),
            details_built: self.details_built.clone(),
            revealer: self.revealer.clone(),
            callbacks: self.callbacks.clone(),
            title_lbl: self.title_lbl.clone(),
            sub_lbl: self.sub_lbl.clone(),
            title_entry: self.title_entry.clone(),
        }
    }

    pub fn set_expanded(&self, expand: bool) {
        let was_expanded = *self.expanded.borrow();
        if was_expanded == expand {
            return;
        }
        *self.expanded.borrow_mut() = expand;
        let card_id = self.card.borrow().id;
        if expand {
            if !*self.details_built.borrow() {
                let (details, t_entry) = build_card_details(
                    &self.card,
                    &self.callbacks,
                    &self.title_lbl,
                    &self.sub_lbl,
                );
                *self.title_entry.borrow_mut() = Some(t_entry);
                self.revealer.set_child(Some(&details));
                *self.details_built.borrow_mut() = true;
            }
            self.row.add_css_class("expanded");
            self.revealer.set_reveal_child(true);
            (self.callbacks.on_expand_changed)(card_id, true);
        } else {
            self.row.remove_css_class("expanded");
            self.revealer.set_reveal_child(false);
            (self.callbacks.on_expand_changed)(card_id, false);
            if self.card.borrow().is_completely_empty() {
                (self.callbacks.on_delete_empty)(card_id);
            }
        }
    }

    pub fn focus_title(&self) {
        if let Some(ref t) = *self.title_entry.borrow() {
            t.grab_focus();
        }
    }
}

fn build_card_details(
    card_rc: &Rc<RefCell<Card>>,
    cb: &CardCallbacks,
    header_title_lbl: &gtk::Label,
    header_sub_lbl: &gtk::Label,
) -> (gtk::Box, adw::EntryRow) {
    let details = gtk::Box::new(gtk::Orientation::Vertical, 12);
    details.add_css_class("card-details");

    let c = card_rc.borrow().clone();

    // 1. Action bar
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    actions.add_css_class("details-actions");

    if c.kind.value == CardKind::Login {
        let copy_user = gtk::Button::with_label("Copy User");
        let u = c.username.value.clone();
        let cb_u = cb.clone();
        copy_user.connect_clicked(move |_| (cb_u.on_copy_text)("Username".into(), u.clone()));
        actions.append(&copy_user);

        let copy_pw = gtk::Button::with_label("Copy Password");
        let p = c.password.value.clone();
        let cb_p = cb.clone();
        copy_pw.connect_clicked(move |_| (cb_p.on_copy_secret)("Password".into(), p.clone()));
        actions.append(&copy_pw);
    }

    let fav_btn = gtk::ToggleButton::with_label(if c.favorite.value {
        "Favorited"
    } else {
        "Favorite"
    });
    fav_btn.set_active(c.favorite.value);
    actions.append(&fav_btn);

    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    actions.append(&spacer);

    let is_deleted = c.is_deleted();
    let trash_btn = gtk::Button::with_label(if is_deleted { "Restore" } else { "Trash" });
    if !is_deleted {
        trash_btn.add_css_class("destructive-action");
    }
    {
        let cb_t = cb.clone();
        let id = c.id;
        trash_btn.connect_clicked(move |_| (cb_t.on_toggle_trash)(id, !is_deleted));
    }
    actions.append(&trash_btn);
    details.append(&actions);

    // 2. Stat tiles
    let flow = gtk::FlowBox::new();
    flow.set_selection_mode(gtk::SelectionMode::None);
    flow.set_row_spacing(8);
    flow.set_column_spacing(8);
    flow.set_min_children_per_line(2);
    flow.set_max_children_per_line(4);
    flow.add_css_class("stat-flow");

    if c.kind.value == CardKind::Login {
        let bits = estimate_entropy_bits(&c.password.value);
        let label = format!("{:.0} bits · {}", bits, strength_from_entropy(bits).label());
        flow.insert(&stat_tile("Password Strength", &label), -1);
    } else {
        flow.insert(&stat_tile("Type", "Markdown Note"), -1);
    }
    flow.insert(&stat_tile("Modified", &fmt_time_ago(c.max_hlc().unix_ms)), -1);
    flow.insert(&stat_tile("Revisions", &c.total_revisions().to_string()), -1);
    flow.insert(&stat_tile("Author Device", &c.title.author_device), -1);
    details.append(&flow);

    // 3. Roll-down boxed-list sections
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");
    details.append(&list);

    // Section A: Fields & Inline Password Generator
    let creds_exp = adw::ExpanderRow::builder()
        .title(if c.kind.value == CardKind::Login {
            "Credentials &amp; Password Generator"
        } else {
            "Card Metadata"
        })
        .expanded(true)
        .build();

    let title_row = adw::EntryRow::builder().title("Title").build();
    title_row.set_text(&c.title.value);
    creds_exp.add_row(&title_row);

    let user_row = adw::EntryRow::builder().title("Username").build();
    user_row.set_text(&c.username.value);
    let pw_row = adw::PasswordEntryRow::builder().title("Password").build();
    pw_row.set_text(&c.password.value);
    let email_row = adw::EntryRow::builder().title("Email").build();
    email_row.set_text(&c.email.value);
    let url_row = adw::EntryRow::builder().title("URL").build();
    url_row.set_text(&c.url.value);

    if c.kind.value == CardKind::Login {
        creds_exp.add_row(&user_row);
        creds_exp.add_row(&pw_row);
        creds_exp.add_row(&email_row);
        creds_exp.add_row(&url_row);

        // Nested roll-down Password Generator!
        let gen_exp = adw::ExpanderRow::builder()
            .title("Generate Strong Password")
            .subtitle("CSPRNG · Customize length, capitals, symbols or passphrase")
            .build();
        let pw_row_clone = pw_row.clone();
        let gen_box = build_password_generator_box(move |new_pw| {
            pw_row_clone.set_text(new_pw);
        });
        let gen_row = gtk::ListBoxRow::new();
        gen_row.set_activatable(false);
        gen_row.set_selectable(false);
        gen_box.set_margin_start(12);
        gen_box.set_margin_end(12);
        gen_box.set_margin_top(6);
        gen_box.set_margin_bottom(8);
        gen_row.set_child(Some(&gen_box));
        gen_exp.add_row(&gen_row);
        creds_exp.add_row(&gen_exp);
    }

    let folder_row = adw::EntryRow::builder().title("Folder").build();
    folder_row.set_text(&c.folder.value);
    creds_exp.add_row(&folder_row);

    let tags_row = adw::EntryRow::builder().title("Tags (comma-separated)").build();
    tags_row.set_text(&c.tags.value.join(", "));
    creds_exp.add_row(&tags_row);

    list.append(&creds_exp);

    // Section B: Custom Attributes (with Sensitive toggle & Eye reveal)
    #[derive(Clone)]
    struct CustomFieldUi {
        id: u64,
        name_entry: gtk::Entry,
        value_entry: gtk::Entry,
        sensitive_btn: gtk::ToggleButton,
    }

    let custom_ui_list: Rc<RefCell<Vec<CustomFieldUi>>> = Rc::new(RefCell::new(Vec::new()));
    let next_cf_id: Rc<RefCell<u64>> = Rc::new(RefCell::new(1));
    let on_attr_change: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));

    let attrs_exp = adw::ExpanderRow::builder()
        .title("Custom Attributes")
        .subtitle(if c.custom_fields.is_empty() {
            "None".to_string()
        } else {
            format!("{} fields", c.custom_fields.len())
        })
        .expanded(!c.custom_fields.is_empty())
        .build();

    let attrs_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    attrs_box.set_margin_start(12);
    attrs_box.set_margin_end(12);
    attrs_box.set_margin_top(8);
    attrs_box.set_margin_bottom(10);

    let attrs_rows_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    attrs_box.append(&attrs_rows_box);

    let add_attr_row_fn: Rc<dyn Fn(&str, &str, bool)> = {
        let attrs_rows_box = attrs_rows_box.clone();
        let custom_ui_list = custom_ui_list.clone();
        let next_cf_id = next_cf_id.clone();
        let cb = cb.clone();
        let on_attr_change = on_attr_change.clone();
        Rc::new(move |key: &str, val: &str, secret: bool| {
            let cf_id = {
                let mut g = next_cf_id.borrow_mut();
                let v = *g;
                *g += 1;
                v
            };

            let row_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);

            let name_entry = gtk::Entry::builder()
                .placeholder_text("Attribute name")
                .text(key)
                .width_chars(14)
                .build();

            let value_entry = gtk::Entry::builder()
                .placeholder_text("Value")
                .text(val)
                .hexpand(true)
                .visibility(!secret)
                .build();

            let eye_btn = gtk::ToggleButton::new();
            eye_btn.set_icon_name("view-reveal-symbolic");
            eye_btn.set_tooltip_text(Some("Reveal / hide value"));
            eye_btn.set_active(!secret);
            eye_btn.add_css_class("flat");
            eye_btn.set_visible(secret);

            let sensitive_btn = gtk::ToggleButton::new();
            sensitive_btn.set_icon_name("channel-secure-symbolic");
            sensitive_btn.set_tooltip_text(Some("Sensitive (hidden by default)"));
            sensitive_btn.set_active(secret);
            sensitive_btn.add_css_class("flat");

            {
                let value_entry = value_entry.clone();
                let eye_btn_c = eye_btn.clone();
                sensitive_btn.connect_toggled(move |b| {
                    let is_sec = b.is_active();
                    eye_btn_c.set_visible(is_sec);
                    if is_sec {
                        eye_btn_c.set_active(false);
                        value_entry.set_visibility(false);
                    } else {
                        value_entry.set_visibility(true);
                    }
                });
            }

            {
                let value_entry = value_entry.clone();
                eye_btn.connect_toggled(move |b| {
                    value_entry.set_visibility(b.is_active());
                    b.set_icon_name(if b.is_active() {
                        "view-conceal-symbolic"
                    } else {
                        "view-reveal-symbolic"
                    });
                });
            }

            let copy_btn = gtk::Button::from_icon_name("edit-copy-symbolic");
            copy_btn.set_tooltip_text(Some("Copy attribute value"));
            copy_btn.add_css_class("flat");
            {
                let name_entry = name_entry.clone();
                let value_entry = value_entry.clone();
                let sensitive_btn = sensitive_btn.clone();
                let cb = cb.clone();
                copy_btn.connect_clicked(move |_| {
                    let label = {
                        let n = name_entry.text().to_string();
                        if n.trim().is_empty() {
                            "Attribute".to_string()
                        } else {
                            n
                        }
                    };
                    let val = value_entry.text().to_string();
                    if sensitive_btn.is_active() {
                        (cb.on_copy_secret)(label, val);
                    } else {
                        (cb.on_copy_text)(label, val);
                    }
                });
            }

            let del_btn = gtk::Button::from_icon_name("user-trash-symbolic");
            del_btn.set_tooltip_text(Some("Remove attribute"));
            del_btn.add_css_class("flat");
            {
                let attrs_rows_box = attrs_rows_box.clone();
                let row_box = row_box.clone();
                let custom_ui_list = custom_ui_list.clone();
                let on_attr_change = on_attr_change.clone();
                del_btn.connect_clicked(move |_| {
                    attrs_rows_box.remove(&row_box);
                    custom_ui_list.borrow_mut().retain(|item| item.id != cf_id);
                    if let Some(f) = on_attr_change.borrow().as_ref() {
                        f();
                    }
                });
            }

            {
                let on_attr_change = on_attr_change.clone();
                name_entry.connect_changed(move |_| {
                    if let Some(f) = on_attr_change.borrow().as_ref() {
                        f();
                    }
                });
            }
            {
                let on_attr_change = on_attr_change.clone();
                value_entry.connect_changed(move |_| {
                    if let Some(f) = on_attr_change.borrow().as_ref() {
                        f();
                    }
                });
            }
            {
                let on_attr_change = on_attr_change.clone();
                sensitive_btn.connect_toggled(move |_| {
                    if let Some(f) = on_attr_change.borrow().as_ref() {
                        f();
                    }
                });
            }

            row_box.append(&name_entry);
            row_box.append(&value_entry);
            row_box.append(&eye_btn);
            row_box.append(&sensitive_btn);
            row_box.append(&copy_btn);
            row_box.append(&del_btn);
            attrs_rows_box.append(&row_box);

            custom_ui_list.borrow_mut().push(CustomFieldUi {
                id: cf_id,
                name_entry,
                value_entry,
                sensitive_btn,
            });
        })
    };

    for (k, field) in &c.custom_fields {
        add_attr_row_fn(k, &field.value.value, field.value.secret);
    }

    let add_attr_btn = gtk::Button::with_label("+ Add Attribute");
    add_attr_btn.set_halign(gtk::Align::Start);
    add_attr_btn.add_css_class("filter-chip");
    {
        let add_attr_row_fn = add_attr_row_fn.clone();
        add_attr_btn.connect_clicked(move |_| {
            add_attr_row_fn("", "", false);
        });
    }
    attrs_box.append(&add_attr_btn);

    let attrs_container_row = gtk::ListBoxRow::new();
    attrs_container_row.set_activatable(false);
    attrs_container_row.set_selectable(false);
    attrs_container_row.set_child(Some(&attrs_box));
    attrs_exp.add_row(&attrs_container_row);
    list.append(&attrs_exp);

    // Section C: Markdown Notes (Editor + Rendered Preview + [[Card Links]])
    let notes_exp = adw::ExpanderRow::builder()
        .title("Markdown Notes")
        .subtitle(if c.notes_markdown.value.is_empty() {
            "Empty"
        } else {
            "Markdown &amp; [[Card Links]]"
        })
        .expanded(c.kind.value == CardKind::Note)
        .build();

    let notes_container = gtk::Box::new(gtk::Orientation::Vertical, 8);
    notes_container.set_margin_start(12);
    notes_container.set_margin_end(12);
    notes_container.set_margin_top(8);
    notes_container.set_margin_bottom(10);

    let has_notes = !c.notes_markdown.value.trim().is_empty();
    let mode_bar = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let edit_toggle = gtk::ToggleButton::with_label("Edit Markdown");
    edit_toggle.set_active(!has_notes);
    edit_toggle.add_css_class("filter-chip");
    let preview_toggle = gtk::ToggleButton::with_label("Preview");
    preview_toggle.set_group(Some(&edit_toggle));
    preview_toggle.set_active(has_notes);
    preview_toggle.add_css_class("filter-chip");
    mode_bar.append(&edit_toggle);
    mode_bar.append(&preview_toggle);
    notes_container.append(&mode_bar);

    let text_view = gtk::TextView::new();
    text_view.set_wrap_mode(gtk::WrapMode::WordChar);
    text_view.set_monospace(true);
    text_view.set_top_margin(6);
    text_view.set_bottom_margin(6);
    text_view.buffer().set_text(&c.notes_markdown.value);
    text_view.add_css_class("markdown-editor");

    let editor_scroll = gtk::ScrolledWindow::builder()
        .min_content_height(220)
        .max_content_height(460)
        .visible(!has_notes)
        .child(&text_view)
        .build();
    notes_container.append(&editor_scroll);

    let preview_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    preview_box.add_css_class("markdown-preview");
    preview_box.set_visible(has_notes);
    notes_container.append(&preview_box);

    let on_toggle_task: Rc<dyn Fn(usize, bool)> = {
        let text_view = text_view.clone();
        Rc::new(move |idx, checked| {
            let buf = text_view.buffer();
            let current = buf.text(&buf.start_iter(), &buf.end_iter(), false);
            if let Some(updated_md) = toggle_markdown_checkbox(&current, idx, checked) {
                buf.set_text(&updated_md);
            }
        })
    };

    if has_notes {
        render_markdown_into_box(&c.notes_markdown.value, &preview_box, &cb, &on_toggle_task);
    }

    // Clickable [[Card Links]] pills
    let links_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    for target in extract_card_links(&c.notes_markdown.value) {
        let btn = gtk::Button::with_label(&format!("↗ {target}"));
        btn.add_css_class("filter-chip");
        let cb_l = cb.clone();
        btn.connect_clicked(move |_| (cb_l.on_jump_card)(target.clone()));
        links_box.append(&btn);
    }
    if links_box.first_child().is_some() {
        notes_container.append(&links_box);
    }

    {
        let editor_scroll = editor_scroll.clone();
        let preview_box = preview_box.clone();
        let text_view = text_view.clone();
        let cb = cb.clone();
        let on_toggle_task = on_toggle_task.clone();
        preview_toggle.connect_toggled(move |b| {
            if b.is_active() {
                let buf = text_view.buffer();
                let txt = buf.text(&buf.start_iter(), &buf.end_iter(), false);
                render_markdown_into_box(&txt, &preview_box, &cb, &on_toggle_task);
                editor_scroll.set_visible(false);
                preview_box.set_visible(true);
            } else {
                editor_scroll.set_visible(true);
                preview_box.set_visible(false);
            }
        });
    }

    let notes_row = gtk::ListBoxRow::new();
    notes_row.set_activatable(false);
    notes_row.set_selectable(false);
    notes_row.set_child(Some(&notes_container));
    notes_exp.add_row(&notes_row);
    list.append(&notes_exp);

    // Section D: Revision History & Provenance
    let hist_count = c.total_revisions();
    let hist_exp = adw::ExpanderRow::builder()
        .title("Field History &amp; Ed25519 Provenance")
        .subtitle(format!("{hist_count} recorded field revisions"))
        .build();
    if hist_count == 0 {
        let empty = adw::ActionRow::builder()
            .title("No field revisions yet")
            .subtitle("Edits and CRDT merge conflicts are logged per field")
            .build();
        hist_exp.add_row(&empty);
    } else {
        for rev in &c.password.history {
            let r = adw::ActionRow::builder()
                .title("Password changed")
                .subtitle(glib::markup_escape_text(&format!(
                    "By {} · {}",
                    rev.author_device,
                    fmt_time_ago(rev.hlc.unix_ms)
                )))
                .build();
            hist_exp.add_row(&r);
        }
        for rev in &c.notes_markdown.history {
            let r = adw::ActionRow::builder()
                .title("Notes updated")
                .subtitle(glib::markup_escape_text(&format!(
                    "By {} · {}",
                    rev.author_device,
                    fmt_time_ago(rev.hlc.unix_ms)
                )))
                .build();
            hist_exp.add_row(&r);
        }
        for rev in &c.title.history {
            let r = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&format!(
                    "Title was \"{}\"",
                    rev.value
                )))
                .subtitle(glib::markup_escape_text(&format!(
                    "By {} · {}",
                    rev.author_device,
                    fmt_time_ago(rev.hlc.unix_ms)
                )))
                .build();
            hist_exp.add_row(&r);
        }
    }
    list.append(&hist_exp);

    // Save button row at bottom of card
    let save_bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    save_bar.set_halign(gtk::Align::End);
    let save_btn = gtk::Button::with_label("Apply & Save Card");
    save_btn.add_css_class("suggested-action");
    save_bar.append(&save_btn);
    details.append(&save_bar);

    let apply_and_save: Rc<dyn Fn(bool)> = {
        let card_rc = card_rc.clone();
        let cb = cb.clone();
        let title_row = title_row.clone();
        let user_row = user_row.clone();
        let pw_row = pw_row.clone();
        let email_row = email_row.clone();
        let url_row = url_row.clone();
        let folder_row = folder_row.clone();
        let tags_row = tags_row.clone();
        let fav_btn = fav_btn.clone();
        let text_view = text_view.clone();
        let custom_ui_list = custom_ui_list.clone();
        let header_title_lbl = header_title_lbl.clone();
        let header_sub_lbl = header_sub_lbl.clone();

        Rc::new(move |explicit: bool| {
            let mut updated = card_rc.borrow().clone();
            let dev_id = updated.title.hlc.device_id;
            let dev_name = updated.title.author_device.clone();

            updated
                .title
                .set(title_row.text().to_string(), dev_id, &dev_name, 16);
            if updated.kind.value == CardKind::Login {
                updated
                    .username
                    .set(user_row.text().to_string(), dev_id, &dev_name, 16);
                updated
                    .password
                    .set(pw_row.text().to_string(), dev_id, &dev_name, 16);
                updated
                    .email
                    .set(email_row.text().to_string(), dev_id, &dev_name, 16);
                updated
                    .url
                    .set(url_row.text().to_string(), dev_id, &dev_name, 16);
            }
            updated
                .folder
                .set(folder_row.text().to_string(), dev_id, &dev_name, 16);
            let tags: Vec<String> = tags_row
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            updated.tags.set(tags, dev_id, &dev_name, 16);
            updated
                .favorite
                .set(fav_btn.is_active(), dev_id, &dev_name, 16);

            let buf = text_view.buffer();
            let md = buf.text(&buf.start_iter(), &buf.end_iter(), false).to_string();
            updated.notes_markdown.set(md, dev_id, &dev_name, 16);

            let mut new_custom = std::collections::BTreeMap::new();
            for item in custom_ui_list.borrow().iter() {
                let k = item.name_entry.text().trim().to_string();
                if k.is_empty() {
                    continue;
                }
                let val = CustomFieldValue {
                    value: item.value_entry.text().to_string(),
                    secret: item.sensitive_btn.is_active(),
                };
                if let Some(mut existing) = updated.custom_fields.remove(&k) {
                    existing.set(val, dev_id, &dev_name, 16);
                    new_custom.insert(k, existing);
                } else {
                    new_custom.insert(
                        k,
                        LwwField::new(val, Hlc::now(dev_id), &dev_name),
                    );
                }
            }
            updated.custom_fields = new_custom;

            header_title_lbl.set_text(&card_title_text(&updated));
            header_sub_lbl.set_text(&card_subtitle_text(&updated));
            *card_rc.borrow_mut() = updated.clone();
            if explicit {
                (cb.on_save_card)(updated);
            } else {
                (cb.on_auto_save)(updated);
            }
        })
    };

    {
        let f = apply_and_save.clone();
        *on_attr_change.borrow_mut() = Some(Rc::new(move || f(false)));
    }

    for entry in [&title_row, &user_row, &email_row, &url_row, &folder_row, &tags_row] {
        let f = apply_and_save.clone();
        entry.connect_changed(move |_| f(false));
    }
    {
        let f = apply_and_save.clone();
        pw_row.connect_changed(move |_| f(false));
    }
    {
        let f = apply_and_save.clone();
        fav_btn.connect_toggled(move |b| {
            b.set_label(if b.is_active() { "Favorited" } else { "Favorite" });
            f(false);
        });
    }
    {
        let f = apply_and_save.clone();
        text_view.buffer().connect_changed(move |_| f(false));
    }
    {
        let f = apply_and_save.clone();
        save_btn.connect_clicked(move |_| f(true));
    }

    (details, title_row)
}

#[cfg(test)]
mod tests {
    use super::toggle_markdown_checkbox;

    #[test]
    fn toggle_markdown_checkbox_updates_target_item() {
        let md = "- [ ] First\n- [x] Second\n  - [ ] Nested\n";
        let checked_first = toggle_markdown_checkbox(md, 0, true).unwrap();
        assert_eq!(checked_first, "- [x] First\n- [x] Second\n  - [ ] Nested\n");

        let unchecked_second = toggle_markdown_checkbox(&checked_first, 1, false).unwrap();
        assert_eq!(unchecked_second, "- [x] First\n- [ ] Second\n  - [ ] Nested\n");

        let checked_nested = toggle_markdown_checkbox(&unchecked_second, 2, true).unwrap();
        assert_eq!(checked_nested, "- [x] First\n- [ ] Second\n  - [x] Nested\n");

        assert!(toggle_markdown_checkbox(md, 9, true).is_none());
    }
}
