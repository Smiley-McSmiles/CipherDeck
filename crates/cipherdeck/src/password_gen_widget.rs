use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use vault_core::{generate_password, GeneratorMode, PasswordGenConfig, StrengthLevel};

pub fn build_password_generator_box<F>(on_apply: F) -> gtk::Box
where
    F: Fn(&str) + 'static,
{
    let cfg = Rc::new(RefCell::new(PasswordGenConfig::default()));
    let current_pw = Rc::new(RefCell::new(String::new()));
    let on_apply = Rc::new(on_apply);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root.set_margin_top(6);
    root.set_margin_bottom(6);

    // Top row: mode toggle + preview + regenerate + apply
    let top_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let mode_random = gtk::ToggleButton::with_label("Random");
    mode_random.set_active(true);
    mode_random.add_css_class("filter-chip");
    let mode_phrase = gtk::ToggleButton::with_label("Passphrase");
    mode_phrase.set_group(Some(&mode_random));
    mode_phrase.add_css_class("filter-chip");
    top_row.append(&mode_random);
    top_row.append(&mode_phrase);

    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    top_row.append(&spacer);

    let regen_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
    regen_btn.set_tooltip_text(Some("Generate new password"));
    regen_btn.add_css_class("flat");
    top_row.append(&regen_btn);

    let apply_btn = gtk::Button::with_label("Use Password");
    apply_btn.add_css_class("suggested-action");
    top_row.append(&apply_btn);
    root.append(&top_row);

    // Preview & entropy meter
    let preview_lbl = gtk::Label::new(None);
    preview_lbl.set_xalign(0.0);
    preview_lbl.set_selectable(true);
    preview_lbl.set_wrap(true);
    preview_lbl.set_wrap_mode(gtk::pango::WrapMode::Char);
    preview_lbl.add_css_class("gen-preview");
    root.append(&preview_lbl);

    let meter_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let level_bar = gtk::LevelBar::for_interval(0.0, 140.0);
    level_bar.set_hexpand(true);
    level_bar.set_valign(gtk::Align::Center);
    let entropy_lbl = gtk::Label::new(None);
    entropy_lbl.add_css_class("caption");
    entropy_lbl.add_css_class("dim-label");
    entropy_lbl.add_css_class("numeric");
    meter_row.append(&level_bar);
    meter_row.append(&entropy_lbl);
    root.append(&meter_row);

    // Random-mode controls
    let random_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let len_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let len_title = gtk::Label::new(Some("Length"));
    len_title.set_xalign(0.0);
    let len_scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, 8.0, 64.0, 1.0);
    len_scale.set_value(20.0);
    len_scale.set_hexpand(true);
    let len_spin = gtk::SpinButton::with_range(8.0, 128.0, 1.0);
    len_spin.set_value(20.0);
    len_row.append(&len_title);
    len_row.append(&len_scale);
    len_row.append(&len_spin);
    random_box.append(&len_row);

    let toggles_flow = gtk::FlowBox::new();
    toggles_flow.set_selection_mode(gtk::SelectionMode::None);
    toggles_flow.set_row_spacing(6);
    toggles_flow.set_column_spacing(6);

    let make_chip = |label: &str, active: bool| -> gtk::ToggleButton {
        let b = gtk::ToggleButton::with_label(label);
        b.set_active(active);
        b.add_css_class("filter-chip");
        b
    };

    let chk_upper = make_chip("A–Z Capitals", true);
    let chk_lower = make_chip("a–z Lowercase", true);
    let chk_digits = make_chip("0–9 Digits", true);
    let chk_symbols = make_chip("!@# Symbols", true);
    let chk_no_amb = make_chip("No Ambiguous (0O1lI)", false);

    for w in [&chk_upper, &chk_lower, &chk_digits, &chk_symbols, &chk_no_amb] {
        toggles_flow.insert(w, -1);
    }
    random_box.append(&toggles_flow);
    root.append(&random_box);

    // Passphrase-mode controls
    let phrase_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    phrase_box.set_visible(false);

    let words_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let words_lbl = gtk::Label::new(Some("Words"));
    let words_spin = gtk::SpinButton::with_range(3.0, 10.0, 1.0);
    words_spin.set_value(5.0);
    let sep_lbl = gtk::Label::new(Some("Separator"));
    let sep_drop = gtk::DropDown::from_strings(&["-", "_", ".", " "]);
    words_row.append(&words_lbl);
    words_row.append(&words_spin);
    words_row.append(&sep_lbl);
    words_row.append(&sep_drop);
    phrase_box.append(&words_row);

    let phrase_toggles = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let chk_cap = make_chip("Capitalize Words", true);
    let chk_num = make_chip("Append Number", true);
    phrase_toggles.append(&chk_cap);
    phrase_toggles.append(&chk_num);
    phrase_box.append(&phrase_toggles);
    root.append(&phrase_box);

    let refresh = {
        let cfg = cfg.clone();
        let current_pw = current_pw.clone();
        let preview_lbl = preview_lbl.clone();
        let level_bar = level_bar.clone();
        let entropy_lbl = entropy_lbl.clone();
        Rc::new(move || {
            let gen = generate_password(&cfg.borrow());
            let pw_str = gen.password.as_str().to_string();
            preview_lbl.set_text(&pw_str);
            *current_pw.borrow_mut() = pw_str;
            level_bar.set_value(gen.entropy_bits.min(140.0));
            let badge = match gen.strength {
                StrengthLevel::Weak => "Weak",
                StrengthLevel::Fair => "Fair",
                StrengthLevel::Good => "Good",
                StrengthLevel::Strong => "Strong",
                StrengthLevel::VeryStrong => "Very Strong",
            };
            entropy_lbl.set_text(&format!("{:.0} bits · {badge}", gen.entropy_bits));
        })
    };

    refresh();

    // Wire mode switches
    {
        let cfg = cfg.clone();
        let random_box = random_box.clone();
        let phrase_box = phrase_box.clone();
        let refresh = refresh.clone();
        mode_random.connect_toggled(move |b| {
            if b.is_active() {
                cfg.borrow_mut().mode = GeneratorMode::RandomChars;
                random_box.set_visible(true);
                phrase_box.set_visible(false);
                refresh();
            }
        });
    }
    {
        let cfg = cfg.clone();
        let random_box = random_box.clone();
        let phrase_box = phrase_box.clone();
        let refresh = refresh.clone();
        mode_phrase.connect_toggled(move |b| {
            if b.is_active() {
                cfg.borrow_mut().mode = GeneratorMode::Passphrase;
                random_box.set_visible(false);
                phrase_box.set_visible(true);
                refresh();
            }
        });
    }

    // Sync slider & spinbutton
    let syncing = Rc::new(RefCell::new(false));
    {
        let cfg = cfg.clone();
        let len_spin = len_spin.clone();
        let syncing = syncing.clone();
        let refresh = refresh.clone();
        len_scale.connect_value_changed(move |s| {
            if *syncing.borrow() {
                return;
            }
            *syncing.borrow_mut() = true;
            let v = s.value().round();
            len_spin.set_value(v);
            cfg.borrow_mut().length = v as usize;
            *syncing.borrow_mut() = false;
            refresh();
        });
    }
    {
        let cfg = cfg.clone();
        let len_scale = len_scale.clone();
        let syncing = syncing.clone();
        let refresh = refresh.clone();
        len_spin.connect_value_changed(move |s| {
            if *syncing.borrow() {
                return;
            }
            *syncing.borrow_mut() = true;
            let v = s.value().round();
            if v <= 64.0 {
                len_scale.set_value(v);
            }
            cfg.borrow_mut().length = v as usize;
            *syncing.borrow_mut() = false;
            refresh();
        });
    }

    // Random toggles
    let bind_toggle = |btn: &gtk::ToggleButton, setter: fn(&mut PasswordGenConfig, bool)| {
        let cfg = cfg.clone();
        let refresh = refresh.clone();
        btn.connect_toggled(move |b| {
            setter(&mut cfg.borrow_mut(), b.is_active());
            refresh();
        });
    };
    bind_toggle(&chk_upper, |c, v| c.uppercase = v);
    bind_toggle(&chk_lower, |c, v| c.lowercase = v);
    bind_toggle(&chk_digits, |c, v| c.digits = v);
    bind_toggle(&chk_symbols, |c, v| c.symbols = v);
    bind_toggle(&chk_no_amb, |c, v| c.exclude_ambiguous = v);
    bind_toggle(&chk_cap, |c, v| c.capitalize_words = v);
    bind_toggle(&chk_num, |c, v| c.append_number = v);

    {
        let cfg = cfg.clone();
        let refresh = refresh.clone();
        words_spin.connect_value_changed(move |s| {
            cfg.borrow_mut().word_count = s.value() as usize;
            refresh();
        });
    }
    {
        let cfg = cfg.clone();
        let refresh = refresh.clone();
        sep_drop.connect_selected_notify(move |d| {
            let seps = ["-", "_", ".", " "];
            let idx = d.selected() as usize;
            cfg.borrow_mut().separator = seps.get(idx).copied().unwrap_or("-").to_string();
            refresh();
        });
    }

    {
        let refresh = refresh.clone();
        regen_btn.connect_clicked(move |_| refresh());
    }
    {
        let current_pw = current_pw.clone();
        let on_apply = on_apply.clone();
        apply_btn.connect_clicked(move |_| {
            on_apply(&current_pw.borrow());
        });
    }

    root
}
