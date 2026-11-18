mod card_row;
mod cli;
mod donate;
mod merge_dialog;
mod password_gen_widget;
mod window;

use adw::prelude::*;
use clap::Parser;
use gtk::gdk;

const APP_CSS: &str = include_str!("style.css");

fn main() {
    let parsed = cli::Cli::parse();
    if let Some(cmd) = parsed.cmd {
        if let Err(err) = cli::run(cmd) {
            eprintln!("Error: {err:#}");
            std::process::exit(1);
        }
        return;
    }

    let app = adw::Application::builder()
        .application_id("io.github.woosah.CipherDeck")
        .build();

    app.connect_startup(|_| {
        let provider = gtk::CssProvider::new();
        provider.load_from_string(APP_CSS);
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
            let icon_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/icons");
            if std::path::Path::new(icon_dir).exists() {
                gtk::IconTheme::for_display(&display).add_search_path(icon_dir);
            }
        }
        gtk::Window::set_default_icon_name("io.github.woosah.CipherDeck");
    });

    app.connect_activate(|app| {
        let win = window::build_main_window(app);
        win.present();
    });

    app.run();
}
