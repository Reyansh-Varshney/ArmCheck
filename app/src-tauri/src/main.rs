#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icons;

use std::{collections::HashMap, path::PathBuf, sync::Mutex};

use armcheck_core::{
    file_check::check_file,
    model::{App, FileCheck, GroupingEvidence},
    scan::scan_running_while,
};
use serde::Serialize;
use tauri::{
    AppHandle, Emitter, Manager, WebviewWindow, WindowEvent, async_runtime, menu::MenuBuilder,
    tray::TrayIconBuilder,
};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct Desktop {
    icons: Mutex<HashMap<PathBuf, Option<String>>>,
}

#[derive(Serialize)]
struct AppRow {
    #[serde(flatten)]
    app: App,
    icon: Option<String>,
}

#[derive(Serialize)]
struct CheckedFile {
    name: String,
    finding: Result<FileCheck, String>,
}

fn can_scan(window: &WebviewWindow) -> bool {
    window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(true)
}

#[tauri::command]
async fn scan_apps(window: WebviewWindow) -> Result<Option<Vec<AppRow>>, String> {
    async_runtime::spawn_blocking(move || {
        let desktop = window.state::<Desktop>();
        // Keep the lock through sampling and icon lookup so requests cannot overlap.
        let Ok(mut cache) = desktop.icons.try_lock() else {
            return Ok(None);
        };
        let Some(apps) =
            scan_running_while(|| can_scan(&window)).map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        if cache.len() > 512 {
            cache.clear();
        }
        let rows = apps
            .into_iter()
            .map(|app| {
                let icon = match &app.grouping {
                    Some(GroupingEvidence::ExecutablePath { path }) => {
                        cached_icon(&mut cache, path)
                    }
                    Some(GroupingEvidence::ProductVersion { .. }) => app
                        .processes
                        .iter()
                        .filter_map(|process| process.image_path.as_ref())
                        .find_map(|path| cached_icon(&mut cache, path)),
                    None => None,
                };
                AppRow { app, icon }
            })
            .collect();
        Ok(Some(rows))
    })
    .await
    .map_err(|error| error.to_string())?
}

fn cached_icon(
    cache: &mut HashMap<PathBuf, Option<String>>,
    path: &std::path::Path,
) -> Option<String> {
    cache
        .entry(path.to_owned())
        .or_insert_with(|| icons::executable_icon(path))
        .clone()
}

fn inspect(path: PathBuf) -> CheckedFile {
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let finding = check_file(&path).map_err(|error| error.to_string());
    CheckedFile { name, finding }
}

#[tauri::command]
async fn check_path(path: PathBuf) -> Result<CheckedFile, String> {
    async_runtime::spawn_blocking(move || inspect(path))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn choose_file(window: WebviewWindow) -> Result<Option<CheckedFile>, String> {
    async_runtime::spawn_blocking(move || {
        let picked = window
            .dialog()
            .file()
            .set_parent(&window)
            .add_filter("Windows binaries", &["exe", "dll", "msi"])
            .add_filter("All files", &["*"])
            .blocking_pick_file();
        picked
            .map(|path| {
                path.into_path()
                    .map(inspect)
                    .map_err(|error| error.to_string())
            })
            .transpose()
    })
    .await
    .map_err(|error| error.to_string())?
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        let _ = window.emit("armcheck://visibility", ());
    }
}

fn main() -> tauri::Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Desktop::default())
        .setup(|app| {
            let menu = MenuBuilder::new(app)
                .text("show", "Show ArmCheck")
                .text("hide", "Hide to tray")
                .separator()
                .text("quit", "Quit ArmCheck")
                .build()?;
            let mut tray = TrayIconBuilder::with_id("armcheck")
                .menu(&menu)
                .tooltip("ArmCheck");
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.on_menu_event(|app, event| match event.id().as_ref() {
                "show" => show_main(app),
                "hide" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                        let _ = window.emit("armcheck://visibility", ());
                    }
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
                let _ = window.emit("armcheck://visibility", ());
            }
            WindowEvent::Focused(_) => {
                let _ = window.emit("armcheck://visibility", ());
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![scan_apps, check_path, choose_file])
        .run(tauri::generate_context!())
}
