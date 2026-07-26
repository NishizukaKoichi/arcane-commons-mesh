#![forbid(unsafe_code)]

use serde::Serialize;
use tauri::Manager;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopStatus {
    protocol_version: u16,
    chunk_size_bytes: usize,
    secret_store: &'static str,
}

#[tauri::command]
fn desktop_status() -> DesktopStatus {
    DesktopStatus {
        protocol_version: arcane_mesh_core::PROTOCOL_VERSION,
        chunk_size_bytes: arcane_mesh_core::DEFAULT_CHUNK_SIZE,
        secret_store: "stronghold",
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let salt_path = app
                .path()
                .app_local_data_dir()
                .expect("could not resolve app local data path")
                .join("stronghold-salt");
            app.handle()
                .plugin(tauri_plugin_stronghold::Builder::with_argon2(&salt_path).build())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![desktop_status])
        .run(tauri::generate_context!())
        .expect("error while running Arcane Commons Mesh");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_reports_shared_core_and_stronghold() {
        let status = desktop_status();
        assert_eq!(status.protocol_version, 1);
        assert_eq!(status.chunk_size_bytes, 4 * 1024 * 1024);
        assert_eq!(status.secret_store, "stronghold");
    }
}
