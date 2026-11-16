// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod fido;
mod oath;
mod otp;
mod pico;

use std::sync::Mutex;
use types::{Device, FidoInfo, NewOath, NewOtp, OathAccount, OtpSlot, Passkey, Phy, PicoInfo};

/// One device conversation at a time: Pico firmware wedges if HID (CTAP) and
/// CCID (rescue) requests overlap.
// ponytail: one global lock for all keys; per-device locks if multi-key use needs parallelism.
static DEVICE: Mutex<()> = Mutex::new(());

/// Device I/O blocks (and may wait for touch), so keep it off the UI/async threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = DEVICE.lock().unwrap_or_else(|p| p.into_inner());
        f()
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_devices() -> Result<Vec<Device>, String> {
    // enumeration only, never opens the device: no lock needed
    tauri::async_runtime::spawn_blocking(fido::list_devices).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn fido_info(path: String) -> Result<FidoInfo, String> {
    blocking(move || fido::info(&path)).await
}

#[tauri::command]
async fn set_pin(path: String, new_pin: String) -> Result<(), String> {
    blocking(move || fido::set_pin(&path, &new_pin)).await
}

#[tauri::command]
async fn change_pin(path: String, current: String, new_pin: String) -> Result<(), String> {
    blocking(move || fido::change_pin(&path, &current, &new_pin)).await
}

#[tauri::command]
async fn list_passkeys(path: String, pin: String) -> Result<Vec<Passkey>, String> {
    blocking(move || fido::passkeys(&path, &pin)).await
}

#[tauri::command]
async fn delete_passkey(path: String, pin: String, cred_id: String) -> Result<(), String> {
    blocking(move || fido::delete_passkey(&path, &pin, &cred_id)).await
}

#[tauri::command]
async fn wink(path: String) -> Result<(), String> {
    blocking(move || fido::wink(&path)).await
}

#[tauri::command]
async fn pico_info() -> Result<PicoInfo, String> {
    blocking(pico::info).await
}

#[tauri::command]
async fn write_phy(phy: Phy) -> Result<(), String> {
    blocking(move || pico::write_phy(&phy)).await
}

#[tauri::command]
async fn fido_reset(path: String) -> Result<(), String> {
    blocking(move || pico::fido_reset(&path)).await
}

#[tauri::command]
async fn oath_list() -> Result<Vec<OathAccount>, String> {
    blocking(oath::list).await
}

#[tauri::command]
async fn oath_calculate(name: String) -> Result<String, String> {
    blocking(move || oath::calculate(&name)).await
}

#[tauri::command]
async fn oath_add(account: NewOath) -> Result<(), String> {
    blocking(move || oath::add(&account)).await
}

#[tauri::command]
async fn oath_delete(name: String) -> Result<(), String> {
    blocking(move || oath::delete(&name)).await
}

#[tauri::command]
async fn otp_status() -> Result<Vec<OtpSlot>, String> {
    blocking(otp::status).await
}

#[tauri::command]
async fn otp_configure(slot: u8, config: NewOtp) -> Result<(), String> {
    blocking(move || otp::configure(slot, &config)).await
}

#[tauri::command]
async fn otp_delete(slot: u8) -> Result<(), String> {
    blocking(move || otp::delete(slot)).await
}

#[tauri::command]
async fn otp_swap() -> Result<(), String> {
    blocking(otp::swap).await
}

#[tauri::command]
fn random_hex(bytes: usize) -> Result<String, String> {
    otp::random_hex(bytes)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_devices, fido_info, set_pin, change_pin, list_passkeys, delete_passkey, wink,
            pico_info, write_phy, fido_reset, oath_list, oath_calculate, oath_add, oath_delete,
            otp_status, otp_configure, otp_delete, otp_swap, random_hex
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
