// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;
mod blobs;
mod ctap;
mod fido;
mod hsm;
mod migrate;
mod firmware;
mod oath;
mod otp;
mod pgp;
mod pico;
mod recovery;
mod ssh;

use std::sync::Mutex;
use types::{AgentStatus, Board, FidoPolicy, LargeBlobs, LegacyKey, GitSetup, GitSigning, NewSshKey, SshEnv, SshKey, Device, FlashProgress, FwRelease, FidoInfo, NewOath, NewOtp, OathAccount, OtpSlot, Passkey, Phy, PicoInfo};

/// One device conversation at a time: Pico firmware wedges if HID (CTAP) and
/// CCID (rescue) requests overlap.
// ponytail: one global lock for all keys; per-device locks if multi-key use needs parallelism.
pub(crate) static DEVICE: Mutex<()> = Mutex::new(());

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
async fn fido_policy(path: String, pin: String, change: FidoPolicy) -> Result<(), String> {
    blocking(move || {
        let (p, n) = (path.as_str(), pin.as_str());
        match change {
            FidoPolicy::AlwaysUv => ctap::toggle_always_uv(p, n),
            FidoPolicy::EnterpriseAttestation => ctap::enable_enterprise_attestation(p, n),
            FidoPolicy::MinPin { len, rp_ids, force_change } => ctap::set_min_pin(p, n, len, &rp_ids, force_change),
            FidoPolicy::Toggle { which } => ctap::toggle(p, n, &which),
            FidoPolicy::PinComplexity { bits } => ctap::pin_policy(p, n, bits),
            FidoPolicy::Revoke { cred_id } => ctap::revoke(p, n, &cred_id),
            FidoPolicy::Expire { cred_id, unix } => ctap::expire(p, n, &cred_id, unix),
            FidoPolicy::Touch { cred_id, required } => ctap::button(p, n, &cred_id, required),
        }
    })
    .await
}

#[tauri::command]
async fn large_blobs(path: String, pin: String) -> Result<LargeBlobs, String> {
    blocking(move || blobs::list(&path, &pin)).await
}

#[tauri::command]
async fn large_blob_delete(path: String, pin: String, index: u32) -> Result<(), String> {
    blocking(move || blobs::delete(&path, &pin, index)).await
}

#[tauri::command]
async fn agent_status() -> Result<AgentStatus, String> {
    agent::status()
}

/// Start (with an optional PIN for keys that need it) or stop the built-in ssh-agent.
#[tauri::command]
async fn agent_set(running: bool, pin: Option<String>) -> Result<AgentStatus, String> {
    if running {
        agent::set_pin(pin);
        agent::start()?;
    } else {
        agent::stop()?;
        agent::set_pin(None);
    }
    agent::status()
}

#[tauri::command]
async fn recovery_files() -> Result<Vec<types::RecoveryFile>, String> {
    recovery::files()
}

/// Opens a "Save as" dialog and copies the file there. `understood` is the user's explicit
/// acknowledgement in the UI; the backend refuses without it. Ok(None) = cancelled.
#[tauri::command]
async fn recovery_export(app: tauri::AppHandle, path: String, understood: bool) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    if !understood {
        return Err("Confirm that you understand what this file is first.".into());
    }
    let name = std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let dest = tauri::async_runtime::spawn_blocking(move || app.dialog().file().set_file_name(name).blocking_save_file())
        .await
        .map_err(|e| e.to_string())?;
    let Some(dest) = dest.and_then(|d| d.into_path().ok()) else { return Ok(None) };
    recovery::export(&path, &dest)?;
    Ok(Some(dest.display().to_string()))
}

#[tauri::command]
async fn pgp_status() -> Result<types::PgpStatus, String> {
    blocking(pgp::status).await
}

#[tauri::command]
async fn pgp_change_pin(admin: bool, old: String, new: String) -> Result<(), String> {
    blocking(move || pgp::change_pin(admin, &old, &new)).await
}

#[tauri::command]
async fn pgp_reset_pin(admin_pin: String, new: String) -> Result<(), String> {
    blocking(move || pgp::reset_pin(&admin_pin, &new)).await
}

#[tauri::command]
async fn pgp_set_cardholder(admin_pin: String, name: String, url: String) -> Result<(), String> {
    blocking(move || pgp::set_cardholder(&admin_pin, &name, &url)).await
}

#[tauri::command]
async fn pgp_factory_reset(admin_pin: Option<String>, confirm: String) -> Result<(), String> {
    if confirm != "RESET OPENPGP" {
        return Err("Confirmation phrase didn't match.".into());
    }
    blocking(move || pgp::factory_reset(admin_pin.as_deref())).await
}

#[tauri::command]
async fn hsm_status() -> Result<types::HsmStatus, String> {
    blocking(hsm::status).await
}

#[tauri::command]
async fn hsm_change_pin(so: bool, old: String, new: String) -> Result<(), String> {
    blocking(move || hsm::change_pin(so, &old, &new)).await
}

#[tauri::command]
async fn hsm_unblock(so_pin: String, new: String) -> Result<(), String> {
    blocking(move || hsm::unblock(&so_pin, &new)).await
}

#[tauri::command]
async fn hsm_initialize(pin: String, so_pin: String, retries: u8, confirm: String) -> Result<(), String> {
    blocking(move || {
        // Re-initializing erases keys: then the typed phrase is required. First-time setup isn't.
        if confirm != "ERASE HSM" && hsm::status()?.initialized {
            return Err("Confirmation phrase didn't match.".into());
        }
        hsm::initialize(&pin, &so_pin, retries)
    })
    .await
}

#[tauri::command]
async fn hsm_delete_key(pin: String, id: u8) -> Result<(), String> {
    blocking(move || hsm::delete_key(&pin, id)).await
}

#[tauri::command]
async fn pico_time() -> Result<Option<u32>, String> {
    blocking(pico::get_time).await
}

#[tauri::command]
async fn pico_sync_time() -> Result<(), String> {
    blocking(pico::set_time).await
}

/// Saves an export into ~/Downloads without overwriting; returns the path.
#[tauri::command]
async fn save_text(name: String, content: String) -> Result<String, String> {
    let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).collect();
    let (stem, ext) = name.rsplit_once('.').unwrap_or((&name, "txt"));
    let dir = ssh::home()?.join("Downloads");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut path = dir.join(format!("{stem}.{ext}"));
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("{stem}-{n}.{ext}"));
        n += 1;
    }
    std::fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
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
async fn oath_unlock(password: String) -> Result<(), String> {
    blocking(move || oath::unlock(&password)).await
}

#[tauri::command]
async fn oath_lock() {
    oath::lock()
}

#[tauri::command]
async fn oath_protected() -> Result<bool, String> {
    blocking(oath::protected).await
}

#[tauri::command]
async fn oath_set_password(password: Option<String>) -> Result<(), String> {
    blocking(move || oath::set_password(password.as_deref())).await
}

#[tauri::command]
async fn oath_rename(old: String, new: String) -> Result<(), String> {
    blocking(move || oath::rename(&old, &new)).await
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

#[tauri::command]
async fn fw_releases(product: String) -> Result<Vec<FwRelease>, String> {
    tauri::async_runtime::spawn_blocking(move || firmware::releases(&product)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fw_flash(app: tauri::AppHandle, url: String, board: Board) -> Result<(), String> {
    use tauri::Emitter;
    blocking(move || firmware::flash(&url, board, &mut |p: FlashProgress| {
        let _ = app.emit("flash-progress", p);
    }))
    .await
}

#[tauri::command]
async fn ssh_env() -> Result<SshEnv, String> {
    tauri::async_runtime::spawn_blocking(ssh::env).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_install_openssh() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(ssh::install_openssh).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_keys() -> Result<Vec<SshKey>, String> {
    tauri::async_runtime::spawn_blocking(ssh::keys).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_generate(key: NewSshKey) -> Result<SshKey, String> {
    blocking(move || ssh::generate(&key)).await
}

#[tauri::command]
async fn ssh_recover(pin: Option<String>) -> Result<Vec<SshKey>, String> {
    blocking(move || ssh::recover(pin.as_deref())).await
}

#[tauri::command]
async fn ssh_git_setup(setup: GitSetup) -> Result<GitSigning, String> {
    tauri::async_runtime::spawn_blocking(move || ssh::setup_git(&setup)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_add_host(host: String, key: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || ssh::add_host(&host, &key)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_test(host: String, key: String, pin: Option<String>) -> Result<String, String> {
    blocking(move || ssh::test(&host, &key, pin.as_deref())).await
}

#[tauri::command]
async fn ssh_inventory() -> Result<Vec<LegacyKey>, String> {
    tauri::async_runtime::spawn_blocking(migrate::inventory).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_authorize(host: String, key: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || migrate::authorize(&host, &key)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_check(host: String, key: String, pin: Option<String>) -> Result<String, String> {
    blocking(move || migrate::check(&host, &key, pin.as_deref())).await
}

#[tauri::command]
async fn ssh_switch_config(old: String, key: String) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || migrate::switch_config(&old, &key)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn ssh_archive(old: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || migrate::archive(&old)).await.map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            list_devices, fido_info, set_pin, change_pin, list_passkeys, delete_passkey, wink,
            pico_info, write_phy, fido_reset,
            fido_policy,
            pico_time,
            hsm_status,
            hsm_change_pin,
            hsm_unblock,
            hsm_initialize,
            hsm_delete_key,
            pgp_status,
            pgp_change_pin,
            pgp_reset_pin,
            pgp_set_cardholder,
            pgp_factory_reset,
            recovery_files,
            recovery_export,
            agent_status,
            agent_set,
            pico_sync_time,
            save_text,
            large_blobs,
            large_blob_delete, oath_list, oath_calculate, oath_add, oath_delete,
            oath_unlock, oath_lock, oath_protected, oath_set_password, oath_rename,
            otp_status, otp_configure, otp_delete, otp_swap, random_hex, fw_releases, fw_flash,
            ssh_env, ssh_install_openssh, ssh_keys, ssh_generate, ssh_recover, ssh_git_setup, ssh_add_host, ssh_test,
            ssh_inventory, ssh_authorize, ssh_check, ssh_switch_config, ssh_archive
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
