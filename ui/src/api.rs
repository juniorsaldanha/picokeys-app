//! Typed bridge to the Tauri backend (`window.__TAURI__.core.invoke`).
use serde::{Serialize, de::DeserializeOwned};
use types::{Device, FidoInfo, Passkey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

async fn call<A: Serialize, T: DeserializeOwned>(cmd: &str, args: A) -> Result<T, String> {
    let args = serde_wasm_bindgen::to_value(&args).map_err(|e| e.to_string())?;
    let v = tauri_invoke(cmd, args)
        .await
        .map_err(|e| e.as_string().unwrap_or_else(|| "backend unavailable".into()))?;
    serde_wasm_bindgen::from_value(v).map_err(|e| e.to_string())
}

/// Set when a risky action hit the app admin lock; the root shows the unlock dialog.
pub static ADMIN_PROMPT: dioxus::prelude::GlobalSignal<bool> = dioxus::prelude::Signal::global(|| false);

/// `call` for commands the admin lock can refuse.
async fn guarded<A: Serialize, T: DeserializeOwned>(cmd: &str, args: A) -> Result<T, String> {
    match call(cmd, args).await {
        Err(e) if e == "ADMIN_LOCKED" => {
            *ADMIN_PROMPT.write() = true;
            Err("Needs the admin passphrase. Unlock in the dialog, then try again.".into())
        }
        r => r,
    }
}

// Tauri maps snake_case Rust args to camelCase JS keys.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Args<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_pin: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_id: Option<&'a str>,
}

const NONE: Args<'static> = Args { path: None, pin: None, current: None, new_pin: None, cred_id: None };

pub async fn list_devices() -> Result<Vec<Device>, String> {
    call("list_devices", NONE).await
}
pub async fn fido_info(path: &str) -> Result<FidoInfo, String> {
    call("fido_info", Args { path: Some(path), ..NONE }).await
}
pub async fn set_pin(path: &str, new_pin: &str) -> Result<(), String> {
    call("set_pin", Args { path: Some(path), new_pin: Some(new_pin), ..NONE }).await
}
pub async fn change_pin(path: &str, current: &str, new_pin: &str) -> Result<(), String> {
    call("change_pin", Args { path: Some(path), current: Some(current), new_pin: Some(new_pin), ..NONE }).await
}
pub async fn list_passkeys(path: &str, pin: &str) -> Result<Vec<Passkey>, String> {
    call("list_passkeys", Args { path: Some(path), pin: Some(pin), ..NONE }).await
}
pub async fn delete_passkey(path: &str, pin: &str, cred_id: &str) -> Result<(), String> {
    guarded("delete_passkey", Args { path: Some(path), pin: Some(pin), cred_id: Some(cred_id), ..NONE }).await
}
pub async fn wink(path: &str) -> Result<(), String> {
    call("wink", Args { path: Some(path), ..NONE }).await
}

/// Promise-based sleep, so polling doesn't need an extra timer crate.
pub async fn sleep_ms(ms: i32) {
    let p = js_sys::Promise::new(&mut |res, _| {
        web_sys_set_timeout(&res, ms);
    });
    let _ = wasm_bindgen_futures::JsFuture::from(p).await;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = setTimeout)]
    fn web_sys_set_timeout(f: &js_sys::Function, ms: i32);
}

pub async fn pico_info() -> Result<types::PicoInfo, String> {
    call("pico_info", NONE).await
}

#[derive(Serialize)]
struct PhyArgs<'a> {
    phy: &'a types::Phy,
}
pub async fn write_phy(phy: &types::Phy) -> Result<(), String> {
    guarded("write_phy", PhyArgs { phy }).await
}

pub async fn fido_reset(path: &str) -> Result<(), String> {
    guarded("fido_reset", Args { path: Some(path), ..NONE }).await
}

#[derive(Serialize)]
struct NameArgs<'a> {
    name: &'a str,
}
pub async fn oath_list() -> Result<Vec<types::OathAccount>, String> {
    call("oath_list", NONE).await
}
pub async fn oath_calculate(name: &str) -> Result<String, String> {
    call("oath_calculate", NameArgs { name }).await
}
pub async fn oath_delete(name: &str) -> Result<(), String> {
    guarded("oath_delete", NameArgs { name }).await
}
#[derive(Serialize)]
struct AddArgs<'a> {
    account: &'a types::NewOath,
}
pub async fn oath_add(account: &types::NewOath) -> Result<(), String> {
    call("oath_add", AddArgs { account }).await
}

/// Seconds since the Unix epoch (JS clock).
pub fn now_secs() -> f64 {
    js_sys::Date::now() / 1000.0
}

pub fn copy_text(text: &str) {
    use js_sys::{Function, Reflect};
    // navigator.clipboard.writeText(text), without string-building JS
    let clip = Reflect::get(&js_sys::global(), &"navigator".into()).and_then(|n| Reflect::get(&n, &"clipboard".into()));
    if let Ok(clip) = clip
        && let Ok(f) = Reflect::get(&clip, &"writeText".into()) {
            let _ = f.unchecked_into::<Function>().call1(&clip, &text.into());
        }
}

#[derive(Serialize)]
struct SlotArgs<'a> {
    slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<&'a types::NewOtp>,
}
pub async fn otp_status() -> Result<Vec<types::OtpSlot>, String> {
    call("otp_status", NONE).await
}
pub async fn otp_configure(slot: u8, config: &types::NewOtp) -> Result<(), String> {
    guarded("otp_configure", SlotArgs { slot, config: Some(config) }).await
}
pub async fn otp_delete(slot: u8) -> Result<(), String> {
    guarded("otp_delete", SlotArgs { slot, config: None }).await
}
pub async fn otp_swap() -> Result<(), String> {
    call("otp_swap", NONE).await
}
#[derive(Serialize)]
struct BytesArgs {
    bytes: usize,
}
pub async fn random_hex(bytes: usize) -> String {
    call("random_hex", BytesArgs { bytes }).await.unwrap_or_default()
}

#[derive(Serialize)]
struct ProductArgs<'a> {
    product: &'a str,
}
pub async fn fw_releases(product: &str) -> Result<Vec<types::FwRelease>, String> {
    call("fw_releases", ProductArgs { product }).await
}
#[derive(Serialize)]
struct FlashArgs<'a> {
    url: &'a str,
    board: types::Board,
}
pub async fn fw_flash(url: &str, board: types::Board) -> Result<(), String> {
    guarded("fw_flash", FlashArgs { url, board }).await
}
pub async fn fw_pick_file() -> Result<Option<String>, String> {
    call("fw_pick_file", NONE).await
}
#[derive(Serialize)]
struct FlashFileArgs<'a> {
    path: &'a str,
    board: types::Board,
}
pub async fn fw_flash_file(path: &str, board: types::Board) -> Result<(), String> {
    guarded("fw_flash_file", FlashFileArgs { path, board }).await
}
#[derive(Serialize)]
struct BootLogArgs {
    seconds: u64,
}
pub async fn fw_boot_log(seconds: u64) -> Result<String, String> {
    call("fw_boot_log", BootLogArgs { seconds }).await
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = listen)]
    fn tauri_listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> js_sys::Promise;
}

/// Calls `f` with each `flash-progress` event payload until the returned guard is dropped.
pub struct Listener(#[allow(dead_code)] Closure<dyn FnMut(JsValue)>, js_sys::Promise);
impl Drop for Listener {
    fn drop(&mut self) {
        // listen() resolves to an unlisten function
        let unlisten = Closure::<dyn FnMut(JsValue)>::new(|f: JsValue| {
            if let Some(f) = f.dyn_ref::<js_sys::Function>() {
                let _ = f.call0(&JsValue::NULL);
            }
        });
        let _ = self.1.then(&unlisten);
        unlisten.forget();
    }
}
pub fn on_flash_progress(mut f: impl FnMut(types::FlashProgress) + 'static) -> Listener {
    let cb = Closure::<dyn FnMut(JsValue)>::new(move |e: JsValue| {
        let payload = js_sys::Reflect::get(&e, &"payload".into()).unwrap_or(JsValue::NULL);
        if let Ok(p) = serde_wasm_bindgen::from_value(payload) {
            f(p)
        }
    });
    let p = tauri_listen("flash-progress", &cb);
    Listener(cb, p)
}

pub async fn ssh_env() -> Result<types::SshEnv, String> {
    call("ssh_env", NONE).await
}
pub async fn ssh_keys() -> Result<Vec<types::SshKey>, String> {
    call("ssh_keys", NONE).await
}
#[derive(Serialize)]
struct KeyArgs<'a> {
    key: &'a types::NewSshKey,
}
pub async fn ssh_generate(key: &types::NewSshKey) -> Result<types::SshKey, String> {
    call("ssh_generate", KeyArgs { key }).await
}
#[derive(Serialize)]
struct SetupArgs<'a> {
    setup: &'a types::GitSetup,
}
pub async fn ssh_git_setup(setup: &types::GitSetup) -> Result<types::GitSigning, String> {
    call("ssh_git_setup", SetupArgs { setup }).await
}
#[derive(Serialize)]
struct HostArgs<'a> {
    host: &'a str,
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
}
pub async fn ssh_add_host(host: &str, key: &str) -> Result<String, String> {
    call("ssh_add_host", HostArgs { host, key, pin: None }).await
}
pub async fn ssh_test(host: &str, key: &str, pin: Option<&str>) -> Result<String, String> {
    call("ssh_test", HostArgs { host, key, pin }).await
}
pub async fn ssh_install_openssh() -> Result<String, String> {
    call("ssh_install_openssh", NONE).await
}
#[derive(Serialize)]
struct PinArgs<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
}
pub async fn ssh_recover(pin: Option<&str>) -> Result<Vec<types::SshKey>, String> {
    call("ssh_recover", PinArgs { pin }).await
}

pub async fn ssh_inventory() -> Result<Vec<types::LegacyKey>, String> {
    call("ssh_inventory", NONE).await
}
pub async fn ssh_authorize(host: &str, key: &str) -> Result<String, String> {
    call("ssh_authorize", HostArgs { host, key, pin: None }).await
}
pub async fn ssh_check(host: &str, key: &str, pin: Option<&str>) -> Result<String, String> {
    call("ssh_check", HostArgs { host, key, pin }).await
}
#[derive(Serialize)]
struct OldArgs<'a> {
    old: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}
pub async fn ssh_switch_config(old: &str, key: &str) -> Result<Vec<String>, String> {
    guarded("ssh_switch_config", OldArgs { old, key: Some(key) }).await
}
pub async fn ssh_archive(old: &str) -> Result<String, String> {
    guarded("ssh_archive", OldArgs { old, key: None }).await
}

#[derive(Serialize)]
struct PolicyArgs<'a> {
    path: &'a str,
    pin: &'a str,
    change: &'a types::FidoPolicy,
}
pub async fn fido_policy(path: &str, pin: &str, change: &types::FidoPolicy) -> Result<(), String> {
    guarded("fido_policy", PolicyArgs { path, pin, change }).await
}
pub async fn pico_time() -> Result<Option<u32>, String> {
    call("pico_time", NONE).await
}
pub async fn pico_sync_time() -> Result<(), String> {
    call("pico_sync_time", NONE).await
}
#[derive(Serialize)]
struct SaveArgs<'a> {
    name: &'a str,
    content: &'a str,
}
/// Writes to ~/Downloads (unique name); returns the full path.
pub async fn save_text(name: &str, content: &str) -> Result<String, String> {
    call("save_text", SaveArgs { name, content }).await
}

pub async fn large_blobs(path: &str, pin: &str) -> Result<types::LargeBlobs, String> {
    call("large_blobs", Args { path: Some(path), pin: Some(pin), ..NONE }).await
}
#[derive(Serialize)]
struct BlobDel<'a> {
    path: &'a str,
    pin: &'a str,
    index: u32,
}
pub async fn large_blob_delete(path: &str, pin: &str, index: u32) -> Result<(), String> {
    guarded("large_blob_delete", BlobDel { path, pin, index }).await
}

#[derive(Serialize)]
struct PwArgs<'a> {
    password: Option<&'a str>,
}
pub async fn oath_unlock(password: &str) -> Result<(), String> {
    call("oath_unlock", PwArgs { password: Some(password) }).await
}
pub async fn oath_lock() -> Result<(), String> {
    call("oath_lock", NONE).await
}
pub async fn oath_protected() -> Result<bool, String> {
    call("oath_protected", NONE).await
}
/// None removes the password.
pub async fn oath_set_password(password: Option<&str>) -> Result<(), String> {
    guarded("oath_set_password", PwArgs { password }).await
}
#[derive(Serialize)]
struct RenameArgs<'a> {
    old: &'a str,
    new: &'a str,
}
pub async fn oath_rename(old: &str, new: &str) -> Result<(), String> {
    call("oath_rename", RenameArgs { old, new }).await
}

pub async fn agent_status() -> Result<types::AgentStatus, String> {
    call("agent_status", NONE).await
}
#[derive(Serialize)]
struct AgentArgs<'a> {
    running: bool,
    pin: Option<&'a str>,
}
pub async fn agent_set(running: bool, pin: Option<&str>) -> Result<types::AgentStatus, String> {
    call("agent_set", AgentArgs { running, pin }).await
}

pub async fn recovery_files() -> Result<Vec<types::RecoveryFile>, String> {
    call("recovery_files", NONE).await
}
#[derive(Serialize)]
struct ExportArgs<'a> {
    path: &'a str,
    understood: bool,
}
/// Save-as dialog; Ok(None) when the user cancels.
pub async fn recovery_export(path: &str, understood: bool) -> Result<Option<String>, String> {
    guarded("recovery_export", ExportArgs { path, understood }).await
}

pub async fn pgp_status() -> Result<types::PgpStatus, String> {
    call("pgp_status", NONE).await
}
#[derive(Serialize)]
struct PgpPinArgs<'a> {
    admin: bool,
    old: &'a str,
    new: &'a str,
}
pub async fn pgp_change_pin(admin: bool, old: &str, new: &str) -> Result<(), String> {
    call("pgp_change_pin", PgpPinArgs { admin, old, new }).await
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PgpResetPinArgs<'a> {
    admin_pin: &'a str,
    new: &'a str,
}
pub async fn pgp_reset_pin(admin_pin: &str, new: &str) -> Result<(), String> {
    call("pgp_reset_pin", PgpResetPinArgs { admin_pin, new }).await
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PgpHolderArgs<'a> {
    admin_pin: &'a str,
    name: &'a str,
    url: &'a str,
}
pub async fn pgp_set_cardholder(admin_pin: &str, name: &str, url: &str) -> Result<(), String> {
    call("pgp_set_cardholder", PgpHolderArgs { admin_pin, name, url }).await
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PgpResetArgs<'a> {
    admin_pin: Option<&'a str>,
    confirm: &'a str,
}
pub async fn pgp_factory_reset(admin_pin: Option<&str>, confirm: &str) -> Result<(), String> {
    guarded("pgp_factory_reset", PgpResetArgs { admin_pin, confirm }).await
}

pub async fn hsm_status() -> Result<types::HsmStatus, String> {
    call("hsm_status", NONE).await
}
#[derive(Serialize)]
struct HsmPinArgs<'a> {
    so: bool,
    old: &'a str,
    new: &'a str,
}
pub async fn hsm_change_pin(so: bool, old: &str, new: &str) -> Result<(), String> {
    call("hsm_change_pin", HsmPinArgs { so, old, new }).await
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HsmUnblockArgs<'a> {
    so_pin: &'a str,
    new: &'a str,
}
pub async fn hsm_unblock(so_pin: &str, new: &str) -> Result<(), String> {
    call("hsm_unblock", HsmUnblockArgs { so_pin, new }).await
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HsmInitArgs<'a> {
    pin: &'a str,
    so_pin: &'a str,
    retries: u8,
    confirm: &'a str,
}
/// Wipes the HSM. `confirm` must be "ERASE HSM" when it's already initialized.
pub async fn hsm_initialize(pin: &str, so_pin: &str, retries: u8, confirm: &str) -> Result<(), String> {
    guarded("hsm_initialize", HsmInitArgs { pin, so_pin, retries, confirm }).await
}
#[derive(Serialize)]
struct HsmDeleteArgs<'a> {
    pin: &'a str,
    id: u8,
}
pub async fn hsm_delete_key(pin: &str, id: u8) -> Result<(), String> {
    guarded("hsm_delete_key", HsmDeleteArgs { pin, id }).await
}

/// Looks for an otpauth:// QR code on the screen(s).
pub async fn oath_scan_screen() -> Result<String, String> {
    call("oath_scan_screen", NONE).await
}

pub async fn admin_status() -> Result<types::AdminStatus, String> {
    call("admin_status", NONE).await
}
#[derive(Serialize)]
struct PassArgs<'a> {
    pass: &'a str,
}
pub async fn admin_unlock(pass: &str) -> Result<(), String> {
    call("admin_unlock", PassArgs { pass }).await
}
pub async fn admin_lock() -> Result<(), String> {
    call("admin_lock", NONE).await
}
#[derive(Serialize)]
struct AdminSetArgs<'a> {
    current: Option<&'a str>,
    new: &'a str,
}
pub async fn admin_set(current: Option<&str>, new: &str) -> Result<(), String> {
    call("admin_set", AdminSetArgs { current, new }).await
}
#[derive(Serialize)]
struct CurrentArgs<'a> {
    current: &'a str,
}
pub async fn admin_remove(current: &str) -> Result<(), String> {
    call("admin_remove", CurrentArgs { current }).await
}
pub async fn audit_log() -> Result<types::AuditLog, String> {
    call("audit_log", NONE).await
}
pub async fn audit_export() -> Result<String, String> {
    call("audit_export", NONE).await
}
