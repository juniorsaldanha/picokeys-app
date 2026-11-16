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
    call("delete_passkey", Args { path: Some(path), pin: Some(pin), cred_id: Some(cred_id), ..NONE }).await
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
    call("write_phy", PhyArgs { phy }).await
}

pub async fn fido_reset(path: &str) -> Result<(), String> {
    call("fido_reset", Args { path: Some(path), ..NONE }).await
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
    call("oath_delete", NameArgs { name }).await
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
    call("otp_configure", SlotArgs { slot, config: Some(config) }).await
}
pub async fn otp_delete(slot: u8) -> Result<(), String> {
    call("otp_delete", SlotArgs { slot, config: None }).await
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
    call("fw_flash", FlashArgs { url, board }).await
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
