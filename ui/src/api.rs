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
