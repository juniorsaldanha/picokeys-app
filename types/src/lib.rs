//! Data shared between the Tauri backend and the Dioxus UI (sent as JSON over IPC).
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    pub path: String,
    pub product: String,
    pub vid: u16,
    pub pid: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct FidoInfo {
    pub firmware: String,
    pub aaguid: String,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub algorithms: Vec<String>,
    pub options: Vec<(String, bool)>,
    /// `None` when the key doesn't report clientPin.
    pub pin_set: Option<bool>,
    pub pin_retries: Option<i32>,
    pub min_pin_length: u32,
    pub remaining_passkeys: u32,
    pub max_msg_size: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Passkey {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// hex-encoded credential id
    pub cred_id: String,
    pub cred_protect: String,
}
