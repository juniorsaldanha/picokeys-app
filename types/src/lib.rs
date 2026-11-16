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

/// Pico Keys SDK "rescue" applet info (shared by Pico FIDO / HSM / OpenPGP).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PicoInfo {
    pub mcu: String,
    pub product: String,
    pub version: String,
    pub serial: String,
    pub build: Option<u32>,
    pub flash: Option<Flash>,
    pub secure_boot: Option<SecureBoot>,
    pub phy: Phy,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Flash {
    pub free: u32,
    pub used: u32,
    pub total: u32,
    pub files: u32,
    pub size: u32,
    pub firmware: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct SecureBoot {
    pub enabled: bool,
    pub locked: bool,
    pub bootkey: u8,
}

/// Device configuration ("PHY" file 0xE020). `None` = not set, firmware default.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Phy {
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub led_gpio: Option<u8>,
    pub led_brightness: Option<u8>,
    pub opts: u16,
    /// Seconds to wait for a button press; 0/None disables user presence on the button.
    pub up_btn: Option<u8>,
    pub usb_product: Option<String>,
    pub enabled_curves: Option<u32>,
    pub enabled_usb_itf: Option<u8>,
    pub led_driver: Option<u8>,
    pub led_order: Option<u8>,
}

impl Phy {
    pub const OPT_WCID: u16 = 0x1;
    pub const OPT_DIMM: u16 = 0x2;
    pub const OPT_DISABLE_POWER_RESET: u16 = 0x4;
    pub const OPT_LED_STEADY: u16 = 0x8;

    pub const ITF_CCID: u8 = 0x1;
    pub const ITF_WCID: u8 = 0x2;
    pub const ITF_HID: u8 = 0x4;
    pub const ITF_KB: u8 = 0x8;
    pub const ITF_ALL: u8 = 0x1F;

    pub const CURVE_SECP256K1: u32 = 0x8;
}
