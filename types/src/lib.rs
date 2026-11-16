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

/// One OATH (authenticator) account stored on the key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OathAccount {
    /// Raw on-key name, e.g. "60/GitHub:alice" (period prefix only when != 30).
    pub name: String,
    pub issuer: Option<String>,
    pub account: String,
    pub hotp: bool,
    pub algorithm: OathAlg,
    pub digits: u8,
    pub period: u32,
    pub touch: bool,
    /// Current code; `None` for HOTP / touch accounts until requested.
    pub code: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
pub enum OathAlg {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NewOath {
    pub issuer: String,
    pub account: String,
    /// Base32 secret, as shown by websites.
    pub secret: String,
    pub hotp: bool,
    pub algorithm: OathAlg,
    pub digits: u8,
    pub period: u32,
    pub counter: u64,
    pub touch: bool,
}

impl Default for NewOath {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            account: String::new(),
            secret: String::new(),
            hotp: false,
            algorithm: OathAlg::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            touch: false,
        }
    }
}

impl NewOath {
    /// Name stored on the key, YKOATH convention: `[period/]issuer:account`.
    pub fn key_name(&self) -> String {
        let base = if self.issuer.is_empty() { self.account.clone() } else { format!("{}:{}", self.issuer, self.account) };
        if !self.hotp && self.period != 30 { format!("{}/{}", self.period, base) } else { base }
    }

    /// Parse an `otpauth://totp|hotp/Label?secret=...` link (from a QR code).
    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let rest = uri.trim().strip_prefix("otpauth://").ok_or("Not an otpauth:// link")?;
        let (kind, rest) = rest.split_once('/').ok_or("Missing account label")?;
        let hotp = match kind.to_ascii_lowercase().as_str() {
            "totp" => false,
            "hotp" => true,
            _ => return Err("Unsupported OTP type".into()),
        };
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = pct_decode(label);
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };
        let mut n = NewOath { hotp, account, ..Default::default() };
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = pct_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => n.secret = v,
                "issuer" => issuer = v,
                "digits" => n.digits = v.parse().map_err(|_| "Bad digits")?,
                "period" => n.period = v.parse().map_err(|_| "Bad period")?,
                "counter" => n.counter = v.parse().map_err(|_| "Bad counter")?,
                "algorithm" => {
                    n.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => OathAlg::Sha1,
                        "SHA256" => OathAlg::Sha256,
                        "SHA512" => OathAlg::Sha512,
                        _ => return Err("Unsupported algorithm".into()),
                    }
                }
                _ => {}
            }
        }
        n.issuer = issuer;
        if n.secret.is_empty() {
            return Err("Link has no secret".into());
        }
        Ok(n)
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_parsing() {
        let n = NewOath::from_uri("otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!((n.issuer.as_str(), n.account.as_str(), n.secret.as_str()), ("ACME Co", "john@example.com", "JBSWY3DPEHPK3PXP"));
        assert_eq!((n.algorithm, n.digits, n.period, n.hotp), (OathAlg::Sha256, 8, 60, false));
        assert_eq!(n.key_name(), "60/ACME Co:john@example.com");

        let h = NewOath::from_uri("otpauth://hotp/alice?secret=ABC&counter=5").unwrap();
        assert!(h.hotp && h.counter == 5 && h.issuer.is_empty());
        assert_eq!(h.key_name(), "alice");

        assert!(NewOath::from_uri("https://x").is_err());
        assert!(NewOath::from_uri("otpauth://totp/x?issuer=a").is_err());
        assert_eq!(pct_decode("a%2"), "a%2"); // truncated escape kept as-is
    }
}

/// What a YubiKey-style OTP slot (short/long touch) is programmed with.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum OtpKind {
    YubicoOtp,
    Static,
    ChallengeResponse,
    YubicoChallenge,
    Hotp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OtpSlot {
    /// 1 = short touch, 2 = long touch
    pub slot: u8,
    pub kind: Option<OtpKind>,
    /// Needs a touch to run (always true for typed OTPs).
    pub touch: bool,
    /// Yubico OTP public ID (modhex).
    pub public_id: Option<String>,
}

/// New slot configuration. Keys/IDs are hex (public ID: modhex).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind")]
pub enum NewOtp {
    YubicoOtp { public_id: String, private_id: String, key: String },
    Static { password: String, enter: bool },
    ChallengeResponse { key: String, touch: bool },
}
