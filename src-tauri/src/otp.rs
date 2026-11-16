//! YubiKey-compatible OTP slots (short/long touch) over CCID, as implemented by
//! pico-fido `src/fido/otp.c`. Config layout and flags follow ykpers/ykman.
use crate::oath::tlvs;
use crate::pico::Card;
use types::{NewOtp, OtpKind, OtpSlot};

type R<T> = Result<T, String>;

const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
const INS: u8 = 0x01;
const CMD_CONFIG: [u8; 2] = [0x01, 0x03]; // slot 1, slot 2
const CMD_SWAP: u8 = 0x06;
const CMD_STATUS_EXT: u8 = 0x14;

// otp_config_t: fixed[16] uid[6] key[16] acc_code[6] fixed_size ext tkt cfg rfu[2] crc[2]
const CONFIG_SIZE: usize = 52;
const ACC_CODE_SIZE: usize = 6;

const TKT_APPEND_CR: u8 = 0x20;
const TKT_CHAL_RESP: u8 = 0x40; // same bit as OATH_HOTP
const CFG_SHORT_TICKET: u8 = 0x02;
const CFG_HMAC_LT64: u8 = 0x04;
const CFG_CHAL_BTN_TRIG: u8 = 0x08;
const CFG_CHAL_YUBICO: u8 = 0x20;
const CFG_CHAL_HMAC: u8 = 0x22;
const EXT_SERIAL_API_VISIBLE: u8 = 0x04;
const EXT_ALLOW_UPDATE: u8 = 0x20;

const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

fn open() -> R<Card> {
    let card = Card::open()?;
    card.select_aid(&AID).map_err(|e| {
        if e.contains("6A82") { "The OTP application is disabled on this key.".into() } else { e }
    })?;
    Ok(card)
}

fn apdu(p1: u8, data: &[u8]) -> Vec<u8> {
    let mut c = vec![0x00, INS, p1, 0x00, data.len() as u8];
    c.extend_from_slice(data);
    c
}

/// Kind from ticket/config flags, in the same order the firmware checks them.
fn kind(tkt: u8, cfg: u8) -> OtpKind {
    if tkt & TKT_CHAL_RESP != 0 && cfg & CFG_CHAL_YUBICO != 0 {
        if cfg & CFG_CHAL_HMAC == CFG_CHAL_HMAC { OtpKind::ChallengeResponse } else { OtpKind::YubicoChallenge }
    } else if tkt & TKT_CHAL_RESP != 0 {
        OtpKind::Hotp
    } else if cfg & CFG_CHAL_HMAC != 0 {
        OtpKind::Static // SHORT_TICKET or STATIC_TICKET
    } else {
        OtpKind::YubicoOtp
    }
}

pub fn status() -> R<Vec<OtpSlot>> {
    let card = open()?;
    let ext = card.apdu(&apdu(CMD_STATUS_EXT, &[]))?;
    let mut slots: Vec<OtpSlot> =
        (1..=2).map(|slot| OtpSlot { slot, kind: None, touch: false, public_id: None }).collect();
    for (tag, v) in tlvs(&ext) {
        let Some(s) = slots.get_mut((tag.wrapping_sub(0xB0)) as usize) else { continue };
        for (t, d) in tlvs(v) {
            match (t, d) {
                (0xA0, [tkt, cfg, ..]) => {
                    let k = kind(*tkt, *cfg);
                    s.touch = !matches!(k, OtpKind::ChallengeResponse | OtpKind::YubicoChallenge) || cfg & CFG_CHAL_BTN_TRIG != 0;
                    s.kind = Some(k);
                }
                (0xC0, id) => s.public_id = Some(modhex(id)),
                _ => {}
            }
        }
    }
    Ok(slots)
}

fn crc16(d: &[u8]) -> u16 {
    d.iter().fold(0xFFFF, |mut crc, &b| {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
        }
        crc
    })
}

/// Build the 52-byte config with its CRC.
fn config(fixed: &[u8], uid: &[u8], key: &[u8], fixed_size: u8, tkt: u8, cfg: u8) -> Vec<u8> {
    let mut c = vec![0u8; CONFIG_SIZE];
    c[..fixed.len()].copy_from_slice(fixed);
    c[16..16 + uid.len()].copy_from_slice(uid);
    c[22..22 + key.len()].copy_from_slice(key);
    c[44] = fixed_size;
    c[45] = EXT_SERIAL_API_VISIBLE | EXT_ALLOW_UPDATE;
    c[46] = tkt;
    c[47] = cfg;
    let crc = !crc16(&c[..50]);
    c[50..].copy_from_slice(&crc.to_le_bytes());
    c
}

fn build(n: &NewOtp) -> R<Vec<u8>> {
    Ok(match n {
        NewOtp::YubicoOtp { public_id, private_id, key } => {
            let public = unmodhex(public_id).filter(|p| p.len() == 6).ok_or("Public ID must be 12 modhex characters.")?;
            let private = unhex_n(private_id, 6, "Private ID")?;
            let key = unhex_n(key, 16, "Secret key")?;
            config(&public, &private, &key, 6, TKT_APPEND_CR, 0)
        }
        NewOtp::Static { password, enter } => {
            let codes = scancodes(password)?;
            if codes.is_empty() || codes.len() > 38 {
                return Err("Password must be 1–38 characters.".into());
            }
            let mut all = codes.clone();
            all.resize(38, 0);
            config(&all[..16], &all[16..22], &all[22..], codes.len().min(16) as u8, if *enter { TKT_APPEND_CR } else { 0 }, CFG_SHORT_TICKET)
        }
        NewOtp::ChallengeResponse { key, touch } => {
            let key = unhex_n(key, 20, "Secret key")?;
            let cfg = CFG_CHAL_HMAC | CFG_HMAC_LT64 | if *touch { CFG_CHAL_BTN_TRIG } else { 0 };
            config(&[], &key[16..20], &key[..16], 0, TKT_CHAL_RESP, cfg)
        }
    })
}

/// Write a slot (overwrites). ponytail: access codes not supported, always sends the zero code.
pub fn configure(slot: u8, n: &NewOtp) -> R<()> {
    write(slot, build(n)?)
}

pub fn delete(slot: u8) -> R<()> {
    write(slot, vec![0u8; CONFIG_SIZE])
}

fn write(slot: u8, mut cfg: Vec<u8>) -> R<()> {
    let p1 = *CMD_CONFIG.get(slot as usize - 1).ok_or("Slot must be 1 or 2.")?;
    cfg.extend_from_slice(&[0u8; ACC_CODE_SIZE]);
    open()?.apdu(&apdu(p1, &cfg)).map(|_| ())
}

pub fn swap() -> R<()> {
    open()?.apdu(&apdu(CMD_SWAP, &[])).map(|_| ())
}

pub fn random_hex(n: usize) -> R<String> {
    let mut b = vec![0u8; n.min(64)];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(crate::fido::hex(&b))
}

fn modhex(d: &[u8]) -> String {
    d.iter().flat_map(|b| [MODHEX[(b >> 4) as usize], MODHEX[(b & 15) as usize]]).map(char::from).collect()
}

fn unmodhex(s: &str) -> Option<Vec<u8>> {
    let v: Vec<u8> = s.trim().bytes().map(|c| MODHEX.iter().position(|&m| m == c.to_ascii_lowercase()).map(|p| p as u8)).collect::<Option<_>>()?;
    (v.len() % 2 == 0).then(|| v.chunks(2).map(|p| p[0] << 4 | p[1]).collect())
}

fn unhex_n(s: &str, n: usize, what: &str) -> R<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    crate::fido::unhex(&s).ok().filter(|v| v.len() == n).ok_or_else(|| format!("{what} must be {} hex characters.", n * 2))
}

/// ASCII → US-layout HID scan codes (0x80 = shift), as ykman's static password does.
fn scancodes(s: &str) -> R<Vec<u8>> {
    const NUM: &[u8] = b"1234567890";
    const SHIFT_NUM: &[u8] = b"!@#$%^&*()";
    const PUNCT: &[u8] = b"-=[]\\ ;'`,./";
    const SHIFT_PUNCT: &[u8] = b"_+{}| :\"~<>?";
    const PUNCT_CODES: [u8; 12] = [0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x00, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
    s.bytes()
        .map(|c| match c {
            b'a'..=b'z' => Ok(0x04 + c - b'a'),
            b'A'..=b'Z' => Ok(0x84 + c - b'A'),
            b' ' => Ok(0x2c),
            _ => NUM.iter().position(|&x| x == c).map(|i| 0x1e + i as u8)
                .or_else(|| SHIFT_NUM.iter().position(|&x| x == c).map(|i| 0x9e + i as u8))
                .or_else(|| PUNCT.iter().position(|&x| x == c).filter(|&i| i != 5).map(|i| PUNCT_CODES[i]))
                .or_else(|| SHIFT_PUNCT.iter().position(|&x| x == c).filter(|&i| i != 5).map(|i| PUNCT_CODES[i] | 0x80))
                .ok_or_else(|| format!("'{}' can't be typed by the key (US keyboard ASCII only).", c as char)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_encodings() {
        let c = build(&NewOtp::YubicoOtp { public_id: "vvccccdddddd".into(), private_id: "010203040506".into(), key: "00".repeat(16) }).unwrap();
        assert_eq!(c.len(), CONFIG_SIZE);
        assert_eq!(crc16(&c), 0xF0B8, "firmware's check_crc residual");
        assert_eq!(&c[..6], &[0xff, 0x00, 0x00, 0x22, 0x22, 0x22]);
        assert_eq!(modhex(&c[..6]), "vvccccdddddd");
        assert_eq!(kind(c[46], c[47]), OtpKind::YubicoOtp);

        let s = build(&NewOtp::Static { password: "aZ1!".into(), enter: true }).unwrap();
        assert_eq!(&s[..4], &[0x04, 0x9d, 0x1e, 0x9e]);
        assert_eq!(kind(s[46], s[47]), OtpKind::Static);
        assert!(scancodes("é").is_err());

        let key: String = (0..20).map(|i| format!("{i:02x}")).collect();
        let h = build(&NewOtp::ChallengeResponse { key, touch: true }).unwrap();
        assert_eq!(crc16(&h), 0xF0B8);
        assert_eq!(&h[22..38], &(0..16).collect::<Vec<u8>>()[..]);
        assert_eq!(&h[16..22], &[16, 17, 18, 19, 0, 0]);
        assert_eq!(&h[..16], &[0u8; 16]);
        assert_eq!(kind(h[46], h[47]), OtpKind::ChallengeResponse);
        assert!(build(&NewOtp::ChallengeResponse { key: "zz".into(), touch: false }).is_err());
    }

    /// Programs slot 2 with HMAC challenge-response, checks the HMAC, then clears it.
    /// Refuses to touch slot 2 if it's already in use.
    /// `cargo test -p picokeys-app -- --ignored otp_roundtrip --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn otp_roundtrip() {
        let before = status().unwrap();
        println!("{before:#?}");
        assert!(before[1].kind.is_none(), "slot 2 is in use; not touching it");
        let key = "0102030405060708090a0b0c0d0e0f1011121314";
        configure(2, &NewOtp::ChallengeResponse { key: key.into(), touch: false }).unwrap();
        assert_eq!(status().unwrap()[1].kind, Some(OtpKind::ChallengeResponse));
        let mut chal = b"hello".to_vec();
        chal.resize(64, 0);
        let rsp = open().unwrap().apdu(&apdu(0x38, &chal)).unwrap();
        println!("hmac = {}", rsp.iter().map(|b| format!("{b:02x}")).collect::<String>());
        delete(2).unwrap();
        assert!(status().unwrap()[1].kind.is_none());
        // HMAC-SHA1(key, "hello"), from `openssl dgst -sha1 -mac HMAC -macopt hexkey:0102..14`
        assert_eq!(crate::fido::hex(&rsp), "61232556fab861c4f772dcc4ae3f1968632025a0");
    }
}
