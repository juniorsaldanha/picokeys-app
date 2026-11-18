//! Pico HSM (SmartCard-HSM compatible): status, PIN/SO-PIN, initialize, list and delete keys.
//! Key generation, signing and DKEK backup stay with pkcs11-tool / sc-hsm-tool / pico-hsm-tool.
use crate::pgp::find;
use crate::pico::Card;
use types::{HsmKey, HsmStatus};

type R<T> = Result<T, String>;

const AID: [u8; 11] = [0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01];
const KEY_PREFIX: u8 = 0xCC;
const PRKD_PREFIX: u8 = 0xC4;
const CD_PREFIX: u8 = 0xC8;

fn open() -> R<(Card, Vec<u8>)> {
    let card = Card::open()?;
    let fci = card.select_aid(&AID).map_err(|e| if e.contains("6A82") { "This key isn't running Pico HSM.".into() } else { e })?;
    Ok((card, fci))
}

/// VERIFY with no data: Some(tries left), None = not initialized.
fn tries(card: &Card, p2: u8) -> R<Option<u8>> {
    let (_, sw) = card.transmit(&[0x00, 0x20, 0x00, p2])?;
    Ok(match sw {
        [0x63, n] if n & 0xF0 == 0xC0 => Some(n & 0x0F),
        [0x90, 0x00] => Some(u8::MAX), // already verified this session
        [0x69, 0x83] => Some(0),
        [0x6A, 0x88] => None,
        [a, b] => return Err(format!("Key returned status {a:02X}{b:02X}")),
    })
}

fn sw(card: &Card, cmd: &[u8], what: &str) -> R<Vec<u8>> {
    let (mut data, mut s) = card.transmit(cmd)?;
    while s[0] == 0x61 {
        let (more, next) = card.transmit(&[0x00, 0xC0, 0x00, 0x00, 0x00])?;
        data.extend(more);
        s = next;
    }
    match s {
        [0x90, 0x00] => Ok(data),
        [0x63, n] if n & 0xF0 == 0xC0 => Err(format!("Wrong {what}. {} tries left.", n & 0x0F)),
        [0x69, 0x83] => Err(format!("{what} is blocked.")),
        [0x69, 0x82] => Err("Log in with the PIN first.".into()),
        [0x6A, 0x88] => Err("The HSM isn't initialized yet.".into()),
        [a, b] => Err(format!("Key returned status {a:02X}{b:02X}")),
    }
}

/// LIST KEYS reply: (prefix, id) pairs.
fn pairs(d: &[u8]) -> Vec<(u8, u8)> {
    d.as_chunks::<2>().0.iter().map(|c| (c[0], c[1])).filter(|p| *p != (0, 0)).collect()
}

/// PKCS#15 PrivateKey/SecretKey object: outer tag gives the type, first UTF8String the label.
fn describe(prkd: &[u8]) -> (String, Option<String>) {
    let kind = match prkd.first() {
        Some(0x30) => "RSA",
        Some(0xA0) => "EC",
        Some(0xA8) => "AES",
        _ => "Key",
    };
    (kind.into(), find(prkd, 0x0C).map(|l| String::from_utf8_lossy(l).into_owned()))
}

fn read(card: &Card, prefix: u8, id: u8) -> Option<Vec<u8>> {
    // READ BINARY (odd ins) from offset 0
    sw(card, &[0x00, 0xB1, prefix, id, 0x04, 0x54, 0x02, 0x00, 0x00, 0x00], "PIN").ok().filter(|d| !d.is_empty())
}

pub fn status() -> R<HsmStatus> {
    let (card, fci) = open()?;
    let v = find(&fci, 0x85).unwrap_or_default();
    let version = v.get(3..5).map(|v| format!("{}.{}", v[0], v[1])).unwrap_or_default();
    let options = v.get(0..2).map(|o| u16::from_be_bytes([o[0], o[1]])).unwrap_or(0);
    let pin = tries(&card, 0x81)?;
    let so = tries(&card, 0x88)?;
    let mut keys = vec![];
    if pin.is_some() {
        let list = pairs(&sw(&card, &[0x80, 0x58, 0x00, 0x00, 0x00], "PIN")?);
        for &(_, id) in list.iter().filter(|(p, id)| *p == KEY_PREFIX && *id != 0) {
            let (kind, label) = read(&card, PRKD_PREFIX, id).map(|d| describe(&d)).unwrap_or(("Key".into(), None));
            keys.push(HsmKey { id, kind, label, has_cert: list.contains(&(CD_PREFIX, id)) });
        }
    }
    Ok(HsmStatus {
        version,
        initialized: pin.is_some(),
        pin_tries: pin.filter(|n| *n != u8::MAX),
        so_pin_tries: so.filter(|n| *n != u8::MAX),
        transport_pin: options & 0x0002 != 0,
        keys,
    })
}

/// SO-PIN is 16 hex digits (8 bytes), as sc-hsm-tool takes it.
fn so_pin(hex: &str) -> R<Vec<u8>> {
    let b = crate::fido::unhex(hex.trim()).map_err(|_| "The SO-PIN is 16 hex digits (0–9, A–F).".to_string())?;
    if b.len() != 8 {
        return Err("The SO-PIN is 16 hex digits (0–9, A–F).".into());
    }
    Ok(b)
}

fn user_pin_ok(p: &str) -> R<()> {
    if (6..=16).contains(&p.len()) { Ok(()) } else { Err("The PIN must be 6–16 characters.".into()) }
}

fn apdu(cla_ins: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = cla_ins.to_vec();
    c.push(data.len() as u8);
    c.extend_from_slice(data);
    c
}

/// `so`: change the SO-PIN (hex) instead of the user PIN.
pub fn change_pin(so: bool, old: &str, new: &str) -> R<()> {
    let (old, new) = if so { (so_pin(old)?, so_pin(new)?) } else { (user_pin_ok(new).map(|_| old.as_bytes().to_vec())?, new.as_bytes().to_vec()) };
    let (card, _) = open()?;
    let what = if so { "SO-PIN" } else { "PIN" };
    sw(&card, &apdu([0x00, 0x24, 0x00, if so { 0x88 } else { 0x81 }], &[old, new].concat()), what).map(|_| ())
}

/// RESET RETRY COUNTER with a new PIN, authorized by the SO-PIN.
pub fn unblock(so: &str, new: &str) -> R<()> {
    user_pin_ok(new)?;
    let so = so_pin(so)?;
    let (card, _) = open()?;
    sw(&card, &apdu([0x00, 0x2C, 0x00, 0x81], &[so, new.as_bytes().to_vec()].concat()), "SO-PIN").map(|_| ())
}

/// INITIALIZE: wipes every key and sets PIN, SO-PIN and a random device key (no DKEK shares).
pub fn initialize(pin: &str, so: &str, retries: u8) -> R<()> {
    user_pin_ok(pin)?;
    let so = so_pin(so)?;
    if !(1..=10).contains(&retries) {
        return Err("PIN retries must be 1–10.".into());
    }
    let mut d = vec![0x80, 0x02, 0x00, 0x01]; // options: allow RESET RETRY COUNTER
    d.extend([0x81, pin.len() as u8]);
    d.extend_from_slice(pin.as_bytes());
    d.extend([0x82, 0x08]);
    d.extend(so);
    d.extend([0x91, 0x01, retries, 0x92, 0x01, 0x00]);
    let (card, _) = open()?;
    sw(&card, &apdu([0x80, 0x50, 0x00, 0x00], &d), "SO-PIN").map(|_| ())
}

/// Deletes the key, its description and its certificate (missing parts are skipped).
pub fn delete_key(pin: &str, id: u8) -> R<()> {
    if id == 0 {
        return Err("The device key can't be deleted.".into());
    }
    let (card, _) = open()?;
    sw(&card, &apdu([0x00, 0x20, 0x00, 0x81], pin.as_bytes()), "PIN")?;
    for prefix in [KEY_PREFIX, PRKD_PREFIX, CD_PREFIX] {
        match sw(&card, &apdu([0x00, 0xE4, 0x00, 0x00], &[prefix, id]), "PIN") {
            Ok(_) => {}
            Err(e) if e.contains("6A82") && prefix != KEY_PREFIX => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert_eq!(pairs(&[0xC4, 0x00, 0xCC, 0x00, 0xCC, 0x01, 0xC4, 0x01, 0x00, 0x00]), vec![(0xC4, 0), (0xCC, 0), (0xCC, 1), (0xC4, 1)]);
        // EC PRKD: A0 { 30 { 0C "mykey" } ... }
        let prkd = [0xA0, 0x09, 0x30, 0x07, 0x0C, 0x05, b'm', b'y', b'k', b'e', b'y'];
        assert_eq!(describe(&prkd), ("EC".into(), Some("mykey".into())));
        // SELECT FCI with 85 = opts(2) FF major minor
        let fci = [0x62, 0x07, 0x85, 0x05, 0x00, 0x01, 0xFF, 0x06, 0x02];
        assert_eq!(find(&fci, 0x85).unwrap()[3..5], [6, 2]);
        assert!(so_pin("3537363231383830").is_ok()); // factory default
        assert!(so_pin("1234").is_err());
        assert_eq!(apdu([0, 0x24, 0, 0x81], &[1, 2]), [0, 0x24, 0, 0x81, 2, 1, 2]);
    }

    /// Read-only against the plugged-in key.
    #[test]
    #[ignore]
    fn live_status() {
        println!("{:?}", status());
    }
}
