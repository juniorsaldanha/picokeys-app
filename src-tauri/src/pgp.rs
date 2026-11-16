//! OpenPGP card (Pico OpenPGP): status, PINs, cardholder data, factory reset.
//! Key generation/import stays with gpg (`gpg --card-edit`).
use crate::pico::Card;
use types::{PgpKey, PgpStatus};

type R<T> = Result<T, String>;

const AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// BER-TLV with 1–2 byte tags and short/0x81/0x82 lengths, as OpenPGP cards use.
pub(crate) fn ber(d: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = vec![];
    let mut i = 0;
    while i < d.len() {
        let mut tag = d[i] as u16;
        i += 1;
        if tag & 0x1F == 0x1F {
            let Some(&b) = d.get(i) else { break };
            tag = (tag << 8) | b as u16;
            i += 1;
        }
        let Some(&l) = d.get(i) else { break };
        i += 1;
        let len = match l {
            0x81 => {
                let Some(&n) = d.get(i) else { break };
                i += 1;
                n as usize
            }
            0x82 => {
                let Some(n) = d.get(i..i + 2) else { break };
                i += 2;
                u16::from_be_bytes([n[0], n[1]]) as usize
            }
            n => n as usize,
        };
        let Some(v) = d.get(i..i + len) else { break };
        out.push((tag, v));
        i += len;
    }
    out
}

/// Depth-first search for a tag inside constructed DOs.
pub(crate) fn find(d: &[u8], tag: u16) -> Option<&[u8]> {
    for (t, v) in ber(d) {
        if t == tag {
            return Some(v);
        }
        // constructed: bit 0x20 of the first tag byte
        let first = if t > 0xFF { (t >> 8) as u8 } else { t as u8 };
        if first & 0x20 != 0
            && let Some(x) = find(v, tag)
        {
            return Some(x);
        }
    }
    None
}

fn open() -> R<Card> {
    let card = Card::open()?;
    card.select_aid(&AID).map_err(|e| {
        if e.contains("6A82") { "This key isn't running Pico OpenPGP.".into() } else { e }
    })?;
    Ok(card)
}

fn get_data(card: &Card, tag: u16) -> R<Vec<u8>> {
    let [p1, p2] = tag.to_be_bytes();
    card.apdu(&[0x00, 0xCA, p1, p2, 0x00])
}

fn algo(attr: &[u8]) -> String {
    match attr.first() {
        Some(0x01) if attr.len() >= 3 => format!("RSA {}", u16::from_be_bytes([attr[1], attr[2]])),
        Some(&id @ (0x12 | 0x13 | 0x16)) => {
            let oid = &attr[1..];
            let curve = match crate::fido::hex(oid.strip_suffix(&[0xFF]).unwrap_or(oid)).as_str() {
                "2a8648ce3d030107" => "P-256",
                "2b81040022" => "P-384",
                "2b81040023" => "P-521",
                "2b8104000a" => "secp256k1",
                "2b2403030208010107" => "brainpoolP256r1",
                "2b240303020801010b" => "brainpoolP384r1",
                "2b240303020801010d" => "brainpoolP512r1",
                "2b06010401da470f01" => "Ed25519",
                "2b060104019755010501" => "Cv25519",
                "2b6570" => "Ed448",
                "2b656f" => "X448",
                _ => "EC",
            };
            format!("{} {curve}", match id { 0x12 => "ECDH", 0x13 => "ECDSA", _ => "EdDSA" })
        }
        _ => "unknown".into(),
    }
}

pub fn status() -> R<PgpStatus> {
    let card = open()?;
    let app = get_data(&card, 0x006E)?;
    let aid = find(&app, 0x4F).unwrap_or_default();
    let pw = find(&app, 0xC4).unwrap_or_default();
    let fps = find(&app, 0xC5).unwrap_or_default();
    let times = find(&app, 0xCD).unwrap_or_default();
    let mut keys = vec![];
    for (i, (slot, attr_tag)) in [("Signature", 0xC1), ("Encryption", 0xC2), ("Authentication", 0xC3)].into_iter().enumerate() {
        let fp = fps.get(i * 20..i * 20 + 20).filter(|f| f.iter().any(|b| *b != 0));
        keys.push(PgpKey {
            slot: slot.into(),
            fingerprint: fp.map(crate::fido::hex),
            created: times.get(i * 4..i * 4 + 4).map(|t| u32::from_be_bytes(t.try_into().unwrap())).filter(|t| *t != 0),
            algorithm: find(&app, attr_tag).map(algo).unwrap_or_default(),
        });
    }
    let ch = get_data(&card, 0x0065).unwrap_or_default();
    let text = |v: Option<&[u8]>| v.map(|b| String::from_utf8_lossy(b).into_owned()).filter(|s| !s.is_empty());
    let sec = get_data(&card, 0x007A).unwrap_or_default();
    let kdf = get_data(&card, 0x00F9).ok().and_then(|d| find(&d, 0x81).map(|a| a.first() == Some(&0x03))).unwrap_or(false);
    Ok(PgpStatus {
        version: aid.get(6..8).map(|v| format!("{}.{}", v[0], v[1])).unwrap_or_default(),
        serial: aid.get(10..14).map(crate::fido::hex).unwrap_or_default().to_uppercase(),
        name: text(find(&ch, 0x5B)).map(|n| n.replace("<<", " ").replace('<', " ")),
        language: text(find(&ch, 0x5F2D)),
        url: text(get_data(&card, 0x5F50).ok().as_deref()),
        signatures: find(&sec, 0x93).map(|c| c.iter().fold(0u32, |a, b| (a << 8) | *b as u32)).unwrap_or(0),
        user_pin_tries: pw.get(4).copied().unwrap_or(0),
        reset_code_tries: pw.get(5).copied().unwrap_or(0),
        admin_pin_tries: pw.get(6).copied().unwrap_or(0),
        kdf,
        keys,
    })
}

fn sw_err(e: String, what: &str) -> String {
    if e.contains("63C") || e.contains("6982") || e.contains("locked with a password") {
        format!("Wrong {what}.")
    } else if e.contains("6983") {
        format!("{what} is blocked.")
    } else {
        e
    }
}

fn no_kdf(card: &Card) -> R<()> {
    let kdf = get_data(card, 0x00F9).ok().and_then(|d| find(&d, 0x81).map(|a| a.first() == Some(&0x03))).unwrap_or(false);
    if kdf { Err("This card hashes PINs (KDF-DO). Change them with `gpg --card-edit` → passwd.".into()) } else { Ok(()) }
}

fn verify(card: &Card, p2: u8, pin: &str) -> R<()> {
    let mut c = vec![0x00, 0x20, 0x00, p2, pin.len() as u8];
    c.extend_from_slice(pin.as_bytes());
    card.apdu(&c).map(|_| ()).map_err(|e| sw_err(e, if p2 == 0x83 { "Admin PIN" } else { "PIN" }))
}

/// `admin`: change PW3 (Admin PIN, min 8) instead of PW1 (PIN, min 6).
pub fn change_pin(admin: bool, old: &str, new: &str) -> R<()> {
    let min = if admin { 8 } else { 6 };
    if new.len() < min || new.len() > 127 {
        return Err(format!("The new {} must be {min}–127 characters.", if admin { "Admin PIN" } else { "PIN" }));
    }
    let card = open()?;
    no_kdf(&card)?;
    let mut data = old.as_bytes().to_vec();
    data.extend_from_slice(new.as_bytes());
    let mut c = vec![0x00, 0x24, 0x00, if admin { 0x83 } else { 0x81 }, data.len() as u8];
    c.extend(data);
    card.apdu(&c).map(|_| ()).map_err(|e| sw_err(e, if admin { "Admin PIN" } else { "PIN" }))
}

/// Unblock/reset the user PIN with the Admin PIN.
pub fn reset_pin(admin_pin: &str, new: &str) -> R<()> {
    if new.len() < 6 || new.len() > 127 {
        return Err("The new PIN must be 6–127 characters.".into());
    }
    let card = open()?;
    no_kdf(&card)?;
    verify(&card, 0x83, admin_pin)?;
    let mut c = vec![0x00, 0x2C, 0x02, 0x81, new.len() as u8];
    c.extend_from_slice(new.as_bytes());
    card.apdu(&c).map(|_| ())
}

/// Cardholder name ("Given Surname") and public key URL. Empty clears.
pub fn set_cardholder(admin_pin: &str, name: &str, url: &str) -> R<()> {
    if name.len() > 39 || url.len() > 255 {
        return Err("Name must be ≤39 characters, URL ≤255.".into());
    }
    let card = open()?;
    no_kdf(&card)?;
    verify(&card, 0x83, admin_pin)?;
    // ISO 7501-1 style: Surname<<Given<Names
    let mut parts: Vec<&str> = name.split_whitespace().collect();
    let encoded = match parts.pop() {
        Some(last) if !parts.is_empty() => format!("{last}<<{}", parts.join("<")),
        Some(last) => last.to_string(),
        None => String::new(),
    };
    for (tag, v) in [(0x005Bu16, encoded.as_bytes()), (0x5F50, url.as_bytes())] {
        let [p1, p2] = tag.to_be_bytes();
        let mut c = vec![0x00, 0xDA, p1, p2, v.len() as u8];
        c.extend_from_slice(v);
        card.apdu(&c)?;
    }
    Ok(())
}

/// Erases keys and resets PINs to defaults (123456 / 12345678). Needs the Admin PIN unless it's blocked.
pub fn factory_reset(admin_pin: Option<&str>) -> R<()> {
    let card = open()?;
    if let Some(p) = admin_pin.filter(|p| !p.is_empty()) {
        verify(&card, 0x83, p)?;
    }
    card.apdu(&[0x00, 0xE6, 0x00, 0x00]).map_err(|e| sw_err(e, "Admin PIN"))?;
    card.apdu(&[0x00, 0x44, 0x00, 0x00]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        // 6E { 4F aid, 73 { C4 pw, C1 attr } }
        let mut app = vec![0x6E, 0x81, 0];
        let aid = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0xFF, 0xFE, 0x12, 0x34, 0x56, 0x78, 0, 0];
        let mut inner = vec![0x4F, 16];
        inner.extend(aid);
        let mut d73 = vec![0xC4, 7, 0, 127, 127, 127, 3, 0, 3, 0xC1, 9, 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let mut t73 = vec![0x73, d73.len() as u8];
        t73.append(&mut d73);
        inner.extend(t73);
        app[2] = inner.len() as u8;
        app.extend(inner);
        let body = find(&app, 0x6E).unwrap();
        assert_eq!(find(body, 0x4F).unwrap()[10..14], [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(find(body, 0xC4).unwrap()[4], 3);
        assert_eq!(algo(find(body, 0xC1).unwrap()), "ECDSA P-256");
        assert_eq!(algo(&[0x01, 0x10, 0x00, 0x00, 0x20, 0x00]), "RSA 4096");
        // two-byte tag
        assert_eq!(ber(&[0x5F, 0x50, 2, b'h', b'i']), vec![(0x5F50, &b"hi"[..])]);
    }

    /// Read-only: SELECT + GET DATA against the plugged-in key.
    #[test]
    #[ignore]
    fn live_status() {
        println!("{:?}", status());
    }
}
