//! OpenPGP card (Pico OpenPGP): status, PINs, cardholder data, factory reset.
//! SSH: the authentication key (generated on the card) is offered by the built-in agent.
//! Other key generation/import stays with gpg (`gpg --card-edit`).
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
        ssh: auth_key(&card).ok().flatten().map(|k| k.ssh_line(&format!("openpgp:{}", status_serial(&card)))),
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

// ---------- SSH with the authentication key ----------

/// Algorithms offered for the SSH (authentication) key, with their OpenPGP algorithm attributes.
pub const SSH_ALGOS: [(&str, &[u8]); 5] = [
    ("rsa2048", &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]),
    ("rsa3072", &[0x01, 0x0C, 0x00, 0x00, 0x20, 0x00]),
    ("rsa4096", &[0x01, 0x10, 0x00, 0x00, 0x20, 0x00]),
    ("ed25519", &[0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]),
    ("p256", &[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
];
const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Public part of the authentication key.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ed25519(Vec<u8>),
    /// Uncompressed point 04||X||Y.
    P256(Vec<u8>),
}

impl AuthKey {
    /// From the algorithm attributes (C3) and the 7F49 public key DO.
    fn parse(attr: &[u8], pk: &[u8]) -> R<Self> {
        let body = find(pk, 0x7F49).unwrap_or(pk);
        let oid = attr.get(1..).map(|o| o.strip_suffix(&[0xFF]).unwrap_or(o)).unwrap_or_default();
        match attr.first() {
            Some(0x01) => Ok(Self::Rsa {
                n: find(body, 0x81).ok_or("No RSA modulus in the key.")?.to_vec(),
                e: find(body, 0x82).ok_or("No RSA exponent in the key.")?.to_vec(),
            }),
            Some(0x16) if oid == OID_ED25519 => {
                let p = find(body, 0x86).ok_or("No public point in the key.")?;
                // some cards prefix the native point with 0x40
                Ok(Self::Ed25519(if p.len() == 33 && p[0] == 0x40 { &p[1..] } else { p }.to_vec()))
            }
            Some(0x13) if oid == OID_P256 => Ok(Self::P256(find(body, 0x86).ok_or("No public point in the key.")?.to_vec())),
            _ => Err(format!("SSH can't use this key type ({}). Generate an RSA, Ed25519 or P-256 key for SSH.", algo(attr))),
        }
    }

    pub fn ssh_type(&self) -> &'static str {
        match self {
            Self::Rsa { .. } => "ssh-rsa",
            Self::Ed25519(_) => "ssh-ed25519",
            Self::P256(_) => "ecdsa-sha2-nistp256",
        }
    }

    /// Public key blob as ssh puts it on the wire.
    pub fn blob(&self) -> Vec<u8> {
        use crate::agent::{mpint, put};
        let mut b = vec![];
        put(&mut b, self.ssh_type().as_bytes());
        match self {
            Self::Rsa { n, e } => {
                mpint(&mut b, e);
                mpint(&mut b, n);
            }
            Self::Ed25519(p) => put(&mut b, p),
            Self::P256(p) => {
                put(&mut b, b"nistp256");
                put(&mut b, p);
            }
        }
        b
    }

    /// `ssh-rsa AAAA… comment`
    pub fn ssh_line(&self, comment: &str) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        format!("{} {} {comment}", self.ssh_type(), B64.encode(self.blob()))
    }

    /// OpenPGP v4 fingerprint (RFC 4880 §12.2), as gpg computes it from the creation time.
    fn fingerprint(&self, created: u32) -> [u8; 20] {
        fn mpi(out: &mut Vec<u8>, v: &[u8]) {
            let v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
            let bits = v.first().map(|b| (v.len() * 8 - b.leading_zeros() as usize) as u16).unwrap_or(0);
            out.extend(bits.to_be_bytes());
            out.extend(v);
        }
        let mut body = vec![0x04];
        body.extend(created.to_be_bytes());
        match self {
            Self::Rsa { n, e } => {
                body.push(1);
                mpi(&mut body, n);
                mpi(&mut body, e);
            }
            Self::Ed25519(p) => {
                body.push(22);
                body.push(OID_ED25519.len() as u8);
                body.extend(OID_ED25519);
                mpi(&mut body, &[&[0x40u8][..], p].concat());
            }
            Self::P256(p) => {
                body.push(19);
                body.push(OID_P256.len() as u8);
                body.extend(OID_P256);
                mpi(&mut body, p);
            }
        }
        let mut data = vec![0x99];
        data.extend((body.len() as u16).to_be_bytes());
        data.extend(body);
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data).as_ref().try_into().unwrap()
    }
}

/// Extended-length APDU, so RSA-4096 keys and signatures fit in one exchange.
fn ext(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut c = vec![0x00, ins, p1, p2, 0x00];
    if !data.is_empty() {
        c.extend((data.len() as u16).to_be_bytes());
        c.extend_from_slice(data);
    }
    c.extend([0x00, 0x00]);
    c
}

/// The authentication key, or None if the slot is empty.
fn auth_key(card: &Card) -> R<Option<AuthKey>> {
    let attr = get_data(card, 0x00C3)?;
    match card.apdu(&ext(0x47, 0x81, 0x00, &[0xA4, 0x00])) {
        Ok(pk) => AuthKey::parse(&attr, &pk).map(Some),
        Err(e) if e.contains("6A88") => Ok(None),
        Err(e) => Err(e),
    }
}

fn status_serial(card: &Card) -> String {
    get_data(card, 0x004F).ok().and_then(|a| a.get(10..14).map(crate::fido::hex)).unwrap_or_default().to_uppercase()
}

/// Generates a new authentication key on the card (replacing any) and returns its SSH line.
pub fn ssh_generate(admin_pin: &str, algorithm: &str) -> R<String> {
    let attr = SSH_ALGOS.iter().find(|(n, _)| *n == algorithm).map(|(_, a)| *a).ok_or("Unknown key type.")?;
    let mut card = open()?;
    no_kdf(&card)?;
    let before = auth_key(&card).ok().flatten();
    verify(&card, 0x83, admin_pin)?;
    let mut put = vec![0x00, 0xDA, 0x00, 0xC3, attr.len() as u8];
    put.extend_from_slice(attr);
    card.apdu(&put).map_err(|e| {
        if e.contains("6A80") { "This card's firmware doesn't support that key type.".to_string() } else { e }
    })?;
    let key = match card.apdu(&ext(0x47, 0x80, 0x00, &[0xA4, 0x00])) {
        Ok(pk) => AuthKey::parse(attr, &pk)?,
        // macOS can drop the session during a minutes-long RSA generation, but the key still gets
        // made: reconnect, and if the slot holds a new key, finish setting it up.
        Err(e) => {
            drop(card);
            card = open()?;
            match auth_key(&card)? {
                Some(k) if Some(&k) != before.as_ref() => {
                    verify(&card, 0x83, admin_pin)?;
                    k
                }
                _ => return Err(e),
            }
        }
    };
    // fingerprint (C9) and creation time (D0), so gpg --card-status shows the key like one it made
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
    for (tag, v) in [(0xC9u8, key.fingerprint(created).to_vec()), (0xD0, created.to_be_bytes().to_vec())] {
        let mut c = vec![0x00, 0xDA, 0x00, tag, v.len() as u8];
        c.extend(v);
        card.apdu(&c)?;
    }
    Ok(key.ssh_line(&format!("openpgp:{}", status_serial(&card))))
}

/// DigestInfo prefixes for PKCS#1 v1.5 (RFC 8017 §9.2 note 1).
const DI_SHA1: &[u8] = &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14];
const DI_SHA256: &[u8] = &[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
const DI_SHA512: &[u8] = &[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

/// What INTERNAL AUTHENTICATE gets for `data`, and the SSH signature algorithm name.
/// `flags`: ssh-agent SIGN_REQUEST flags (2 = rsa-sha2-256, 4 = rsa-sha2-512).
fn sign_input(key: &AuthKey, data: &[u8], flags: u32) -> (Vec<u8>, &'static str) {
    use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA512, digest};
    match key {
        AuthKey::Rsa { .. } => {
            let (name, di, alg) = if flags & 4 != 0 {
                ("rsa-sha2-512", DI_SHA512, &SHA512)
            } else if flags & 2 != 0 {
                ("rsa-sha2-256", DI_SHA256, &SHA256)
            } else {
                ("ssh-rsa", DI_SHA1, &SHA1_FOR_LEGACY_USE_ONLY)
            };
            ([di, digest(alg, data).as_ref()].concat(), name)
        }
        AuthKey::Ed25519(_) => (data.to_vec(), "ssh-ed25519"),
        AuthKey::P256(_) => (digest(&SHA256, data).as_ref().to_vec(), "ecdsa-sha2-nistp256"),
    }
}

/// SSH signature blob from what the card returned.
fn ssh_sig(name: &str, raw: &[u8]) -> Vec<u8> {
    use crate::agent::{mpint, put};
    let mut out = vec![];
    put(&mut out, name.as_bytes());
    if name == "ecdsa-sha2-nistp256" {
        let (r, s) = raw.split_at(raw.len() / 2);
        let mut rs = vec![];
        mpint(&mut rs, r);
        mpint(&mut rs, s);
        put(&mut out, &rs);
    } else {
        put(&mut out, raw);
    }
    out
}

/// Signs `data` for ssh with the authentication key. Returns (public blob, signature blob).
pub fn ssh_sign(pin: &str, data: &[u8], flags: u32) -> R<(Vec<u8>, Vec<u8>)> {
    let card = open()?;
    no_kdf(&card)?;
    let key = auth_key(&card)?.ok_or("The card has no authentication key.")?;
    verify(&card, 0x82, pin)?;
    let (input, name) = sign_input(&key, data, flags);
    let raw = card.apdu(&ext(0x88, 0x00, 0x00, &input))?;
    Ok((key.blob(), ssh_sig(name, &raw)))
}

/// The authentication key's blob, for the agent's identity list (no PIN needed).
pub fn ssh_blob() -> R<Option<Vec<u8>>> {
    let card = open()?;
    Ok(auth_key(&card)?.map(|k| k.blob()))
}

/// Checks the PIN (PW1, the one for signing/authentication) without using the key.
pub fn check_pin(pin: &str) -> R<()> {
    let card = open()?;
    no_kdf(&card)?;
    verify(&card, 0x82, pin)
}

#[cfg(test)]
mod ssh_tests {
    use super::*;

    #[test]
    fn auth_key_formats() {
        // RSA from a 7F49 DO: blob = string("ssh-rsa") mpint(e) mpint(n)
        let pk = [&[0x7F, 0x49, 0x0A, 0x81, 0x03, 0xC1, 0x02, 0x03, 0x82, 0x03, 0x01, 0x00, 0x01][..]].concat();
        let k = AuthKey::parse(SSH_ALGOS[0].1, &pk).unwrap();
        assert_eq!(k, AuthKey::Rsa { n: vec![0xC1, 2, 3], e: vec![1, 0, 1] });
        let mut want = vec![0, 0, 0, 7];
        want.extend(b"ssh-rsa");
        want.extend([0, 0, 0, 3, 1, 0, 1, 0, 0, 0, 4, 0, 0xC1, 2, 3]);
        assert_eq!(k.blob(), want);
        assert!(k.ssh_line("c").starts_with("ssh-rsa AAAAB3NzaC1yc2E"));

        // Ed25519 point with and without the 0x40 prefix
        let p = [7u8; 32];
        let do_ = |pt: &[u8]| [&[0x7F, 0x49, (pt.len() + 2) as u8, 0x86, pt.len() as u8][..], pt].concat();
        assert_eq!(AuthKey::parse(SSH_ALGOS[3].1, &do_(&p)).unwrap(), AuthKey::Ed25519(p.to_vec()));
        assert_eq!(AuthKey::parse(SSH_ALGOS[3].1, &do_(&[&[0x40u8][..], &p].concat())).unwrap(), AuthKey::Ed25519(p.to_vec()));
        assert!(AuthKey::parse(&[0x12, 0x2B, 0x81, 0x04, 0x00, 0x22], &do_(&p)).is_err(), "ECDH isn't for ssh");

        // RSA signing input: DigestInfo + hash, picked by the agent flags
        let (i, n) = sign_input(&k, b"abc", 2);
        assert_eq!((n, i.len()), ("rsa-sha2-256", DI_SHA256.len() + 32));
        assert_eq!(sign_input(&k, b"abc", 4).1, "rsa-sha2-512");
        assert_eq!(sign_input(&k, b"abc", 0).1, "ssh-rsa");

        // ECDSA r||s -> string(name) string(mpint r, mpint s)
        let sig = ssh_sig("ecdsa-sha2-nistp256", &[[0x80u8; 32], [0x01u8; 32]].concat());
        assert_eq!(&sig[4..23], b"ecdsa-sha2-nistp256");
        assert_eq!(&sig[27..31], &[0, 0, 0, 33], "high bit set: mpint gets a 0x00 prefix");
    }
}

/// Against an emulated Pico OpenPGP with factory PINs (123456 / 12345678), e.g.
/// `ci/emulator/run.sh <pico_openpgp> cargo test -p picokeys-app -- --ignored openpgp_ --test-threads=1`
#[cfg(test)]
mod live {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use ring::signature::{self as sig, UnparsedPublicKey};

    const PIN: &str = "123456";
    const ADMIN: &str = "12345678";

    /// string(name) string(raw) -> (name, raw)
    fn split(blob: &[u8]) -> (String, Vec<u8>) {
        let n = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        let name = String::from_utf8(blob[4..4 + n].to_vec()).unwrap();
        let rest = &blob[4 + n..];
        let m = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        (name, rest[4..4 + m].to_vec())
    }

    /// ECDSA ssh signature body (mpint r, mpint s) -> fixed r||s.
    fn fixed_rs(body: &[u8]) -> Vec<u8> {
        let (r, rest) = {
            let n = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
            (&body[4..4 + n], &body[4 + n..])
        };
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let s = &rest[4..4 + n];
        let pad = |v: &[u8]| {
            let v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
            [vec![0; 32 - v.len()], v].concat()
        };
        [pad(r), pad(s)].concat()
    }

    #[test]
    #[ignore]
    fn openpgp_ssh_live() {
        check_pin(PIN).unwrap();
        assert!(check_pin("000000").is_err());
        check_pin(PIN).unwrap(); // reset the retry counter
        let msg = b"ssh session data to sign";
        for algo in ["rsa2048", "p256", "ed25519"] {
            let line = ssh_generate(ADMIN, algo).unwrap();
            println!("{algo}: {}", &line[..60.min(line.len())]);
            assert_eq!(status().unwrap().ssh.as_deref(), Some(line.as_str()));
            let blob = B64.decode(line.split(' ').nth(1).unwrap()).unwrap();
            assert_eq!(ssh_blob().unwrap().unwrap(), blob);
            let card = open().unwrap();
            let key = auth_key(&card).unwrap().unwrap();
            drop(card);
            for flags in [0u32, 2, 4] {
                let (pk, s) = ssh_sign(PIN, msg, flags).unwrap();
                assert_eq!(pk, blob);
                let (name, raw) = split(&s);
                match &key {
                    AuthKey::Rsa { n, e } => {
                        let (want, alg): (&str, &sig::RsaParameters) = match flags {
                            4 => ("rsa-sha2-512", &sig::RSA_PKCS1_2048_8192_SHA512),
                            2 => ("rsa-sha2-256", &sig::RSA_PKCS1_2048_8192_SHA256),
                            _ => ("ssh-rsa", &sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
                        };
                        assert_eq!(name, want);
                        sig::RsaPublicKeyComponents { n, e }.verify(alg, msg, &raw).unwrap();
                    }
                    AuthKey::P256(p) => {
                        assert_eq!(name, "ecdsa-sha2-nistp256");
                        UnparsedPublicKey::new(&sig::ECDSA_P256_SHA256_FIXED, p).verify(msg, &fixed_rs(&raw)).unwrap();
                    }
                    AuthKey::Ed25519(p) => {
                        assert_eq!(name, "ssh-ed25519");
                        UnparsedPublicKey::new(&sig::ED25519, p).verify(msg, &raw).unwrap();
                    }
                }
            }
        }
        assert!(ssh_generate("wrongadmin", "rsa2048").is_err());
    }

    /// Real ssh logins into sshd on 127.0.0.1:2222 through the built-in agent.
    #[test]
    #[ignore]
    fn openpgp_agent_login_live() {
        let home = std::env::var("HOME").unwrap();
        let sock = crate::agent::socket_path().unwrap();
        crate::agent::start().unwrap();
        assert!(crate::agent::set_pgp_pin(Some("000000".into())).is_err(), "wrong PIN refused");
        crate::agent::set_pgp_pin(Some(PIN.into())).unwrap();
        for (algo, pubkey_algos) in [
            ("rsa2048", "rsa-sha2-512"),
            ("rsa2048", "rsa-sha2-256"),
            ("p256", "ecdsa-sha2-nistp256"),
            ("ed25519", "ssh-ed25519"),
        ] {
            let line = ssh_generate(ADMIN, algo).unwrap();
            std::fs::write(format!("{home}/.ssh/authorized_keys"), format!("{line}\n")).unwrap();
            let out = std::process::Command::new("ssh")
                .args(["-p", "2222", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
                .args(["-o", &format!("IdentityAgent={}", sock.display()), "-o", &format!("PubkeyAcceptedAlgorithms={pubkey_algos}")])
                .args(["-o", "LogLevel=ERROR", "root@127.0.0.1", "echo logged-in"])
                .output()
                .unwrap();
            println!("{algo} via {pubkey_algos}: {} {}", String::from_utf8_lossy(&out.stdout).trim(), String::from_utf8_lossy(&out.stderr).trim());
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "logged-in", "{algo}/{pubkey_algos}");
        }
        let st = crate::agent::status().unwrap();
        assert!(st.pgp && st.keys.iter().any(|k| k.ends_with("openpgp-card")), "{:?}", st.keys);
        crate::agent::set_pgp_pin(None).unwrap();
        crate::agent::stop().unwrap();
    }
}
