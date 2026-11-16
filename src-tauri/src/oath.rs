//! OATH (TOTP/HOTP) over CCID using the YKOATH protocol, as implemented by
//! pico-fido `src/fido/oath.c`.
use crate::pico::Card;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{NewOath, OathAccount, OathAlg};

type R<T> = Result<T, String>;

const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_T_RESPONSE: u8 = 0x76;
const TAG_NO_RESPONSE: u8 = 0x77;
const TAG_PROPERTY: u8 = 0x78;
const TAG_IMF: u8 = 0x7A;
const TAG_TOUCH: u8 = 0x7C;

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RENAME: u8 = 0x05;
const INS_VALIDATE: u8 = 0xA3;
const TAG_RESPONSE: u8 = 0x75;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_CALC_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;

const TYPE_HOTP: u8 = 0x10;
const PROP_TOUCH: u8 = 0x02;

/// Access key derived from the OATH password, kept in memory after unlock (never the password).
static KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// YKOATH: PBKDF2-HMAC-SHA1(password, device id, 1000 rounds, 16 bytes).
fn derive(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut k = vec![0u8; 16];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA1, std::num::NonZeroU32::new(1000).unwrap(), salt, password.as_bytes(), &mut k);
    k
}

fn hmac1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key), msg).as_ref().to_vec()
}

fn validate(card: &Card, key: &[u8], challenge: &[u8]) -> R<()> {
    let mut mine = [0u8; 8];
    getrandom::fill(&mut mine).map_err(|e| e.to_string())?;
    let mut data = vec![];
    tlv(&mut data, TAG_RESPONSE, &hmac1(key, challenge));
    tlv(&mut data, TAG_CHALLENGE, &mine);
    let rsp = card.apdu(&apdu(INS_VALIDATE, 0, &data)).map_err(|_| "Wrong password.".to_string())?;
    // The key proves it knows the password too.
    match tlvs(&rsp).find(|(t, _)| *t == TAG_RESPONSE) {
        Some((_, r)) if r == hmac1(key, &mine) => Ok(()),
        Some(_) => Err("The key's reply didn't verify.".into()),
        None => Ok(()),
    }
}

/// SELECT, then VALIDATE with the remembered key if the applet is password-protected.
fn open() -> R<Card> {
    let card = Card::open()?;
    let sel = card.select_aid(&AID)?;
    if let Some((_, chal)) = tlvs(&sel).find(|(t, _)| *t == TAG_CHALLENGE) {
        let key = KEY.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or("OATH_LOCKED")?;
        if let Err(e) = validate(&card, &key, chal) {
            *KEY.lock().unwrap_or_else(|p| p.into_inner()) = None;
            return Err(if e == "Wrong password." { "OATH_LOCKED".into() } else { e });
        }
    }
    Ok(card)
}

fn device_id(sel: &[u8]) -> R<Vec<u8>> {
    tlvs(sel).find(|(t, _)| *t == TAG_NAME).map(|(_, v)| v.to_vec()).ok_or_else(|| "The key didn't report an OATH device id.".into())
}

/// Checks the password and remembers the derived key for this app session.
pub fn unlock(password: &str) -> R<()> {
    let card = Card::open()?;
    let sel = card.select_aid(&AID)?;
    let Some((_, chal)) = tlvs(&sel).find(|(t, _)| *t == TAG_CHALLENGE) else { return Ok(()) };
    let key = derive(password, &device_id(&sel)?);
    validate(&card, &key, chal)?;
    *KEY.lock().unwrap_or_else(|p| p.into_inner()) = Some(key);
    Ok(())
}

pub fn lock() {
    *KEY.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// Whether the applet has a password (true) — independent of whether we're unlocked.
pub fn protected() -> R<bool> {
    let card = Card::open()?;
    Ok(tlvs(&card.select_aid(&AID)?).any(|(t, _)| t == TAG_CHALLENGE))
}

/// Set, change (`Some`) or remove (`None`) the OATH password. Needs a prior unlock if one is set.
pub fn set_password(new: Option<&str>) -> R<()> {
    let card = open()?;
    let sel = card.select_aid(&AID)?;
    // re-SELECT reset validation; validate again on this fresh session
    if let Some((_, chal)) = tlvs(&sel).find(|(t, _)| *t == TAG_CHALLENGE) {
        let key = KEY.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or("OATH_LOCKED")?;
        validate(&card, &key, chal)?;
    }
    match new.filter(|p| !p.is_empty()) {
        None => {
            card.apdu(&[0x00, INS_SET_CODE, 0x00, 0x00])?;
            lock();
        }
        Some(pw) => {
            let key = derive(pw, &device_id(&sel)?);
            let mut chal = [0u8; 8];
            getrandom::fill(&mut chal).map_err(|e| e.to_string())?;
            let mut k = vec![0x21]; // TOTP | HMAC-SHA1
            k.extend_from_slice(&key);
            let mut data = vec![];
            tlv(&mut data, TAG_KEY, &k);
            tlv(&mut data, TAG_CHALLENGE, &chal);
            tlv(&mut data, TAG_RESPONSE, &hmac1(&key, &chal));
            card.apdu(&apdu(INS_SET_CODE, 0, &data))?;
            *KEY.lock().unwrap_or_else(|p| p.into_inner()) = Some(key);
        }
    }
    Ok(())
}

pub fn rename(old: &str, new: &str) -> R<()> {
    if new.is_empty() || new.len() > 64 {
        return Err("Name must be 1–64 bytes.".into());
    }
    let mut data = vec![];
    tlv(&mut data, TAG_NAME, old.as_bytes());
    tlv(&mut data, TAG_NAME, new.as_bytes());
    open()?.apdu(&apdu(INS_RENAME, 0, &data)).map(|_| ())
}

pub(crate) fn tlvs(d: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut i = 0;
    std::iter::from_fn(move || {
        let (&tag, &len) = (d.get(i)?, d.get(i + 1)?);
        let v = d.get(i + 2..i + 2 + len as usize)?;
        i += 2 + len as usize;
        Some((tag, v))
    })
}

fn tlv(out: &mut Vec<u8>, tag: u8, v: &[u8]) {
    out.push(tag);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
}

fn apdu(ins: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut c = vec![0x00, ins, 0x00, p2, data.len() as u8];
    c.extend_from_slice(data);
    c
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Split a YKOATH name `[period/]issuer:account`.
fn parse_name(name: &str) -> (u32, Option<String>, String) {
    let (period, rest) = match name.split_once('/') {
        Some((p, r)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (p.parse().unwrap_or(30), r),
        _ => (30, name),
    };
    match rest.split_once(':') {
        Some((i, a)) => (period, Some(i.to_string()), a.to_string()),
        None => (period, None, rest.to_string()),
    }
}

/// Truncated response `[digits, 4 bytes]` → zero-padded code.
fn format_code(v: &[u8]) -> Option<String> {
    let (&digits, b) = v.split_first()?;
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) & 0x7FFF_FFFF;
    Some(format!("{:0width$}", n % 10u32.pow(digits as u32), width = digits as usize))
}

pub fn list() -> R<Vec<OathAccount>> {
    let card = open()?;
    let listing = card.apdu_chained(&apdu(INS_LIST, 0, &[]), INS_SEND_REMAINING)?;
    let mut accounts: Vec<OathAccount> = tlvs(&listing)
        .filter(|(t, v)| *t == TAG_NAME_LIST && v.len() > 1)
        .map(|(_, v)| {
            let name = String::from_utf8_lossy(&v[1..]).into_owned();
            let (period, issuer, account) = parse_name(&name);
            OathAccount {
                hotp: v[0] & 0xF0 == TYPE_HOTP,
                algorithm: match v[0] & 0x0F {
                    2 => OathAlg::Sha256,
                    3 => OathAlg::Sha512,
                    _ => OathAlg::Sha1,
                },
                digits: 6,
                period,
                touch: false,
                code: None,
                name,
                issuer,
                account,
            }
        })
        .collect();

    // CALCULATE ALL uses one challenge (30 s steps); accounts with another period are computed individually.
    let mut chal = vec![];
    tlv(&mut chal, TAG_CHALLENGE, &(now() / 30).to_be_bytes());
    let calc = card.apdu_chained(&apdu(INS_CALC_ALL, 1, &chal), INS_SEND_REMAINING)?;
    let mut it = tlvs(&calc);
    while let (Some((TAG_NAME, n)), Some((tag, v))) = (it.next(), it.next()) {
        let name = String::from_utf8_lossy(n);
        let Some(a) = accounts.iter_mut().find(|a| a.name == name) else { continue };
        if let Some(&d) = v.first() {
            a.digits = d;
        }
        match tag {
            TAG_T_RESPONSE if a.period == 30 => a.code = format_code(v),
            TAG_T_RESPONSE => a.code = calculate_with(&card, &a.name, a.period).ok(),
            TAG_TOUCH => a.touch = true,
            TAG_NO_RESPONSE => {}
            _ => {}
        }
    }
    Ok(accounts)
}

fn calculate_with(card: &Card, name: &str, period: u32) -> R<String> {
    let mut data = vec![];
    tlv(&mut data, TAG_NAME, name.as_bytes());
    tlv(&mut data, TAG_CHALLENGE, &(now() / period.max(1) as u64).to_be_bytes());
    let rsp = card.apdu(&apdu(INS_CALCULATE, 1, &data))?;
    tlvs(&rsp)
        .find(|(t, _)| *t == TAG_T_RESPONSE)
        .and_then(|(_, v)| format_code(v))
        .ok_or_else(|| "Unexpected response".into())
}

/// Single code: HOTP (bumps the counter) or touch-required TOTP (waits for touch).
pub fn calculate(name: &str) -> R<String> {
    let card = open()?;
    calculate_with(&card, name, parse_name(name).0)
}

pub fn add(n: &NewOath) -> R<()> {
    let secret = base32_decode(&n.secret).ok_or("Secret isn't valid Base32.")?;
    if secret.is_empty() {
        return Err("Secret is empty.".into());
    }
    if !(6..=8).contains(&n.digits) {
        return Err("Digits must be 6, 7 or 8.".into());
    }
    let name = n.key_name();
    if name.is_empty() || name.len() > 64 {
        return Err("Name must be 1–64 bytes.".into());
    }
    let alg = match n.algorithm {
        OathAlg::Sha1 => 1,
        OathAlg::Sha256 => 2,
        OathAlg::Sha512 => 3,
    };
    // HMAC keys shorter than the block size are zero-padded by HMAC anyway; long ones are pre-hashed by
    // the authenticator. ponytail: we don't pre-hash >64-byte secrets (YKOATH clients do); rare in practice.
    let mut key = vec![(if n.hotp { TYPE_HOTP } else { 0x20 }) | alg, n.digits];
    key.extend_from_slice(&secret);
    let mut data = vec![];
    tlv(&mut data, TAG_NAME, name.as_bytes());
    tlv(&mut data, TAG_KEY, &key);
    if n.touch {
        data.extend_from_slice(&[TAG_PROPERTY, PROP_TOUCH]); // YKOATH: property is tag+value, no length
    }
    if n.hotp && n.counter > 0 {
        tlv(&mut data, TAG_IMF, &n.counter.to_be_bytes());
    }
    open()?.apdu(&apdu(INS_PUT, 0, &data)).map(|_| ())
}

pub fn delete(name: &str) -> R<()> {
    let mut data = vec![];
    tlv(&mut data, TAG_NAME, name.as_bytes());
    open()?.apdu(&apdu(INS_DELETE, 0, &data)).map(|_| ())
}

/// RFC 4648 Base32, case-insensitive, ignoring spaces, dashes and padding.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = vec![];
    let (mut buf, mut bits) = (0u32, 0u8);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(base32_decode("JBSWY3DPEHPK3PXP").unwrap(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(base32_decode("jbsw y3dp").unwrap(), b"Hello");
        assert!(base32_decode("1!").is_none());
        assert_eq!(parse_name("60/GitHub:alice"), (60, Some("GitHub".into()), "alice".into()));
        assert_eq!(parse_name("a/b:c"), (30, Some("a/b".into()), "c".into()));
        assert_eq!(parse_name("plain"), (30, None, "plain".into()));
        // RFC 4226 test vector: count 0 → 755224 (truncated value 0x4c93cf18)
        assert_eq!(format_code(&[6, 0x4c, 0x93, 0xcf, 0x18]).unwrap(), "755224");
        assert_eq!(format_code(&[8, 0x00, 0x00, 0x00, 0x07]).unwrap(), "00000007");
        let mut it = tlvs(&[0x71, 2, b'a', b'b', 0x76, 1]);
        assert_eq!(it.next(), Some((0x71, &b"ab"[..])));
        assert_eq!(it.next(), None); // truncated TLV stops cleanly
        // openssl kdf -keylen 16 -kdfopt digest:SHA1 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:1000 PBKDF2
        assert_eq!(crate::fido::hex(&derive("password", b"salt")), "6e88be8bad7eae9d9e10aa061224034f");
        // RFC 2202 HMAC-SHA1 test case 2
        assert_eq!(crate::fido::hex(&hmac1(b"Jefe", b"what do ya want for nothing?")), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    /// Adds, reads and deletes a throwaway account on the connected key.
    /// `cargo test -p picokeys-app -- --ignored oath_roundtrip --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn oath_roundtrip() {
        let n = NewOath { issuer: "PicoKeyManagerTest".into(), account: "probe".into(), secret: "JBSWY3DPEHPK3PXP".into(), ..Default::default() };
        add(&n).unwrap();
        let all = list().unwrap();
        println!("{all:#?}");
        let a = all.iter().find(|a| a.name == n.key_name()).expect("added account listed");
        assert_eq!(a.code.as_ref().map(|c| c.len()), Some(6));
        delete(&n.key_name()).unwrap();
        assert!(list().unwrap().iter().all(|a| a.name != n.key_name()));
    }
}
