//! Raw CTAPHID transport + authenticatorConfig, for what ctap-hid-fido2 doesn't expose:
//! pico-fido's vendor config subcommands (0xFF) and per-credential controls.
use ciborium::Value;
use ctap_hid_fido2::fidokey::pin::Permission;
use std::ffi::CString;
use std::time::{Duration, Instant};

type R<T> = Result<T, String>;

const CTAPHID_INIT: u8 = 0x86;
pub(crate) const CTAPHID_CBOR: u8 = 0x90;
const CTAPHID_KEEPALIVE: u8 = 0xBB;
const CTAPHID_ERROR: u8 = 0xBF;

// pico-fido vendor config ids (src/fido/ctap.h)
const NORK: u64 = 0x00052b41f53590d3;
const MCUV_NOTRQD: u64 = 0x000377913e17951f;
const PIN_POLICY: u64 = 0x0007d70fe96c3897;
const CRED_EXPIRE: u64 = 0x0004e532e1feb2fd;
const CRED_REVOKE: u64 = 0x0005961ecba040f9;
const CRED_BUTTON: u64 = 0x0005abc39033a930;

/// One CTAPHID request/response on a fresh channel. Returns (CTAPHID cmd, body).
pub(crate) fn transact(path: &str, cmd: u8, data: &[u8], timeout: Duration) -> R<(u8, Vec<u8>)> {
    let api = hidapi::HidApi::new().map_err(|e| e.to_string())?;
    let dev = api.open_path(&CString::new(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let write = |pkt: &[u8; 65]| dev.write(pkt).map(|_| ()).map_err(|e| e.to_string());
    let send = |cid: [u8; 4], cmd: u8, data: &[u8]| -> R<()> {
        let mut pkt = [0u8; 65]; // report id 0 + 64
        pkt[1..5].copy_from_slice(&cid);
        pkt[5] = cmd;
        pkt[6..8].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let first = data.len().min(57);
        pkt[8..8 + first].copy_from_slice(&data[..first]);
        write(&pkt)?;
        for (seq, chunk) in data[first..].chunks(59).enumerate() {
            let mut pkt = [0u8; 65];
            pkt[1..5].copy_from_slice(&cid);
            pkt[5] = seq as u8;
            pkt[6..6 + chunk.len()].copy_from_slice(chunk);
            write(&pkt)?;
        }
        Ok(())
    };
    let recv = |cid: [u8; 4], deadline: Instant| -> R<(u8, Vec<u8>)> {
        let mut buf = [0u8; 64];
        let read = |buf: &mut [u8; 64]| -> R<()> {
            loop {
                if Instant::now() > deadline {
                    return Err("Timed out waiting for the key.".into());
                }
                let n = dev.read_timeout(buf, 250).map_err(|e| e.to_string())?;
                if n >= 5 && buf[0..4] == cid && buf[4] != CTAPHID_KEEPALIVE {
                    return Ok(());
                }
            }
        };
        read(&mut buf)?;
        let cmd = buf[4];
        let len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        let mut out = buf[7..7 + len.min(57)].to_vec();
        while out.len() < len {
            read(&mut buf)?;
            let take = (len - out.len()).min(59);
            out.extend_from_slice(&buf[5..5 + take]);
        }
        Ok((cmd, out))
    };

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    send([0xFF; 4], CTAPHID_INIT, &nonce)?;
    let (_, init) = recv([0xFF; 4], Instant::now() + Duration::from_secs(2))?;
    if init.len() < 12 || init[..8] != nonce {
        return Err("CTAPHID init failed".into());
    }
    let cid: [u8; 4] = init[8..12].try_into().unwrap();
    send(cid, cmd, data)?;
    let (c, rsp) = recv(cid, Instant::now() + timeout)?;
    if c == CTAPHID_ERROR {
        return Err(format!("CTAPHID error 0x{:02X}", rsp.first().copied().unwrap_or(0)));
    }
    Ok((c, rsp))
}

pub(crate) fn status_text(s: u8) -> String {
    match s {
        0x27 => "The key denied the operation.".into(),
        0x2E => "No passkey with that ID on the key.".into(),
        0x2F => "No touch detected. Try again and touch the key when it blinks.".into(),
        0x30 => "Not allowed by the key right now.".into(),
        0x31 | 0x33 => "Wrong PIN.".into(),
        0x32 => "PIN blocked. Reset the key to use it again.".into(),
        0x34 => "PIN blocked until the key is replugged.".into(),
        0x37 => "The PIN doesn't meet the key's PIN policy.".into(),
        0x3E => "This firmware doesn't support that command.".into(),
        s => format!("The key returned CTAP error 0x{s:02X}."),
    }
}

/// CTAP2 command over CTAPHID_CBOR; returns the CBOR body or a readable error.
pub(crate) fn cbor(path: &str, ctap_cmd: u8, params: Option<&Value>, timeout: Duration) -> R<Vec<u8>> {
    let mut data = vec![ctap_cmd];
    if let Some(p) = params {
        ciborium::into_writer(p, &mut data).map_err(|e| e.to_string())?;
    }
    let (_, rsp) = transact(path, CTAPHID_CBOR, &data, timeout)?;
    match rsp.split_first() {
        Some((0, body)) => Ok(body.to_vec()),
        Some((s, _)) => Err(status_text(*s)),
        None => Err("Empty reply from the key.".into()),
    }
}

pub(crate) fn int(n: u64) -> Value {
    Value::Integer(n.into())
}

fn enc(v: &Value) -> R<Vec<u8>> {
    let mut b = vec![];
    ciborium::into_writer(v, &mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

/// pinUvAuthParam = HMAC-SHA256(token, msg), truncated to 16 bytes for protocol 1.
pub(crate) fn pin_auth(proto: u8, token: &[u8], msg: &[u8]) -> Vec<u8> {
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token), msg);
    let t = tag.as_ref();
    if proto == 1 { t[..16].to_vec() } else { t.to_vec() }
}

pub(crate) fn token(path: &str, pin: &str, perm: Permission) -> R<(u8, Vec<u8>)> {
    let key = crate::fido::open(path)?;
    let t = key.get_pinuv_auth_token_with_permission(pin, perm).map_err(|e| crate::fido::pin_err(&e.to_string()))?;
    Ok((key.pin_protocol_version, t.key))
}

/// authenticatorConfig (0x0D) with the acfg permission.
fn config(path: &str, pin: &str, sub: u8, params: Option<Value>) -> R<()> {
    let (proto, tok) = token(path, pin, Permission::AuthenticatorConfiguration)?;
    let mut msg = vec![0xFF; 32];
    msg.extend([0x0D, sub]);
    if let Some(p) = &params {
        msg.extend(enc(p)?);
    }
    let mut m = vec![(int(1), int(sub as u64))];
    if let Some(p) = params {
        m.push((int(2), p));
    }
    m.push((int(3), int(proto as u64)));
    m.push((int(4), Value::Bytes(pin_auth(proto, &tok, &msg))));
    cbor(path, 0x0D, Some(&Value::Map(m)), Duration::from_secs(30)).map(|_| ())
}

fn vendor(path: &str, pin: &str, id: u64, bytes: Option<Vec<u8>>, n: Option<u64>, b: Option<bool>) -> R<()> {
    let mut p = vec![(int(1), int(id))];
    if let Some(x) = bytes {
        p.push((int(2), Value::Bytes(x)));
    }
    if let Some(x) = n {
        p.push((int(3), int(x)));
    }
    if let Some(x) = b {
        p.push((int(5), Value::Bool(x)));
    }
    config(path, pin, 0xFF, Some(Value::Map(p)))
}

pub fn toggle_always_uv(path: &str, pin: &str) -> R<()> {
    config(path, pin, 0x02, None)
}

pub fn enable_enterprise_attestation(path: &str, pin: &str) -> R<()> {
    config(path, pin, 0x01, None)
}

/// setMinPINLength. `len` 0 keeps the current minimum (it can only go up).
pub fn set_min_pin(path: &str, pin: &str, len: u32, rp_ids: &[String], force_change: bool) -> R<()> {
    let mut p = vec![];
    if len > 0 {
        p.push((int(1), int(len as u64)));
    }
    if !rp_ids.is_empty() {
        p.push((int(2), Value::Array(rp_ids.iter().map(|r| Value::Text(r.clone())).collect())));
    }
    if force_change {
        p.push((int(3), Value::Bool(true)));
    }
    config(path, pin, 0x03, Some(Value::Map(p)))
}

/// "nork": discoverable credentials off/on; "mcuv": makeCredUvNotRqd. Both toggle.
pub fn toggle(path: &str, pin: &str, which: &str) -> R<()> {
    let id = match which {
        "nork" => NORK,
        "mcuv" => MCUV_NOTRQD,
        _ => return Err("Unknown option".into()),
    };
    vendor(path, pin, id, None, None, None)
}

/// Required character classes for new PINs: 1 upper, 2 lower, 4 digit, 8 symbol (0 = none).
pub fn pin_policy(path: &str, pin: &str, bits: u16) -> R<()> {
    vendor(path, pin, PIN_POLICY, None, Some((bits & 0x0F) as u64), None)
}

fn cred(id_hex: &str) -> R<Vec<u8>> {
    let id = crate::fido::unhex(id_hex)?;
    if id.len() != 42 {
        return Err("Only passkeys created by Pico FIDO 8+ can be managed this way.".into());
    }
    Ok(id)
}

pub fn revoke(path: &str, pin: &str, cred_id: &str) -> R<()> {
    vendor(path, pin, CRED_REVOKE, Some(cred(cred_id)?), None, None)
}

/// Expire a passkey at `unix` seconds (0 clears). Syncs the key's clock first: it's lost on power-off.
pub fn expire(path: &str, pin: &str, cred_id: &str, unix: u32) -> R<()> {
    crate::pico::set_time()?;
    vendor(path, pin, CRED_EXPIRE, Some(cred(cred_id)?), Some(unix as u64), None)
}

/// Require (true) or skip (false) the touch for this passkey.
pub fn button(path: &str, pin: &str, cred_id: &str, touch: bool) -> R<()> {
    vendor(path, pin, CRED_BUTTON, Some(cred(cred_id)?), None, Some(touch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        // {1: 0xFF, 2: {1: NORK}} is canonical CBOR with the 8-byte uint form.
        let v = Value::Map(vec![(int(1), int(0xFF)), (int(2), Value::Map(vec![(int(1), int(NORK))]))]);
        assert_eq!(crate::fido::hex(&enc(&v).unwrap()), "a20118ff02a1011b00052b41f53590d3");
        // RFC 4231 test case 2
        let mac = pin_auth(2, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(crate::fido::hex(&mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(pin_auth(1, b"Jefe", b"what do ya want for nothing?").len(), 16);
        assert!(cred("00").is_err());
    }

    /// Read-only: getInfo through our transport (multi-packet reply) + the key's clock.
    #[test]
    #[ignore]
    fn live_readonly() {
        let d = crate::fido::list_devices().into_iter().next().expect("plug in the key");
        let info = cbor(&d.path, 0x04, None, Duration::from_secs(5)).unwrap();
        let v: Value = ciborium::from_reader(&info[..]).unwrap();
        println!("getInfo {} bytes, options: {:?}", info.len(), v.as_map().unwrap().iter().find(|(k, _)| *k == int(4)).map(|(_, o)| o));
        println!("clock: {:?}", crate::pico::get_time());
    }
}
