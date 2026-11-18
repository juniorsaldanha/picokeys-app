//! Pico Vault (pico-fido 8.2+): moves a passkey between keys enrolled in the same vault as an
//! encrypted PKV1 package. Enrolling needs the vendor's licensed `pico_vault_enroller`, so the
//! app only reads the status and exports/imports packages.
use crate::ctap::{enc, int, pin_auth, status_text, token, transact};
use crate::fido::{hex, unhex};
use ciborium::Value;
use ctap_hid_fido2::fidokey::pin::Permission;
use std::time::Duration;
use types::VaultStatus;

type R<T> = Result<T, String>;

const CTAPHID_VENDOR_CBOR: u8 = 0xC1; // CTAPHID_VENDOR_FIRST + 1
const VENDOR_VAULT: u8 = 0x05;

/// Request bytes: VENDOR_VAULT || {1: sub, 2: params, 3: proto, 4: pinUvAuth}. The PIN auth
/// covers 0xFF*32 || 0x0D || sub || encoded params, with the acfg permission.
fn request(sub: u8, params: Option<Value>, auth: Option<(u8, &[u8])>) -> R<Vec<u8>> {
    let raw = params.as_ref().map(enc).transpose()?.unwrap_or_default();
    let mut m = vec![(int(1), int(sub as u64))];
    if let Some(p) = params {
        m.push((int(2), p));
    }
    if let Some((proto, tok)) = auth {
        let mut msg = vec![0xFF; 32];
        msg.extend([0x0D, sub]);
        msg.extend(&raw);
        m.push((int(3), int(proto as u64)));
        m.push((int(4), Value::Bytes(pin_auth(proto, tok, &msg))));
    }
    let mut data = vec![VENDOR_VAULT];
    data.extend(enc(&Value::Map(m))?);
    Ok(data)
}

fn call(path: &str, sub: u8, params: Option<Value>, pin: Option<&str>) -> R<Vec<(Value, Value)>> {
    let auth = pin.map(|p| token(path, p, Permission::AuthenticatorConfiguration)).transpose()?;
    let data = request(sub, params, auth.as_ref().map(|(p, t)| (*p, t.as_slice())))?;
    let (_, rsp) = transact(path, CTAPHID_VENDOR_CBOR, &data, Duration::from_secs(30))
        .map_err(|e| if e.contains("0x01") { "This firmware has no Pico Vault (needs Pico FIDO 8.2 or newer).".into() } else { e })?;
    match rsp.split_first() {
        Some((0, [])) | None => Ok(vec![]),
        Some((0, body)) => match ciborium::from_reader(body).map_err(|e| e.to_string())? {
            Value::Map(m) => Ok(m),
            _ => Err("Unexpected Vault reply".into()),
        },
        Some((0x2E, _)) if sub == 4 => Err("Couldn't export: the key isn't enrolled in a vault, or the passkey is gone.".into()),
        Some((0x3C, _)) if sub == 5 => Err("Couldn't import: the package is damaged or from a different vault.".into()),
        Some((s, _)) => Err(status_text(*s)),
    }
}

fn field(m: &[(Value, Value)], k: u64) -> Option<&Value> {
    m.iter().find(|(key, _)| *key == int(k)).map(|(_, v)| v)
}

pub fn status(path: &str) -> R<VaultStatus> {
    let m = call(path, 1, None, None)?;
    let id = match field(&m, 1) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => vec![],
    };
    let label = match field(&m, 5) {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    };
    Ok(VaultStatus { enrolled: !id.is_empty(), label, id: hex(&id) })
}

/// The PKV1 package for one passkey (default profile, ChaCha20-Poly1305).
pub fn export(path: &str, pin: &str, cred_id: &str) -> R<Vec<u8>> {
    let params = Value::Map(vec![(int(1), Value::Bytes(unhex(cred_id)?))]);
    match field(&call(path, 4, Some(params), Some(pin))?, 1) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err("The key returned no package.".into()),
    }
}

pub fn import(path: &str, pin: &str, package: &[u8]) -> R<()> {
    if !package.starts_with(b"PKV\x01") {
        return Err("Not a Pico Vault package (.pkv).".into());
    }
    call(path, 5, Some(Value::Map(vec![(int(1), Value::Bytes(package.to_vec()))])), Some(pin)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        // status: no params, no auth
        assert_eq!(request(1, None, None).unwrap(), [0x05, 0xA1, 0x01, 0x01]);
        // export: auth covers the encoded params map
        let p = Value::Map(vec![(int(1), Value::Bytes(vec![0xAB]))]);
        let r = request(4, Some(p), Some((2, &[7; 32]))).unwrap();
        let raw = [0xA1, 0x01, 0x41, 0xAB];
        let mut msg = vec![0xFF; 32];
        msg.extend([0x0D, 4]);
        msg.extend(raw);
        let mut want = vec![0x05, 0xA4, 0x01, 0x04, 0x02];
        want.extend(raw);
        want.extend([0x03, 0x02, 0x04, 0x58, 0x20]);
        want.extend(pin_auth(2, &[7; 32], &msg));
        assert_eq!(r, want);
    }

    #[test]
    #[ignore = "needs a key"]
    fn live_status() {
        let d = crate::fido::list_devices().into_iter().next().expect("no key");
        println!("{:?}", status(&d.path));
    }
}
