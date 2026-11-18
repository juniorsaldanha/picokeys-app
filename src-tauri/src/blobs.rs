//! Large blobs (CTAP 2.1 authenticatorLargeBlobs): read the serialized array, decrypt each
//! entry with the passkeys' largeBlobKeys, delete entries.
use crate::ctap::{cbor, int, pin_auth, token};
use ciborium::Value;
use ctap_hid_fido2::fidokey::pin::Permission;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use std::time::Duration;
use types::{BlobEntry, LargeBlobs};

type R<T> = Result<T, String>;
const T: Duration = Duration::from_secs(10);

fn get(m: &Value, k: u64) -> Option<&Value> {
    m.as_map()?.iter().find(|(key, _)| *key == int(k)).map(|(_, v)| v)
}

fn as_u64(v: Option<&Value>) -> Option<u64> {
    v?.as_integer().and_then(|i| u64::try_from(i).ok())
}

fn parse(b: &[u8]) -> R<Value> {
    ciborium::from_reader(b).map_err(|e| format!("Bad CBOR from the key: {e}"))
}

/// (maxMsgSize, maxSerializedLargeBlobArray) from getInfo.
fn limits(path: &str) -> R<(usize, usize)> {
    let info = parse(&cbor(path, 0x04, None, T)?)?;
    Ok((as_u64(get(&info, 0x05)).unwrap_or(1200) as usize, as_u64(get(&info, 0x0B)).unwrap_or(0) as usize))
}

/// The whole serialized array (CBOR array || first 16 bytes of its SHA-256).
fn read_array(path: &str, frag: usize) -> R<Vec<u8>> {
    let mut out = vec![];
    loop {
        let req = Value::Map(vec![(int(1), int(frag as u64)), (int(3), int(out.len() as u64))]);
        let rsp = parse(&cbor(path, 0x0C, Some(&req), T)?)?;
        let chunk = get(&rsp, 1).and_then(Value::as_bytes).ok_or("No large blob data in reply")?;
        out.extend_from_slice(chunk);
        if chunk.len() < frag {
            return Ok(out);
        }
    }
}

fn split(array: &[u8]) -> R<Vec<Value>> {
    if array.len() < 17 || digest(&SHA256, &array[..array.len() - 16]).as_ref()[..16] != array[array.len() - 16..] {
        return Err("The large blob array on the key is corrupt.".into());
    }
    match parse(&array[..array.len() - 16])? {
        Value::Array(v) => Ok(v),
        _ => Err("The large blob array on the key is corrupt.".into()),
    }
}

/// AES-256-GCM open + raw DEFLATE inflate, per CTAP 2.1 §6.10.3.
fn decrypt(key: &[u8], entry: &Value) -> Option<Vec<u8>> {
    let ct = get(entry, 1)?.as_bytes()?;
    let nonce = get(entry, 2)?.as_bytes()?;
    let orig = as_u64(get(entry, 3))?;
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut ad = b"blob".to_vec();
    ad.extend(orig.to_le_bytes());
    let mut buf = ct.clone();
    let plain = k.open_in_place(Nonce::try_assume_unique_for_key(nonce).ok()?, Aad::from(ad), &mut buf).ok()?;
    miniz_oxide::inflate::decompress_to_vec(plain).ok()
}

/// credentialManagement (0x0A) with a cm token; params auth = HMAC(token, sub || params).
fn cm(path: &str, proto: u8, tok: &[u8], sub: u8, params: Option<Value>, auth: bool) -> R<Value> {
    let mut msg = vec![sub];
    let mut m = vec![(int(1), int(sub as u64))];
    if let Some(p) = params {
        ciborium::into_writer(&p, &mut msg).map_err(|e| e.to_string())?;
        m.push((int(2), p));
    }
    if auth {
        m.push((int(3), int(proto as u64)));
        m.push((int(4), Value::Bytes(pin_auth(proto, tok, &msg))));
    }
    let b = cbor(path, 0x0A, Some(&Value::Map(m)), T)?;
    if b.is_empty() { Ok(Value::Map(vec![])) } else { parse(&b) }
}

/// (label, largeBlobKey) for every passkey that has one.
fn blob_keys(path: &str, pin: &str) -> R<Vec<(String, Vec<u8>)>> {
    let (proto, tok) = token(path, pin, Permission::CredentialManagement)?;
    let first = match cm(path, proto, &tok, 0x02, None, true) {
        Ok(v) => v,
        Err(e) if e.contains("0x2E") || e.contains("No passkey") => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let total = as_u64(get(&first, 5)).unwrap_or(0);
    let mut rps = vec![first];
    for _ in 1..total {
        rps.push(cm(path, proto, &tok, 0x03, None, false)?);
    }
    let mut out = vec![];
    for rp in rps {
        let rp_id = get(&rp, 3).and_then(|r| get_text(r, "id")).unwrap_or_default();
        let Some(hash) = get(&rp, 4).and_then(Value::as_bytes).cloned() else { continue };
        let first = cm(path, proto, &tok, 0x04, Some(Value::Map(vec![(int(1), Value::Bytes(hash))])), true)?;
        let n = as_u64(get(&first, 9)).unwrap_or(1);
        let mut creds = vec![first];
        for _ in 1..n {
            creds.push(cm(path, proto, &tok, 0x05, None, false)?);
        }
        for c in creds {
            if let Some(k) = get(&c, 0x0B).and_then(Value::as_bytes) {
                let user = get(&c, 6).and_then(|u| get_text(u, "name")).unwrap_or_default();
                out.push((if user.is_empty() { rp_id.clone() } else { format!("{rp_id} · {user}") }, k.clone()));
            }
        }
    }
    Ok(out)
}

fn get_text(m: &Value, k: &str) -> Option<String> {
    m.as_map()?.iter().find(|(key, _)| key.as_text() == Some(k)).and_then(|(_, v)| v.as_text().map(String::from))
}

fn describe(i: usize, e: &Value, keys: &[(String, Vec<u8>)]) -> BlobEntry {
    let size = get(e, 1).and_then(Value::as_bytes).map(|b| b.len()).unwrap_or(0) as u32;
    let orig_size = as_u64(get(e, 3)).unwrap_or(0) as u32;
    let found = keys.iter().find_map(|(label, k)| decrypt(k, e).map(|p| (label.clone(), p)));
    let (owner, text, hex) = match found {
        Some((label, p)) => {
            let text = std::str::from_utf8(&p).ok().filter(|t| !t.chars().any(|c| c.is_control() && !c.is_whitespace())).map(String::from);
            (Some(label), text, crate::fido::hex(&p[..p.len().min(64)]))
        }
        None => (None, None, String::new()),
    };
    BlobEntry { index: i as u32, size, orig_size, owner, text, hex }
}

pub fn list(path: &str, pin: &str) -> R<LargeBlobs> {
    let (msg, max) = limits(path)?;
    let array = read_array(path, msg.saturating_sub(64).max(64))?;
    let entries = split(&array)?;
    let keys = blob_keys(path, pin)?;
    Ok(LargeBlobs { used: array.len() as u32, max: max as u32, entries: entries.iter().enumerate().map(|(i, e)| describe(i, e, &keys)).collect() })
}

/// Rewrites the array without entry `index` (fragmented writes, largeBlobWrite permission).
pub fn delete(path: &str, pin: &str, index: u32) -> R<()> {
    let (msg, _) = limits(path)?;
    let frag = msg.saturating_sub(64).max(64);
    let mut entries = split(&read_array(path, frag)?)?;
    if index as usize >= entries.len() {
        return Err("That entry is gone already. Refresh.".into());
    }
    entries.remove(index as usize);
    let mut data = vec![];
    ciborium::into_writer(&Value::Array(entries), &mut data).map_err(|e| e.to_string())?;
    let h = digest(&SHA256, &data);
    data.extend_from_slice(&h.as_ref()[..16]);

    let (proto, tok) = token(path, pin, Permission::LargeBlobWrite)?;
    for (n, chunk) in data.chunks(frag).enumerate() {
        let offset = (n * frag) as u32;
        let mut m = vec![0xFF; 32];
        m.extend([0x0C, 0x00]);
        m.extend(offset.to_le_bytes());
        m.extend(digest(&SHA256, chunk).as_ref());
        let mut req = vec![(int(2), Value::Bytes(chunk.to_vec())), (int(3), int(offset as u64))];
        if offset == 0 {
            req.push((int(4), int(data.len() as u64)));
        }
        req.push((int(5), Value::Bytes(pin_auth(proto, &tok, &m))));
        req.push((int(6), int(proto as u64)));
        cbor(path, 0x0C, Some(&Value::Map(req)), T)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_array_and_decrypt() {
        // The initial array every key ships with: 0x80 || LEFT(SHA-256(0x80), 16)
        let empty = crate::fido::unhex("8076be8b528d0075f7aae98d6fa57a6d3c").unwrap();
        assert!(split(&empty).unwrap().is_empty());
        assert!(split(&empty[..10]).is_err());

        // Round-trip an entry the way a client would write it.
        let key = [7u8; 32];
        let plain = b"hello large blob";
        let comp = miniz_oxide::deflate::compress_to_vec(plain, 6);
        let mut ad = b"blob".to_vec();
        ad.extend((plain.len() as u64).to_le_bytes());
        let mut ct = comp.clone();
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap())
            .seal_in_place_append_tag(Nonce::assume_unique_for_key([1; 12]), Aad::from(ad), &mut ct)
            .unwrap();
        let entry = Value::Map(vec![(int(1), Value::Bytes(ct)), (int(2), Value::Bytes(vec![1; 12])), (int(3), int(plain.len() as u64))]);
        assert_eq!(decrypt(&key, &entry).unwrap(), plain);
        assert!(decrypt(&[8u8; 32], &entry).is_none());
        let d = describe(0, &entry, &[("example.com".into(), key.to_vec())]);
        assert_eq!((d.owner.as_deref(), d.text.as_deref()), (Some("example.com"), Some("hello large blob")));
    }

    /// Read-only, no PIN: reads the array straight off the key.
    #[test]
    #[ignore]
    fn live_read_array() {
        let d = crate::fido::list_devices().into_iter().next().expect("plug in the key");
        let (msg, max) = limits(&d.path).unwrap();
        let a = read_array(&d.path, msg - 64).unwrap();
        println!("maxMsg {msg}, max array {max}, array {} bytes, {} entries", a.len(), split(&a).unwrap().len());
    }
}
