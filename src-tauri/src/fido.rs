//! FIDO2 (CTAP2 over USB HID) operations against a Pico FIDO key.
use ctap_hid_fido2::{
    FidoKeyHid, HidParam, LibCfg, get_fidokey_devices,
    public_key_credential_descriptor::PublicKeyCredentialDescriptor,
};
use types::{Device, FidoInfo, Passkey};

type R<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn cfg() -> LibCfg {
    let mut c = LibCfg::init();
    c.enable_keep_alive_msg = false; // the crate would print to stdout otherwise
    c
}

fn open(path: &str) -> R<FidoKeyHid> {
    FidoKeyHid::new(&[HidParam::Path(path.into())], &cfg()).map_err(err)
}

pub fn list_devices() -> Vec<Device> {
    let mut v: Vec<Device> = get_fidokey_devices()
        .into_iter()
        .filter_map(|d| match d.param {
            HidParam::Path(path) => Some(Device { path, product: d.product_string, vid: d.vid, pid: d.pid }),
            _ => None,
        })
        .collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v.dedup_by(|a, b| a.path == b.path);
    v
}

pub fn info(path: &str) -> R<FidoInfo> {
    let key = open(path)?;
    let i = key.get_info().map_err(err)?;
    let pin_set = i.options.iter().find(|(k, _)| k == "clientPin").map(|(_, v)| *v);
    let pin_retries = if pin_set == Some(true) { key.get_pin_retries().ok() } else { None };
    Ok(FidoInfo {
        firmware: fw_version(i.firmware_version),
        aaguid: hex(&i.aaguid),
        versions: i.versions,
        extensions: i.extensions,
        // entries come flattened as ("alg","-7"), ("type","public-key"), ...
        algorithms: i.algorithms.iter().filter(|(k, _)| k == "alg").map(|(_, a)| alg_name(a)).collect(),
        options: i.options,
        pin_set,
        pin_retries,
        min_pin_length: i.min_pin_length,
        remaining_passkeys: i.remaining_discoverable_credentials,
        max_msg_size: i.max_msg_size,
    })
}

pub fn set_pin(path: &str, new_pin: &str) -> R<()> {
    open(path)?.set_new_pin(new_pin).map_err(err)
}

pub fn change_pin(path: &str, current: &str, new_pin: &str) -> R<()> {
    open(path)?.change_pin(current, new_pin).map_err(err)
}

pub fn passkeys(path: &str, pin: &str) -> R<Vec<Passkey>> {
    let key = open(path)?;
    let mut out = vec![];
    for rp in key.credential_management_enumerate_rps(Some(pin)).map_err(err)? {
        let creds = key
            .credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash)
            .map_err(err)?;
        for c in creds {
            out.push(Passkey {
                rp_id: rp.public_key_credential_rp_entity.id.clone(),
                rp_name: rp.public_key_credential_rp_entity.name.clone(),
                user_name: c.public_key_credential_user_entity.name,
                user_display_name: c.public_key_credential_user_entity.display_name,
                cred_id: hex(&c.public_key_credential_descriptor.id),
                cred_protect: format!("{:?}", c.cred_protect),
            });
        }
    }
    Ok(out)
}

pub fn delete_passkey(path: &str, pin: &str, cred_id: &str) -> R<()> {
    let pkcd = PublicKeyCredentialDescriptor { id: unhex(cred_id)?, ctype: "public-key".into() };
    open(path)?.credential_management_delete_credential(Some(pin), pkcd).map_err(err)
}

pub fn wink(path: &str) -> R<()> {
    open(path)?.wink().map_err(err)
}

/// pico-fido reports firmware as 0xMMmm (e.g. 0x0702 = 7.2).
fn fw_version(v: u32) -> String {
    if v == 0 { "unknown".into() } else { format!("{}.{}", v >> 8, v & 0xff) }
}

fn alg_name(alg: &str) -> String {
    match alg {
        "-7" => "ES256",
        "-8" => "EdDSA",
        "-35" => "ES384",
        "-36" => "ES512",
        "-47" => "ES256K",
        "-257" => "RS256",
        other => other,
    }
    .into()
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> R<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err("invalid credential id".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(err))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_versions() {
        let b = vec![0x00, 0xab, 0xff, 0x10];
        assert_eq!(unhex(&hex(&b)).unwrap(), b);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
        assert_eq!(fw_version(0x0702), "7.2");
        assert_eq!(alg_name("-8"), "EdDSA");
    }

    /// Needs a key plugged in: `cargo test -p picokeys-app -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn probe_real_key() {
        let devs = list_devices();
        println!("{devs:#?}");
        let d = devs.first().expect("no FIDO key connected");
        println!("{:#?}", info(&d.path).unwrap());
    }
}
