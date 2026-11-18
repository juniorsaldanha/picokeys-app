//! Built-in ssh-agent for Pico security-key SSH keys. The agent signs via CTAP getAssertion, so
//! any ssh client (including Apple's, which ships without FIDO middleware) can use the keys.
//! Unix only: listens on ~/.ssh/pico-agent.sock.
// ponytail: no Windows named-pipe listener; Windows users use OpenSSH's own sk support.
#![cfg_attr(not(unix), allow(dead_code))]
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use types::AgentStatus;

type R<T> = Result<T, String>;

pub struct SkKey {
    /// Public key blob as ssh puts it on the wire.
    pub blob: Vec<u8>,
    pub kind: String,
    pub application: String,
    pub handle: Vec<u8>,
    pub flags: u8,
    pub comment: String,
}

// ---- SSH wire helpers ----

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (h, t) = self.0.split_at_checked(4)?;
        self.0 = t;
        Some(u32::from_be_bytes(h.try_into().ok()?))
    }
    fn u8(&mut self) -> Option<u8> {
        let (h, t) = self.0.split_first()?;
        self.0 = t;
        Some(*h)
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let (h, t) = self.0.split_at_checked(n)?;
        self.0 = t;
        Some(h)
    }
    fn str(&mut self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

pub(crate) fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Unsigned big-endian integer as an SSH mpint.
pub(crate) fn mpint(out: &mut Vec<u8>, v: &[u8]) {
    let v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
    let mut m = if v.first().is_some_and(|b| b & 0x80 != 0) { vec![0] } else { vec![] };
    m.extend(v);
    put(out, &m);
}

/// Parses an unencrypted OpenSSH private key file for an sk key.
pub fn parse_private(pem: &str) -> R<SkKey> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let raw = B64.decode(b64.trim()).map_err(|_| "Not an OpenSSH private key file.")?;
    let rest = raw.strip_prefix(b"openssh-key-v1\0").ok_or("Not an OpenSSH private key file.")?;
    let mut r = Rd(rest);
    let bad = || "Malformed key file.".to_string();
    let cipher = r.str().ok_or_else(bad)?;
    if cipher != "none" {
        return Err("Key file is passphrase-protected; the agent only loads unprotected key handles.".into());
    }
    r.str().ok_or_else(bad)?; // kdf
    r.bytes().ok_or_else(bad)?; // kdf options
    if r.u32() != Some(1) {
        return Err(bad());
    }
    let blob = r.bytes().ok_or_else(bad)?.to_vec();
    let mut p = Rd(r.bytes().ok_or_else(bad)?);
    if p.u32() != p.u32() {
        return Err(bad());
    }
    let kind = p.str().ok_or_else(bad)?;
    match kind.as_str() {
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            p.str().ok_or_else(bad)?; // curve
            p.bytes().ok_or_else(bad)?; // Q
        }
        "sk-ssh-ed25519@openssh.com" => {
            p.bytes().ok_or_else(bad)?; // pk
        }
        _ => return Err("Not a security-key SSH key.".into()),
    }
    let application = p.str().ok_or_else(bad)?;
    let flags = p.u8().ok_or_else(bad)?;
    let handle = p.bytes().ok_or_else(bad)?.to_vec();
    p.bytes().ok_or_else(bad)?; // reserved
    let comment = p.str().unwrap_or_default();
    Ok(SkKey { blob, kind, application, handle, flags, comment })
}

/// DER ECDSA signature -> (r, s).
fn der_rs(der: &[u8]) -> Option<(&[u8], &[u8])> {
    if *der.first()? != 0x30 {
        return None;
    }
    let mut i = 2 + if der.get(1)? & 0x80 != 0 { (der[1] & 0x7F) as usize } else { 0 };
    let mut int = || -> Option<&[u8]> {
        if *der.get(i)? != 0x02 {
            return None;
        }
        let n = *der.get(i + 1)? as usize;
        let v = der.get(i + 2..i + 2 + n)?;
        i += 2 + n;
        Some(v)
    };
    let r = int()?;
    let s = int()?;
    Some((r, s))
}

/// SSH signature blob from an assertion (authData = rpIdHash | flags | counter | ...).
pub fn ssh_signature(kind: &str, auth_data: &[u8], sig: &[u8]) -> R<Vec<u8>> {
    let (flags, counter) = (*auth_data.get(32).ok_or("short authData")?, auth_data.get(33..37).ok_or("short authData")?);
    let mut out = vec![];
    put(&mut out, kind.as_bytes());
    if kind.starts_with("sk-ecdsa") {
        let (r, s) = der_rs(sig).ok_or("Bad signature from the key.")?;
        let mut inner = vec![];
        mpint(&mut inner, r);
        mpint(&mut inner, s);
        put(&mut out, &inner);
    } else {
        put(&mut out, sig);
    }
    out.push(flags);
    out.extend_from_slice(counter);
    Ok(out)
}

// ---- agent state ----

static RUNNING: AtomicBool = AtomicBool::new(false);
/// PIN for keys that need it (alwaysUv / verify-required). Memory only.
static PIN: Mutex<Option<String>> = Mutex::new(None);
/// OpenPGP card PIN (PW1). While set, the card's authentication key is offered too. Memory only.
static PGP_PIN: Mutex<Option<String>> = Mutex::new(None);
const PGP_COMMENT: &str = "openpgp-card";

fn pgp_pin() -> Option<String> {
    PGP_PIN.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Offer the OpenPGP card's authentication key (checks the PIN first), or stop offering it.
pub fn set_pgp_pin(pin: Option<String>) -> R<()> {
    let pin = pin.filter(|p| !p.is_empty());
    if let Some(p) = &pin {
        crate::pgp::check_pin(p)?;
    }
    *PGP_PIN.lock().unwrap_or_else(|p| p.into_inner()) = pin;
    Ok(())
}

/// The card key's blob, when it's being offered and the card is there.
fn pgp_blob() -> Option<Vec<u8>> {
    pgp_pin()?;
    crate::pgp::ssh_blob().ok().flatten()
}

pub fn socket_path() -> R<std::path::PathBuf> {
    Ok(crate::ssh::ssh_dir()?.join("pico-agent.sock"))
}

fn load_keys() -> Vec<SkKey> {
    let Ok(dir) = crate::ssh::ssh_dir() else { return vec![] };
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut keys: Vec<SkKey> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_none() && p.with_extension("pub").exists())
        .filter_map(|p| std::fs::read_to_string(&p).ok())
        .filter(|t| t.contains("OPENSSH PRIVATE KEY"))
        .filter_map(|t| parse_private(&t).ok())
        .collect();
    keys.sort_by(|a, b| a.comment.cmp(&b.comment));
    keys
}

pub fn status() -> R<AgentStatus> {
    Ok(AgentStatus {
        supported: cfg!(unix),
        running: RUNNING.load(Ordering::SeqCst),
        socket: socket_path()?.display().to_string(),
        keys: load_keys()
            .iter()
            .map(|k| format!("{} {}", k.kind.split('@').next().unwrap_or(&k.kind), k.comment))
            .chain(pgp_blob().and_then(|b| Rd(&b).str()).map(|t| format!("{t} {PGP_COMMENT}")))
            .collect(),
        has_pin: PIN.lock().map(|p| p.is_some()).unwrap_or(false),
        pgp: pgp_pin().is_some(),
    })
}

pub fn set_pin(pin: Option<String>) {
    *PIN.lock().unwrap_or_else(|p| p.into_inner()) = pin.filter(|p| !p.is_empty());
}

fn sign(device_path: &str, key: &SkKey, data: &[u8]) -> R<Vec<u8>> {
    use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
    let _guard = crate::DEVICE.lock().unwrap_or_else(|p| p.into_inner());
    let pin = PIN.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let dev = crate::fido::open(device_path)?;
    let mut b = GetAssertionArgsBuilder::new(&key.application, data).credential_id(&key.handle);
    b = match pin.as_deref() {
        Some(p) => b.pin(p),
        None => b.without_pin_and_uv(),
    };
    if key.flags & 0x01 == 0 {
        b = b.without_up(); // created with -O no-touch-required
    }
    let a = dev.get_assertion_with_args(&b.build()).map_err(|e| e.to_string())?;
    let a = a.first().ok_or("No assertion")?;
    ssh_signature(&key.kind, &a.auth_data, &a.signature)
}

/// One agent request → response.
fn handle(msg: &[u8]) -> Vec<u8> {
    const FAILURE: u8 = 5;
    let mut r = Rd(msg);
    match r.u8() {
        Some(11) => {
            // REQUEST_IDENTITIES
            let mut ids: Vec<(Vec<u8>, String)> = load_keys().into_iter().map(|k| (k.blob, k.comment)).collect();
            ids.extend(pgp_blob().map(|b| (b, PGP_COMMENT.to_string())));
            let mut out = vec![12];
            out.extend((ids.len() as u32).to_be_bytes());
            for (blob, comment) in ids {
                put(&mut out, &blob);
                put(&mut out, comment.as_bytes());
            }
            out
        }
        Some(13) => {
            // SIGN_REQUEST: key blob, data, flags
            let (Some(blob), Some(data)) = (r.bytes(), r.bytes()) else { return vec![FAILURE] };
            let flags = r.u32().unwrap_or(0);
            if let Some(pin) = pgp_pin()
                && pgp_blob().as_deref() == Some(blob)
            {
                return match crate::pgp::ssh_sign(&pin, data, flags) {
                    Ok((_, sig)) => {
                        let mut out = vec![14];
                        put(&mut out, &sig);
                        out
                    }
                    Err(e) => {
                        eprintln!("pico-agent: OpenPGP sign failed: {e}");
                        vec![FAILURE]
                    }
                };
            }
            let Some(key) = load_keys().into_iter().find(|k| k.blob == blob) else { return vec![FAILURE] };
            let Some(dev) = crate::fido::list_devices().into_iter().next() else { return vec![FAILURE] };
            match sign(&dev.path, &key, data) {
                Ok(sig) => {
                    let mut out = vec![14];
                    put(&mut out, &sig);
                    out
                }
                Err(e) => {
                    eprintln!("pico-agent: sign failed: {e}");
                    vec![FAILURE]
                }
            }
        }
        _ => vec![FAILURE],
    }
}

#[cfg(unix)]
pub fn start() -> R<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let path = socket_path()?;
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            RUNNING.store(false, Ordering::SeqCst);
            return Err(format!("Couldn't open {}: {e}", path.display()));
        }
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut s) = conn else { continue };
            std::thread::spawn(move || {
                loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).is_err() {
                        return;
                    }
                    let n = u32::from_be_bytes(len) as usize;
                    if n > 256 * 1024 {
                        return;
                    }
                    let mut msg = vec![0u8; n];
                    if s.read_exact(&mut msg).is_err() {
                        return;
                    }
                    let rsp = handle(&msg);
                    let mut frame = (rsp.len() as u32).to_be_bytes().to_vec();
                    frame.extend(rsp);
                    if s.write_all(&frame).is_err() {
                        return;
                    }
                }
            });
        }
        let _ = std::fs::remove_file(&path);
    });
    Ok(())
}

#[cfg(not(unix))]
pub fn start() -> R<()> {
    Err("The built-in agent is available on macOS and Linux.".into())
}

pub fn stop() -> R<()> {
    if RUNNING.swap(false, Ordering::SeqCst) {
        let path = socket_path()?;
        // wake the accept loop so it sees RUNNING=false and exits
        #[cfg(unix)]
        let _ = std::os::unix::net::UnixStream::connect(&path);
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_formats() {
        // DER: r = 0x00ff.. (needs mpint padding), s = 0x01
        let der = [0x30, 0x08, 0x02, 0x02, 0x00, 0xFF, 0x02, 0x02, 0x00, 0x01];
        let (r, s) = der_rs(&der).unwrap();
        assert_eq!((r, s), (&[0x00, 0xFF][..], &[0x00, 0x01][..]));
        let mut m = vec![];
        mpint(&mut m, r);
        assert_eq!(m, [0, 0, 0, 2, 0x00, 0xFF]);
        let mut m = vec![];
        mpint(&mut m, s);
        assert_eq!(m, [0, 0, 0, 1, 0x01]);

        let mut auth = vec![0u8; 32];
        auth.extend([0x05, 0, 0, 0, 9]);
        let sig = ssh_signature("sk-ssh-ed25519@openssh.com", &auth, &[7u8; 64]).unwrap();
        let mut r = Rd(&sig);
        assert_eq!(r.str().unwrap(), "sk-ssh-ed25519@openssh.com");
        assert_eq!(r.bytes().unwrap(), &[7u8; 64][..]);
        assert_eq!((r.u8(), r.u32()), (Some(5), Some(9)));

        // Empty agent message → failure; identities request → answer code 12
        assert_eq!(handle(&[]), vec![5]);
        assert_eq!(handle(&[11])[0], 12);
    }

    /// Builds an sk-ed25519 private key file the way ssh-keygen lays it out, then parses it.
    #[test]
    fn parses_sk_key_file() {
        let mut pubblob = vec![];
        put(&mut pubblob, b"sk-ssh-ed25519@openssh.com");
        put(&mut pubblob, &[1u8; 32]);
        put(&mut pubblob, b"ssh:");
        let mut private = vec![];
        private.extend([0, 0, 0, 7, 0, 0, 0, 7]); // check ints
        put(&mut private, b"sk-ssh-ed25519@openssh.com");
        put(&mut private, &[1u8; 32]);
        put(&mut private, b"ssh:");
        private.push(0x01);
        put(&mut private, &[9u8; 42]);
        put(&mut private, b"");
        put(&mut private, b"me@laptop");
        let mut raw = b"openssh-key-v1\0".to_vec();
        put(&mut raw, b"none");
        put(&mut raw, b"none");
        put(&mut raw, b"");
        raw.extend(1u32.to_be_bytes());
        put(&mut raw, &pubblob);
        put(&mut raw, &private);
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", B64.encode(&raw));
        let k = parse_private(&pem).unwrap();
        assert_eq!((k.application.as_str(), k.flags, k.handle.len(), k.comment.as_str()), ("ssh:", 1, 42, "me@laptop"));
        assert_eq!(k.blob, pubblob);
        assert!(parse_private("-----BEGIN-----\nAAAA\n-----END-----").is_err());
    }

    /// Starts the agent on ~/.ssh/pico-agent.sock and lists keys with Apple's /usr/bin/ssh-add.
    #[test]
    #[ignore]
    fn live_ssh_add() {
        start().unwrap();
        let out = std::process::Command::new("/usr/bin/ssh-add").arg("-l").env("SSH_AUTH_SOCK", socket_path().unwrap()).output().unwrap();
        stop().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        println!("ssh-add -l: {text}");
        assert!(text.contains("no identities") || text.contains("SK"), "{text}");
        assert!(!socket_path().unwrap().exists());
    }
}
