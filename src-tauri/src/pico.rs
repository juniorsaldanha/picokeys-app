//! Pico Keys SDK "rescue" applet (PC/SC, CCID) + raw CTAPHID authenticatorReset.
//!
//! Protocol read from pico-keys-sdk `src/rescue.c` and `src/fs/phy.c`:
//! SELECT AID A0583FC19B7E4F21 → [mcu, product, major, minor, serial.., build u32]
//! CLA 0x80, INS 0x1E READ (P1 1=PHY, 2=flash, 3=secure boot), INS 0x1C WRITE (P1 1=PHY).
use pcsc::{Context, Protocols, Scope, ShareMode};
use std::ffi::CString;
use std::time::Duration;
use types::{Flash, Phy, PicoInfo, SecureBoot};

type R<T> = Result<T, String>;

const RESCUE_AID: [u8; 8] = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

const TAG_VIDPID: u8 = 0x0;
const TAG_LED_GPIO: u8 = 0x4;
const TAG_LED_BTNESS: u8 = 0x5;
const TAG_OPTS: u8 = 0x6;
const TAG_UP_BTN: u8 = 0x8;
const TAG_USB_PRODUCT: u8 = 0x9;
const TAG_CURVES: u8 = 0xA;
const TAG_USB_ITF: u8 = 0xB;
const TAG_LED_DRIVER: u8 = 0xC;

pub(crate) struct Card(pcsc::Card);

impl Card {
    /// First reader whose card answers the pico-keys rescue applet. Reader names follow the
    /// (user-changeable) USB product name, so they can't be matched by name.
    // ponytail: first pico-keys reader wins; map HID path <-> reader when multi-key matters.
    pub(crate) fn open() -> R<Self> {
        let ctx = Context::establish(Scope::User).map_err(|e| format!("PC/SC unavailable: {e}"))?;
        let mut buf = vec![0u8; ctx.list_readers_len().map_err(|e| e.to_string())?];
        let readers: Vec<CString> = ctx.list_readers(&mut buf).map_err(|e| e.to_string())?.map(|r| r.to_owned()).collect();
        readers
            .iter()
            .filter_map(|r| ctx.connect(r, ShareMode::Shared, Protocols::ANY).ok().map(Card))
            .find(|c| c.select().is_ok())
            .ok_or_else(|| "No Pico Key smart-card interface found (is CCID enabled?)".into())
    }

    fn transmit(&self, cmd: &[u8]) -> R<(Vec<u8>, [u8; 2])> {
        let mut out = [0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let rsp = self.0.transmit(cmd, &mut out).map_err(|e| e.to_string())?;
        if rsp.len() < 2 {
            return Err("Malformed response".into());
        }
        let (data, sw) = rsp.split_at(rsp.len() - 2);
        Ok((data.to_vec(), [sw[0], sw[1]]))
    }

    pub(crate) fn apdu(&self, cmd: &[u8]) -> R<Vec<u8>> {
        self.apdu_chained(cmd, 0xC0) // ISO GET RESPONSE
    }

    /// Follows `61xx` (more data) by sending `INS remaining` until 9000 (YKOATH-style chaining).
    pub(crate) fn apdu_chained(&self, cmd: &[u8], remaining_ins: u8) -> R<Vec<u8>> {
        let (mut all, mut sw) = self.transmit(cmd)?;
        while sw[0] == 0x61 {
            let (more, next) = self.transmit(&[0x00, remaining_ins, 0x00, 0x00, 0x00])?;
            all.extend(more);
            sw = next;
        }
        check_sw(sw).map(|_| all)
    }

    fn select(&self) -> R<Vec<u8>> {
        self.select_aid(&RESCUE_AID)
    }

    pub(crate) fn select_aid(&self, aid: &[u8]) -> R<Vec<u8>> {
        let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        cmd.extend_from_slice(aid);
        cmd.push(0x00);
        self.apdu(&cmd)
    }

    fn read(&self, p1: u8) -> R<Vec<u8>> {
        self.apdu(&[0x80, 0x1E, p1, 0x00, 0x00])
    }
}

fn check_sw(sw: [u8; 2]) -> R<()> {
    match sw {
        [0x90, 0x00] => Ok(()),
        [0x69, 0x85] => Err("Not confirmed on the key (touch the button when it blinks).".into()),
        [0x69, 0x82] => Err("The key is locked with a password.".into()),
        [0x6A, 0x84] => Err("The key is full.".into()),
        [a, b] => Err(format!("Key returned status {a:02X}{b:02X}")),
    }
}

pub fn info() -> R<PicoInfo> {
    let card = Card::open()?;
    let sel = card.select()?;
    if sel.len() < 5 {
        return Err("Unexpected rescue applet response".into());
    }
    // serial is 8 bytes on hardware, 16 in the emulator; older firmware (e.g. 8.0) omits the build number
    let serial_len = if sel[0] == 3 { 16 } else { 8 }.min(sel.len() - 4);
    let serial = &sel[4..4 + serial_len];
    let build = sel.get(4 + serial_len..8 + serial_len).map(|b| u32::from_be_bytes(b.try_into().unwrap()));
    let phy = parse_phy(&card.read(1)?);
    let flash = card.read(2).ok().and_then(|d| parse_flash(&d));
    let secure_boot = card
        .read(3)
        .ok()
        .filter(|d| d.len() >= 3)
        .map(|d| SecureBoot { enabled: d[0] == 1, locked: d[1] == 1, bootkey: d[2] });
    Ok(PicoInfo {
        mcu: mcu_name(sel[0]).into(),
        product: product_name(sel[1]).into(),
        version: format!("{}.{}", sel[2], sel[3]),
        serial: serial.iter().map(|b| format!("{b:02X}")).collect(),
        build,
        flash,
        secure_boot,
        phy,
    })
}

/// Firmware replaces the whole PHY block on write, so always send the full config.
pub fn write_phy(phy: &Phy) -> R<()> {
    let data = serialize_phy(phy)?;
    let card = Card::open()?;
    card.select()?;
    let mut cmd = vec![0x80, 0x1C, 0x01, 0x00, data.len() as u8];
    cmd.extend_from_slice(&data);
    card.apdu(&cmd).map(|_| ())
}

fn mcu_name(b: u8) -> &'static str {
    match b {
        0 => "RP2040",
        1 => "RP2350",
        2 => "ESP32-S3",
        3 => "Emulation",
        4 => "ESP32-S2",
        _ => "Unknown",
    }
}

fn product_name(b: u8) -> &'static str {
    // 2 is confirmed in pico-fido defs.c; 1/3 follow the HSM, FIDO, OpenPGP release order.
    match b {
        1 => "Pico HSM",
        2 => "Pico FIDO",
        3 => "Pico OpenPGP",
        _ => "Pico Key",
    }
}

fn be32(d: &[u8], i: usize) -> Option<u32> {
    d.get(i * 4..i * 4 + 4).map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

fn parse_flash(d: &[u8]) -> Option<Flash> {
    Some(Flash {
        free: be32(d, 0)?,
        used: be32(d, 1)?,
        total: be32(d, 2)?,
        files: be32(d, 3)?,
        size: be32(d, 4)?,
        firmware: be32(d, 5),
    })
}

fn parse_phy(d: &[u8]) -> Phy {
    let mut p = Phy::default();
    let mut i = 0;
    while i + 2 <= d.len() {
        let (tag, len) = (d[i], d[i + 1] as usize);
        let Some(v) = d.get(i + 2..i + 2 + len) else { break };
        match (tag, len) {
            (TAG_VIDPID, 4) => {
                p.vid = Some(u16::from_be_bytes([v[0], v[1]]));
                p.pid = Some(u16::from_be_bytes([v[2], v[3]]));
            }
            (TAG_LED_GPIO, 1) => p.led_gpio = Some(v[0]),
            (TAG_LED_BTNESS, 1) => p.led_brightness = Some(v[0]),
            (TAG_OPTS, 2) => p.opts = u16::from_be_bytes([v[0], v[1]]),
            (TAG_UP_BTN, 1) => p.up_btn = Some(v[0]),
            (TAG_USB_PRODUCT, 1..) => {
                p.usb_product = Some(String::from_utf8_lossy(v).trim_end_matches('\0').to_string())
            }
            (TAG_CURVES, 4) => p.enabled_curves = Some(u32::from_be_bytes(v.try_into().unwrap())),
            (TAG_USB_ITF, 1) => p.enabled_usb_itf = Some(v[0]),
            (TAG_LED_DRIVER, 1..) => {
                p.led_driver = Some(v[0]);
                p.led_order = v.get(1).copied();
            }
            _ => {}
        }
        i += 2 + len;
    }
    p
}

fn serialize_phy(p: &Phy) -> R<Vec<u8>> {
    let mut o = vec![];
    let mut tlv = |tag: u8, v: &[u8]| {
        o.push(tag);
        o.push(v.len() as u8);
        o.extend_from_slice(v);
    };
    if let (Some(vid), Some(pid)) = (p.vid, p.pid) {
        let (v, q) = (vid.to_be_bytes(), pid.to_be_bytes());
        tlv(TAG_VIDPID, &[v[0], v[1], q[0], q[1]]);
    }
    if let Some(g) = p.led_gpio {
        tlv(TAG_LED_GPIO, &[g]);
    }
    if let Some(b) = p.led_brightness {
        tlv(TAG_LED_BTNESS, &[b]);
    }
    tlv(TAG_OPTS, &p.opts.to_be_bytes());
    if let Some(b) = p.up_btn {
        tlv(TAG_UP_BTN, &[b]);
    }
    if let Some(name) = p.usb_product.as_deref().filter(|s| !s.is_empty()) {
        // firmware buffer is 32 bytes including the NUL
        if name.len() > 31 || !name.is_ascii() {
            return Err("USB product name must be ASCII, at most 31 characters.".into());
        }
        let mut v = name.as_bytes().to_vec();
        v.push(0);
        tlv(TAG_USB_PRODUCT, &v);
    }
    if let Some(c) = p.enabled_curves {
        tlv(TAG_CURVES, &c.to_be_bytes());
    }
    if let Some(u) = p.enabled_usb_itf {
        if u & (Phy::ITF_HID | Phy::ITF_CCID) == 0 {
            return Err("Keep HID or CCID enabled, or the key can't be managed anymore.".into());
        }
        tlv(TAG_USB_ITF, &[u]);
    }
    if let Some(d) = p.led_driver {
        match p.led_order {
            Some(ord) => tlv(TAG_LED_DRIVER, &[d, ord]),
            None => tlv(TAG_LED_DRIVER, &[d]),
        }
    }
    Ok(o)
}

// ---------------------------------------------------------------------------
// FIDO factory reset (authenticatorReset, CTAP 0x07) over raw CTAPHID.
// ctap-hid-fido2 doesn't expose it. Pico FIDO only accepts it within 10 s of
// power-up and after a button press.
// ---------------------------------------------------------------------------

pub fn fido_reset(path: &str) -> R<()> {
    use crate::ctap::{CTAPHID_CBOR, transact};
    let (_, rsp) = transact(path, CTAPHID_CBOR, &[0x07], Duration::from_secs(40))?;
    match rsp.first() {
        Some(0x00) => Ok(()),
        Some(0x30) => Err("Reset is only allowed within 10 seconds of plugging in the key. Replug it and try again.".into()),
        Some(0x2F) => Err("No touch detected. Try again and touch the key when it blinks.".into()),
        Some(0x27) => Err("Reset was denied on the key.".into()),
        Some(s) => Err(format!("Reset failed (CTAP error 0x{s:02X})")),
        None => Err("Unexpected reply to reset".into()),
    }
}

/// Set the key's clock to now (Unix seconds). The key forgets it when unplugged.
pub fn set_time() -> R<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs() as u32;
    let card = Card::open()?;
    card.select()?;
    let mut cmd = vec![0x80, 0x1C, 0x02, 0x02, 4];
    cmd.extend_from_slice(&now.to_be_bytes());
    card.apdu(&cmd).map(|_| ())
}

/// The key's clock (Unix seconds), or None if it hasn't been set since power-up.
pub fn get_time() -> R<Option<u32>> {
    let card = Card::open()?;
    card.select()?;
    match card.apdu(&[0x80, 0x1E, 0x04, 0x02, 0x00]) {
        Ok(d) => Ok(be32(&d, 0)),
        Err(e) if e.starts_with("Not confirmed") => Ok(None), // 6985: clock never set
        Err(e) => Err(e),
    }
}

/// IRREVERSIBLE: burns the vendor boot-key digest into one-time fuses so only firmware signed by
/// the pico-keys vendor boots. `lock` (secure lock) additionally revokes the other key slots and
/// write-protects the key; firmware requires secure boot to be enabled first. Needs a touch.
pub fn enable_secure_boot(bootkey: u8, lock: bool) -> R<()> {
    let info = info()?;
    if info.mcu.contains("RP2040") {
        return Err("The RP2040 has no secure boot.".into());
    }
    match (&info.secure_boot, lock) {
        (Some(sb), true) if !sb.enabled => return Err("Enable secure boot first, then secure lock.".into()),
        (Some(sb), true) if sb.locked => return Err("Secure lock is already on.".into()),
        (Some(sb), false) if sb.enabled => return Err("Secure boot is already enabled.".into()),
        _ => {}
    }
    let card = Card::open()?;
    card.select()?;
    card.apdu(&[0x80, 0x1D, bootkey, lock as u8]).map(|_| ())
}

/// Restart an RP2040/RP2350 key into its BOOTSEL (UF2 drive) mode. Needs a touch.
pub fn reboot_bootsel() -> R<()> {
    let card = Card::open()?;
    card.select()?;
    card.apdu(&[0x80, 0x1F, 0x01, 0x00]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phy_roundtrip_matches_firmware_layout() {
        let p = Phy {
            vid: Some(0x2E8A),
            pid: Some(0x10FE),
            led_gpio: Some(48),
            led_brightness: Some(15),
            opts: Phy::OPT_DIMM,
            up_btn: Some(15),
            usb_product: Some("My Key".into()),
            enabled_curves: Some(Phy::CURVE_SECP256K1),
            enabled_usb_itf: Some(Phy::ITF_ALL),
            led_driver: Some(5),
            led_order: Some(2),
        };
        let bytes = serialize_phy(&p).unwrap();
        // VID/PID big-endian, as phy_serialize_data writes them
        assert_eq!(&bytes[..6], &[0x00, 4, 0x2E, 0x8A, 0x10, 0xFE]);
        assert_eq!(parse_phy(&bytes), p);
        // truncated input must not panic
        assert_eq!(parse_phy(&bytes[..3]).vid, None);
        assert!(serialize_phy(&Phy { enabled_usb_itf: Some(Phy::ITF_KB), ..p.clone() }).is_err());
        assert!(serialize_phy(&Phy { usb_product: Some("x".repeat(32)), ..p }).is_err());
    }

    #[test]
    fn flash_parsing() {
        let d: Vec<u8> = [1u32, 2, 3, 4, 5, 6].iter().flat_map(|v| v.to_be_bytes()).collect();
        let f = parse_flash(&d).unwrap();
        assert_eq!((f.free, f.used, f.total, f.files, f.size, f.firmware), (1, 2, 3, 4, 5, Some(6)));
        assert!(parse_flash(&d[..10]).is_none());
    }

    /// `cargo test -p picokeys-app -- --ignored probe_rescue --nocapture`
    #[test]
    #[ignore]
    fn probe_rescue() {
        println!("{:#?}", info().unwrap());
    }
}
