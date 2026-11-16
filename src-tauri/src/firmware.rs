//! Official firmware releases (GitHub) and flashing:
//! ESP32-S2/S3 over the ROM serial bootloader (espflash), RP2040/RP2350 by copying a UF2
//! onto the BOOTSEL drive.
use espflash::connection::{Connection, ResetAfterOperation, ResetBeforeOperation};
use espflash::flasher::Flasher;
use espflash::target::{Chip, ProgressCallbacks};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use types::{Board, FlashProgress, FwAsset, FwRelease};

type R<T> = Result<T, String>;

const MAX_IMAGE: usize = 16 * 1024 * 1024;
const ESPRESSIF_VID: u16 = 0x303A;

/// GitHub owner/repo per product: the official pico-keys firmwares, plus our unofficial
/// Pico FIDO + OpenPGP build (ESP32-S3 app images only).
const REPOS: [(&str, &str); 4] = [
    ("fido", "polhenarejos/pico-fido"),
    ("hsm", "polhenarejos/pico-hsm"),
    ("openpgp", "polhenarejos/pico-openpgp"),
    ("combo", "juniorsaldanha/pico-fido-openpgp"),
];

fn repo(product: &str) -> R<&'static str> {
    REPOS.iter().find(|(p, _)| *p == product).map(|(_, r)| *r).ok_or_else(|| "Unknown product.".into())
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    published_at: Option<String>,
    prerelease: bool,
    draft: bool,
    assets: Vec<GhAsset>,
}
#[derive(Deserialize)]
struct GhAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

/// Stable releases that ship at least one generic board image, newest first.
pub fn releases(product: &str) -> R<Vec<FwRelease>> {
    let url = format!("https://api.github.com/repos/{}/releases?per_page=30", repo(product)?);
    let list: Vec<GhRelease> = ureq::get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("Couldn't reach GitHub: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| e.to_string())?;
    let mut out: Vec<FwRelease> = list
        .into_iter()
        .filter(|r| !r.prerelease && !r.draft)
        .map(|r| FwRelease {
            product: product.into(),
            date: r.published_at.unwrap_or_default().chars().take(10).collect(),
            assets: r
                .assets
                .into_iter()
                .filter_map(|a| {
                    Some(FwAsset { board: Board::from_asset(&a.name)?, name: a.name, size: a.size, url: a.browser_download_url })
                })
                .collect(),
            tag: r.tag_name,
        })
        .filter(|r| !r.assets.is_empty())
        .collect();
    out.sort_by(|a, b| b.date.cmp(&a.date));
    Ok(out)
}

/// Downloads an asset, only from the repositories in `REPOS`.
fn download(url: &str, progress: &mut dyn FnMut(FlashProgress)) -> R<Vec<u8>> {
    if !REPOS.iter().any(|(_, r)| url.starts_with(&format!("https://github.com/{r}/releases/download/"))) {
        return Err("Only release files from the listed firmware repositories can be flashed.".into());
    }
    let mut rsp = ureq::get(url).call().map_err(|e| format!("Download failed: {e}"))?;
    let total = rsp.body().content_length().unwrap_or(0);
    let mut reader = rsp.body_mut().as_reader();
    let (mut data, mut buf) = (Vec::new(), [0u8; 64 * 1024]);
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("Download failed: {e}"))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > MAX_IMAGE {
            return Err("Firmware file is unexpectedly large.".into());
        }
        progress(FlashProgress { stage: "Downloading".into(), done: data.len() as u64, total });
    }
    Ok(data)
}

pub fn flash(url: &str, board: Board, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    let data = download(url, progress)?;
    flash_data(&data, board, progress)
}

// ---------- ESP32 ----------

fn esp_chip(board: Board) -> Chip {
    if board == Board::Esp32S2 { Chip::Esp32s2 } else { Chip::Esp32s3 }
}

/// Merged image (written at 0x0) check: bootloader magic + extended header chip id.
/// The bootloader sits at 0x1000 on the S2 (chip id 2) and at 0x0 on the S3 (chip id 9).
fn check_esp_image(d: &[u8], board: Board) -> R<()> {
    let (at, want) = if board == Board::Esp32S2 { (0x1000, 2) } else { (0, 9) };
    match (d.get(at), d.get(at + 12..at + 14)) {
        (Some(0xE9), Some(id)) if u16::from_le_bytes([id[0], id[1]]) == want => Ok(()),
        _ => Err(format!("This file isn't an {} firmware image.", board.label())),
    }
}

/// Partition table offset on both S2 and S3: everything below it is the bootloader.
const BOOTLOADER_END: u32 = 0x8000;

/// The merged image minus its bootloader region, for chips with secure boot on.
fn keep_bootloader(d: &[u8]) -> R<&[u8]> {
    d.get(BOOTLOADER_END as usize..)
        .filter(|rest| rest.starts_with(&[0xAA, 0x50]))
        .ok_or_else(|| "This image has no partition table at 0x8000, so it can't be written without replacing the signed bootloader.".into())
}

struct Progress<'a>(&'a mut dyn FnMut(FlashProgress), u64);
impl ProgressCallbacks for Progress<'_> {
    fn init(&mut self, _addr: u32, total: usize) {
        self.1 = total as u64;
        (self.0)(FlashProgress { stage: "Writing".into(), done: 0, total: self.1 });
    }
    fn update(&mut self, current: usize) {
        (self.0)(FlashProgress { stage: "Writing".into(), done: current as u64, total: self.1 });
    }
    fn verifying(&mut self) {
        (self.0)(FlashProgress { stage: "Verifying".into(), done: self.1, total: self.1 });
    }
    fn finish(&mut self, _skipped: bool) {}
}

fn flash_esp(data: &[u8], board: Board, app_only: bool, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    if !app_only {
        check_esp_image(data, board)?;
    }
    let (name, info) = match espressif_port() {
        Some(p) => p,
        None => {
            // A board with a USB-UART "COM" port can be put into download mode for us.
            let com = uart_port().ok_or("No ESP32 in download mode found. Unplug the key, hold its BOOT button while plugging it back in, then try again.")?;
            progress(FlashProgress { stage: "Restarting the key into download mode (COM port)".into(), done: 0, total: 0 });
            uart_reset(&com, true)?;
            let start = Instant::now();
            loop {
                if let Some(p) = espressif_port() {
                    break p;
                }
                if start.elapsed() > Duration::from_secs(8) {
                    return Err("The key didn't enter download mode through its COM port. Hold BOOT while plugging it in, then try again.".into());
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    };
    progress(FlashProgress { stage: "Connecting".into(), done: 0, total: 0 });
    let serial = serialport::new(&name, 115_200)
        .flow_control(serialport::FlowControl::None)
        .open_native()
        .map_err(|e| format!("Couldn't open {name}: {e}"))?;
    let conn = Connection::new(serial, info, ResetAfterOperation::HardReset, ResetBeforeOperation::DefaultReset, 115_200);
    let chip = esp_chip(board);
    let mut flasher = Flasher::connect(conn, true, true, false, Some(chip), None).map_err(|e| format!("Couldn't talk to the ESP32 bootloader: {e}"))?;
    if flasher.chip() != chip {
        return Err(format!("The connected chip is an {}, not an {}.", flasher.chip(), board.label()));
    }
    // With secure boot on, the ROM only boots a bootloader signed with a burned key, and release
    // images are unsigned: writing ours over it bricks the key. Keep the (signed) bootloader that's
    // there and write from the partition table up; the bootloader doesn't verify the app.
    let secure = flasher.security_info().map_err(|e| format!("Couldn't read the chip's security fuses: {e}"))?.flags & 1 != 0;
    let (addr, image) = if app_only {
        (APP_OFFSET, data)
    } else if secure {
        (BOOTLOADER_END, keep_bootloader(data)?)
    } else {
        (0, data)
    };
    if secure && !app_only {
        progress(FlashProgress { stage: "Secure boot is on: keeping your signed bootloader".into(), done: 0, total: 0 });
    }
    // The merged image covers bootloader + partition table + app (0x0..~0xB8000); the key's data
    // partition (part0 at 0x200000) is not touched, so passkeys and settings survive.
    flasher.write_bin_to_flash(addr, image, &mut Progress(progress, 0)).map_err(|e| format!("Writing failed: {e}"))?;
    progress(FlashProgress { stage: "Restarting".into(), done: 1, total: 1 });
    // A reset over the native USB port can land back in download mode; the COM port boots it normally.
    match uart_port() {
        Some(com) => {
            drop(flasher);
            uart_reset(&com, false)
        }
        None => {
            let _ = flasher.connection().reset_after(true, chip);
            Ok(())
        }
    }
}

/// pico-keys partitions.csv (S2 and S3): `factory` app at 0x20000, 1 MB.
const APP_OFFSET: u32 = 0x20000;
const APP_MAX: usize = 0x10_0000;

/// Merged image (bootloader + partition table + app) or a bare app image for the app slot?
fn esp_app_only(d: &[u8], board: Board) -> R<bool> {
    let merged = check_esp_image(d, board).is_ok() && (board == Board::Esp32S2 || d.get(0x8000..0x8002) == Some(&[0xAA, 0x50]));
    if merged {
        return Ok(false);
    }
    let want: u16 = if board == Board::Esp32S2 { 2 } else { 9 };
    match (d.first(), d.get(12..14)) {
        (Some(0xE9), Some(id)) if u16::from_le_bytes([id[0], id[1]]) == want => {
            if d.len() > APP_MAX {
                Err(format!("This app image is {} KB; the key's app slot holds 1024 KB.", d.len() / 1024))
            } else {
                Ok(true)
            }
        }
        _ => Err(format!("This file isn't an {} firmware or app image.", board.label())),
    }
}

/// Flashes a local file: an ESP32 merged image or app image (`build/pico_fido.bin`), or a UF2.
pub fn flash_file(path: &str, board: Board, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    let data = std::fs::read(path).map_err(|e| format!("Couldn't read {path}: {e}"))?;
    if data.len() > MAX_IMAGE {
        return Err("Firmware file is unexpectedly large.".into());
    }
    flash_data(&data, board, progress)
}

/// ESP32: a merged image (official releases) or a bare app image (custom builds, the unofficial
/// release) for the app slot; RP2040/RP2350: a UF2.
fn flash_data(data: &[u8], board: Board, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    if board.is_esp() {
        let app_only = esp_app_only(data, board)?;
        if app_only {
            progress(FlashProgress { stage: "App image: writing only the app slot at 0x20000".into(), done: 0, total: 0 });
        }
        flash_esp(data, board, app_only, progress)
    } else {
        flash_uf2(data, board, progress)
    }
}

fn espressif_port() -> Option<(String, serialport::UsbPortInfo)> {
    // ponytail: first Espressif USB port wins; add a port picker if people flash several boards at once.
    serialport::available_ports().ok()?.into_iter().find_map(|p| match p.port_type {
        serialport::SerialPortType::UsbPort(u) if u.vid == ESPRESSIF_VID => Some((p.port_name, u)),
        _ => None,
    })
}

/// USB-UART bridges used for dev boards' "COM"/"UART" port: WCH CH34x, Silicon Labs CP210x, FTDI.
fn uart_port() -> Option<String> {
    serialport::available_ports().ok()?.into_iter().find_map(|p| match p.port_type {
        serialport::SerialPortType::UsbPort(u) if [0x1A86, 0x10C4, 0x0403].contains(&u.vid) => Some(p.port_name),
        _ => None,
    })
}

/// Pulses EN through the bridge's RTS line; DTR drives GPIO0, low = download mode.
fn uart_reset(port: &str, download: bool) -> R<()> {
    let mut s = serialport::new(port, 115_200).open().map_err(|e| format!("Couldn't open {port}: {e}"))?;
    let set = |s: &mut Box<dyn serialport::SerialPort>, dtr: bool, rts: bool| {
        let _ = s.write_data_terminal_ready(dtr);
        let _ = s.write_request_to_send(rts);
    };
    set(&mut s, false, true);
    std::thread::sleep(Duration::from_millis(100));
    set(&mut s, download, false);
    std::thread::sleep(Duration::from_millis(400));
    set(&mut s, false, false);
    Ok(())
}

/// Restarts the key through its COM port and returns what the firmware prints while booting.
pub fn boot_log(seconds: u64) -> R<String> {
    let port = uart_port().ok_or("No COM port found. Connect the board's second USB port (often labelled COM or UART) too.")?;
    let mut s = serialport::new(&port, 115_200).timeout(Duration::from_millis(200)).open().map_err(|e| format!("Couldn't open {port}: {e}"))?;
    let _ = s.write_data_terminal_ready(false);
    let _ = s.write_request_to_send(true);
    std::thread::sleep(Duration::from_millis(100));
    let _ = s.write_request_to_send(false);
    let (mut out, mut buf, end) = (Vec::new(), [0u8; 4096], Instant::now() + Duration::from_secs(seconds.clamp(2, 30)));
    while Instant::now() < end && out.len() < 512 * 1024 {
        match s.read(&mut buf) {
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("Reading {port} failed: {e}")),
        }
    }
    Ok(clean_log(&out))
}

/// Drops carriage returns and ANSI colour codes.
fn clean_log(raw: &[u8]) -> String {
    let t = String::from_utf8_lossy(raw).replace('\r', "");
    let mut out = String::with_capacity(t.len());
    let mut it = t.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------- RP2040 / RP2350 ----------

const UF2_MAGIC: [u32; 2] = [0x0A32_4655, 0x9E5D_5157];
const FAMILY_RP2040: u32 = 0xE48B_FF56;

/// All blocks must be UF2 and target the right family (RP2350 images may also carry the
/// "absolute" / data families, but never RP2040's).
fn check_uf2(d: &[u8], board: Board) -> R<()> {
    let bad = || Err(format!("This file isn't an {} UF2 image.", board.label()));
    if d.is_empty() || !d.len().is_multiple_of(512) {
        return bad();
    }
    for b in d.chunks(512) {
        let w = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        if [w(0), w(4)] != UF2_MAGIC || w(508) != 0x0AB1_6F30 {
            return bad();
        }
        let has_family = w(8) & 0x2000 != 0;
        let fam = w(28);
        let ok = match board {
            Board::Rp2040 => has_family && fam == FAMILY_RP2040,
            _ => has_family && (0xE48B_FF57..=0xE48B_FF5B).contains(&fam),
        };
        if !ok {
            return bad();
        }
    }
    Ok(())
}

fn mount_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        return (b'D'..=b'Z').map(|c| PathBuf::from(format!("{}:\\", c as char))).collect();
    }
    let mut roots = vec![];
    for base in ["/Volumes", "/media", "/run/media"] {
        let Ok(rd) = std::fs::read_dir(base) else { continue };
        for e in rd.flatten() {
            roots.push(e.path());
            // Linux: /media/<user>/<label>
            if let Ok(sub) = std::fs::read_dir(e.path()) {
                roots.extend(sub.flatten().map(|s| s.path()));
            }
        }
    }
    roots
}

/// A mounted BOOTSEL drive for this board (INFO_UF2.TXT Board-ID: RPI-RP2 or RP2350).
fn find_bootsel(board: Board) -> Option<PathBuf> {
    let want = if board == Board::Rp2040 { "RPI-RP2" } else { "RP2350" };
    mount_roots().into_iter().find(|p| {
        std::fs::read_to_string(p.join("INFO_UF2.TXT"))
            .map(|t| t.lines().any(|l| l.starts_with("Board-ID:") && l.contains(want)))
            .unwrap_or(false)
    })
}

fn flash_uf2(data: &[u8], board: Board, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    check_uf2(data, board)?;
    let drive = match find_bootsel(board) {
        Some(d) => d,
        None => {
            progress(FlashProgress { stage: "Touch the key to restart it into update mode".into(), done: 0, total: 0 });
            // Fine if this fails (key already in BOOTSEL by hand, or not a pico-keys firmware): we just wait for the drive.
            let _ = crate::pico::reboot_bootsel();
            progress(FlashProgress { stage: "Waiting for the update drive".into(), done: 0, total: 0 });
            let start = Instant::now();
            loop {
                if let Some(d) = find_bootsel(board) {
                    break d;
                }
                if start.elapsed() > Duration::from_secs(60) {
                    return Err(format!(
                        "No {} update drive appeared. Unplug the key, hold BOOTSEL while plugging it in, then try again.",
                        board.label()
                    ));
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    };
    progress(FlashProgress { stage: "Writing".into(), done: 0, total: data.len() as u64 });
    let target = drive.join("firmware.uf2");
    if let Err(e) = std::fs::write(&target, data) {
        // The bootloader reboots as soon as the last block lands, which can surface as an I/O error.
        if drive.exists() {
            return Err(format!("Copying to {} failed: {e}", drive.display()));
        }
    }
    progress(FlashProgress { stage: "Restarting".into(), done: data.len() as u64, total: data.len() as u64 });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_checks() {
        let mut merged = vec![0xFFu8; 0x9000];
        merged[0x8000..0x8002].copy_from_slice(&[0xAA, 0x50]);
        assert_eq!(keep_bootloader(&merged).unwrap().len(), 0x1000);
        assert!(keep_bootloader(&merged[..0x8000]).is_err());
        assert!(keep_bootloader(&vec![0xFFu8; 0x9000]).is_err());
        let mut esp = vec![0u8; 32];
        esp[0] = 0xE9;
        esp[12] = 9;
        assert!(check_esp_image(&esp, Board::Esp32S3).is_ok());
        assert!(check_esp_image(&esp, Board::Esp32S2).is_err());
        let mut s2 = vec![0xFFu8; 0x1020];
        s2[0x1000] = 0xE9;
        s2[0x100C..0x100E].copy_from_slice(&[2, 0]);
        assert!(check_esp_image(&s2, Board::Esp32S2).is_ok());

        let block = |fam: u32| {
            let mut b = vec![0u8; 512];
            b[0..4].copy_from_slice(&UF2_MAGIC[0].to_le_bytes());
            b[4..8].copy_from_slice(&UF2_MAGIC[1].to_le_bytes());
            b[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
            b[28..32].copy_from_slice(&fam.to_le_bytes());
            b[508..512].copy_from_slice(&0x0AB1_6F30u32.to_le_bytes());
            b
        };
        assert!(check_uf2(&block(FAMILY_RP2040), Board::Rp2040).is_ok());
        assert!(check_uf2(&block(FAMILY_RP2040), Board::Rp2350).is_err());
        assert!(check_uf2(&[block(0xE48B_FF57), block(0xE48B_FF59)].concat(), Board::Rp2350).is_ok());
        assert!(check_uf2(&esp, Board::Rp2040).is_err());

        assert_eq!(Board::from_asset("pico_fido_esp32-s3_8.0.bin"), Some(Board::Esp32S3));
        assert_eq!(Board::from_asset("pico_fido_pico2-8.0.uf2"), Some(Board::Rp2350));
        assert_eq!(Board::from_asset("pico_fido_esp32s3-7.6.bin"), Some(Board::Esp32S3));
        assert_eq!(Board::from_asset("pico_fido_pico-8.0.uf2"), Some(Board::Rp2040));
        assert_eq!(Board::from_asset("pico_fido_waveshare_rp2040_zero.uf2"), None);
        assert!(download("https://evil.example/x.bin", &mut |_| {}).is_err());

        // merged S3 image (partition table at 0x8000) vs bare app image vs junk
        let mut merged_s3 = vec![0xFFu8; 0x9000];
        merged_s3[0] = 0xE9;
        merged_s3[12..14].copy_from_slice(&[9, 0]);
        merged_s3[0x8000..0x8002].copy_from_slice(&[0xAA, 0x50]);
        assert_eq!(esp_app_only(&merged_s3, Board::Esp32S3), Ok(false));
        assert_eq!(esp_app_only(&esp, Board::Esp32S3), Ok(true));
        assert!(esp_app_only(&esp, Board::Esp32S2).is_err());
        let mut big = esp.clone();
        big.resize(APP_MAX + 1, 0);
        assert!(esp_app_only(&big, Board::Esp32S3).is_err());
        assert_eq!(clean_log(b"\x1b[0;32mI (55) boot: ok\x1b[0m\r\n"), "I (55) boot: ok\n");
    }

    /// Lists releases and validates the real v8.0 images (network, no device).
    /// `cargo test -p picokeys-app -- --ignored official_images --nocapture`
    #[test]
    #[ignore]
    fn official_images() {
        let rel = releases("fido").unwrap();
        println!("{:#?}", &rel[..1]);
        for a in &rel[0].assets {
            let d = download(&a.url, &mut |_| {}).unwrap();
            if a.board.is_esp() { check_esp_image(&d, a.board) } else { check_uf2(&d, a.board) }
                .unwrap_or_else(|e| panic!("{}: {e}", a.name));
        }
    }

    /// The unofficial Pico FIDO + OpenPGP release: an ESP32-S3 app image for the app slot.
    #[test]
    #[ignore]
    fn unofficial_combo_image() {
        let rel = releases("combo").unwrap();
        let a = rel[0].assets.iter().find(|a| a.board == Board::Esp32S3).expect("ESP32-S3 asset");
        let d = download(&a.url, &mut |_| {}).unwrap();
        assert_eq!(esp_app_only(&d, Board::Esp32S3), Ok(true), "{}", a.name);
        assert!(download("https://github.com/someone/else/releases/download/v1/x.bin", &mut |_| {}).is_err());
    }
}
