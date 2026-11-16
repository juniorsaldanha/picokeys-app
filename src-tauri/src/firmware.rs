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

const OWNER: &str = "polhenarejos";
const MAX_IMAGE: usize = 16 * 1024 * 1024;
const ESPRESSIF_VID: u16 = 0x303A;

fn repo(product: &str) -> R<&'static str> {
    match product {
        "fido" => Ok("pico-fido"),
        "hsm" => Ok("pico-hsm"),
        "openpgp" => Ok("pico-openpgp"),
        _ => Err("Unknown product.".into()),
    }
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
    let url = format!("https://api.github.com/repos/{OWNER}/{}/releases?per_page=30", repo(product)?);
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

/// Downloads an asset, only from the official repositories.
fn download(url: &str, progress: &mut dyn FnMut(FlashProgress)) -> R<Vec<u8>> {
    let official = ["pico-fido", "pico-hsm", "pico-openpgp"]
        .iter()
        .any(|r| url.starts_with(&format!("https://github.com/{OWNER}/{r}/releases/download/")));
    if !official {
        return Err("Only official pico-keys release files can be flashed.".into());
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
    if board.is_esp() { flash_esp(&data, board, progress) } else { flash_uf2(&data, board, progress) }
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

fn flash_esp(data: &[u8], board: Board, progress: &mut dyn FnMut(FlashProgress)) -> R<()> {
    check_esp_image(data, board)?;
    // ponytail: first Espressif USB port wins; add a port picker if people flash several boards at once.
    let (name, info) = serialport::available_ports()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find_map(|p| match p.port_type {
            serialport::SerialPortType::UsbPort(u) if u.vid == ESPRESSIF_VID => Some((p.port_name, u)),
            _ => None,
        })
        .ok_or("No ESP32 in download mode found. Unplug the key, hold its BOOT button while plugging it back in, then try again.")?;
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
    // The merged image covers bootloader + partition table + app (0x0..~0xB8000); the key's data
    // partition (part0 at 0x200000) is not touched, so passkeys and settings survive.
    flasher.write_bin_to_flash(0, data, &mut Progress(progress, 0)).map_err(|e| format!("Writing failed: {e}"))?;
    progress(FlashProgress { stage: "Restarting".into(), done: 1, total: 1 });
    let _ = flasher.connection().reset_after(true, chip);
    Ok(())
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
}
