//! Firmware page: official releases, a local (custom) image, and the boot log over the COM port.
use crate::api;
use crate::pages::{ErrorBox, PageHeader, humanize};
use dioxus::prelude::*;
use icons::{CircleCheck, Download, ExternalLink, FileUp, ScrollText, TriangleAlert, Zap};
use types::{Board, FlashProgress, FwAsset, FwRelease};

use crate::ui::alert::{Alert, AlertDescription, AlertTitle, AlertVariant};
use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::label::Label;
use crate::ui::progress::Progress;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;

const PRODUCTS: [(&str, &str); 4] =
    [("fido", "Pico FIDO"), ("hsm", "Pico HSM"), ("openpgp", "Pico OpenPGP"), ("combo", "Pico FIDO + OpenPGP (unofficial)")];

/// GitHub repo per product (the backend only downloads from these).
fn repo(product: &str) -> &'static str {
    match product {
        "combo" => "juniorsaldanha/pico-fido-openpgp",
        "hsm" => "polhenarejos/pico-hsm",
        "openpgp" => "polhenarejos/pico-openpgp",
        _ => "polhenarejos/pico-fido",
    }
}
const BOARDS: [Board; 4] = [Board::Esp32S3, Board::Esp32S2, Board::Rp2350, Board::Rp2040];

/// "v7.6" / "8.0" -> (7, 6)
fn ver(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.trim_start_matches('v').split_once('.')?;
    Some((a.parse().ok()?, b.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?))
}

#[derive(Clone, PartialEq)]
enum Flash {
    Idle,
    Running(FlashProgress),
    Done(String),
    Failed(String),
}

#[component]
pub fn FirmwarePage() -> Element {
    // What's on the key now (absent if it isn't plugged in / not pico-keys firmware).
    let current = use_resource(api::pico_info);
    let mut product = use_signal(|| "fido".to_string());
    let mut board = use_signal(|| None::<Board>);
    let releases = use_resource(move || async move { api::fw_releases(&product()).await });
    let mut state = use_signal(|| Flash::Idle);
    let mut armed = use_signal(|| None::<String>);

    // Default the board (and product) to the connected key's.
    use_effect(move || {
        if let Some(Ok(info)) = &*current.read()
            && board.peek().is_none()
        {
            board.set(Board::from_mcu(&info.mcu));
            if let Some((p, _)) = PRODUCTS.iter().find(|(_, n)| *n == info.product) {
                product.set(p.to_string());
            }
        }
    });

    let cur_product = current.read().as_ref().and_then(|r| r.as_ref().ok()).map(|i| (i.product.clone(), i.version.clone()));
    let b = board();
    let busy = matches!(state(), Flash::Running(_));

    let flash = move |asset: FwAsset, tag: String| async move {
        armed.set(None);
        state.set(Flash::Running(FlashProgress { stage: "Starting".into(), ..Default::default() }));
        let _listener = api::on_flash_progress(move |p| state.set(Flash::Running(p)));
        match api::fw_flash(&asset.url, asset.board).await {
            Ok(()) => state.set(Flash::Done(format!("{tag} was written. The key is restarting; it reappears in a few seconds."))),
            Err(e) => state.set(Flash::Failed(humanize(&e))),
        }
    };

    let product_name = PRODUCTS.iter().find(|(p, _)| *p == product()).map(|(_, n)| *n).unwrap_or("");
    let cur_ver = cur_product.as_ref().and_then(|(_, v)| ver(v));
    // The combined build reports itself as Pico FIDO and keeps FIDO's data, so FIDO <-> combo isn't a switch.
    let switching = cur_product.as_ref().is_some_and(|(p, _)| p != product_name && !(product() == "combo" && p == "Pico FIDO"));

    rsx! {
        PageHeader { title: "Firmware", subtitle: "Install pico-keys releases from GitHub, or the unofficial FIDO + OpenPGP build." }

        Card { class: "mb-6",
            CardContent { class: "flex flex-wrap items-end gap-6",
                div { class: "flex flex-col gap-1.5",
                    Label { "Firmware" }
                    div { class: "inline-flex rounded-lg border p-0.5",
                        for (id , name) in PRODUCTS {
                            button {
                                class: "rounded-md px-3 py-1.5 text-sm transition-colors",
                                class: if product() == id { "bg-primary text-primary-foreground shadow-xs" } else { "text-muted-foreground hover:text-foreground" },
                                disabled: busy,
                                onclick: move |_| { product.set(id.to_string()); armed.set(None) },
                                "{name}"
                            }
                        }
                    }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "Board" }
                    div { class: "inline-flex rounded-lg border p-0.5",
                        for bd in BOARDS {
                            button {
                                class: "rounded-md px-3 py-1.5 text-sm transition-colors",
                                class: if b == Some(bd) { "bg-primary text-primary-foreground shadow-xs" } else { "text-muted-foreground hover:text-foreground" },
                                disabled: busy,
                                onclick: move |_| { board.set(Some(bd)); armed.set(None) },
                                "{bd.label()}"
                            }
                        }
                    }
                }
                if let Some((p, v)) = &cur_product {
                    div { class: "ml-auto text-right text-sm",
                        div { class: "text-muted-foreground", "On the key now" }
                        div { class: "font-medium", "{p} {v}" }
                    }
                }
            }
        }

        if product() == "combo" {
            Alert { class: "mb-6", variant: AlertVariant::Warning,
                TriangleAlert {}
                AlertTitle { "Unofficial firmware" }
                AlertDescription {
                    "Pico FIDO and Pico OpenPGP (with PIV) combined in one firmware, with fixes to their SDK. It's built by this app's author, not by pico-keys: "
                    "don't report its problems upstream. ESP32-S3 only. It replaces only the app slot, so the key's passkeys and settings stay; "
                    "the OpenPGP card starts empty. Take a flash backup before installing it."
                }
            }
        }

        if let Some(bd) = b {
            Warnings { board: bd, switching, from: cur_product.map(|c| c.0).unwrap_or_default(), to: product_name.to_string() }
        }

        match state() {
            Flash::Running(p) => rsx! { FlashStatus { p } },
            Flash::Done(msg) => rsx! {
                Alert { class: "mb-6", variant: AlertVariant::Success,
                    CircleCheck {}
                    AlertTitle { "Firmware installed" }
                    AlertDescription { "{msg}" }
                }
            },
            Flash::Failed(e) => rsx! { div { class: "mb-6", ErrorBox { title: "Flashing failed", msg: e } } },
            Flash::Idle => rsx! {},
        }

        match (&*releases.read(), b) {
            (_, None) => rsx! { p { class: "text-sm text-muted-foreground", "Pick the board your key is built on." } },
            (Some(Ok(list)), Some(bd)) => {
                let rows: Vec<(FwRelease, FwAsset)> = list
                    .iter()
                    .filter_map(|r| r.assets.iter().find(|a| a.board == bd).map(|a| (r.clone(), a.clone())))
                    .take(8)
                    .collect();
                rsx! {
                    Card {
                        CardHeader {
                            CardTitle { "Releases" }
                            CardDescription { "{product_name} for {bd.label()}, newest first." }
                        }
                        CardContent { class: "flex flex-col divide-y",
                            if rows.is_empty() { p { class: "py-3 text-sm text-muted-foreground", "No {bd.label()} build in recent releases." } }
                            for (i , (rel , asset)) in rows.into_iter().enumerate() {
                                div { key: "{rel.tag}", class: "flex items-center gap-3 py-3",
                                    div { class: "min-w-0 flex-1",
                                        div { class: "flex items-center gap-2 font-medium",
                                            "{rel.tag}"
                                            if i == 0 { Badge { variant: BadgeVariant::Success, "Latest" } }
                                        }
                                        div { class: "truncate text-xs text-muted-foreground", "{rel.date} · {asset.name} · {asset.size / 1024} KB" }
                                    }
                                    a {
                                        class: "text-muted-foreground hover:text-foreground",
                                        href: "https://github.com/{repo(&product())}/releases/tag/{rel.tag}",
                                        target: "_blank",
                                        title: "Release notes",
                                        ExternalLink { class: "size-4" }
                                    }
                                    if armed() == Some(rel.tag.clone()) {
                                        if !switching && cur_ver.is_some() && ver(&rel.tag) < cur_ver {
                                            span { class: "text-xs text-warning", "Older than what's installed; data saved by newer firmware may not load." }
                                        }
                                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| armed.set(None), "Cancel" }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            size: ButtonSize::Sm,
                                            disabled: busy,
                                            onclick: {
                                                let (asset, tag) = (asset.clone(), rel.tag.clone());
                                                move |_| flash(asset.clone(), tag.clone())
                                            },
                                            Zap {}
                                            "Flash now"
                                        }
                                    } else {
                                        Button {
                                            variant: if i == 0 { ButtonVariant::Default } else { ButtonVariant::Outline },
                                            size: ButtonSize::Sm,
                                            disabled: busy,
                                            onclick: { let tag = rel.tag.clone(); move |_| armed.set(Some(tag.clone())) },
                                            Download {}
                                            "Install"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (Some(Err(e)), _) => rsx! { ErrorBox { title: "Couldn't load releases", msg: humanize(e) } },
            (None, _) => rsx! { Skeleton { class: "h-64 rounded-xl" } },
        }

        if let Some(bd) = b {
            CustomFirmware { board: bd }
            if bd.is_esp() { BootLog {} }
        }
    }
}

/// Flash a local image: an ESP32 merged image or bare app image (`build/pico_fido.bin`), or a UF2.
#[component]
fn CustomFirmware(board: Board) -> Element {
    let mut path = use_signal(|| None::<String>);
    let mut armed = use_signal(|| false);
    let mut state = use_signal(|| Flash::Idle);
    let busy = matches!(state(), Flash::Running(_));
    let pick = move |_| async move {
        match api::fw_pick_file().await {
            Ok(Some(p)) => {
                path.set(Some(p));
                armed.set(false);
                state.set(Flash::Idle);
            }
            Ok(None) => {}
            Err(e) => state.set(Flash::Failed(humanize(&e))),
        }
    };
    let flash = move |_| async move {
        let Some(p) = path() else { return };
        armed.set(false);
        state.set(Flash::Running(FlashProgress { stage: "Starting".into(), ..Default::default() }));
        let _listener = api::on_flash_progress(move |p| state.set(Flash::Running(p)));
        match api::fw_flash_file(&p, board).await {
            Ok(()) => state.set(Flash::Done("Written. The key restarts and reappears in a few seconds; if it doesn't, unplug it and plug it back in, or check the boot log below.".into())),
            Err(e) => state.set(Flash::Failed(humanize(&e))),
        }
    };
    let name = path().map(|p| p.rsplit(['/', '\\']).next().unwrap_or(&p).to_string());
    rsx! {
        Card { class: "mt-6",
            CardHeader {
                CardTitle { "Custom firmware" }
                CardDescription {
                    if board.is_esp() {
                        "Flash a build you made yourself, for example with EdDSA turned on. A merged image is written like a release (keeping a signed bootloader); a bare app image (build/pico_fido.bin) only replaces the app slot at 0x20000, so passkeys and settings stay."
                    } else {
                        "Flash a UF2 you built yourself. It's checked to be a {board.label()} image first."
                    }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                Alert { variant: AlertVariant::Warning,
                    TriangleAlert {}
                    AlertTitle { "Only flash builds you trust" }
                    AlertDescription { "Firmware decides what happens to every secret on the key. Keep a way back: an official release, or a flash backup." }
                }
                div { class: "flex flex-wrap items-center gap-2",
                    Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: busy, onclick: pick, FileUp {} "Choose file…" }
                    if let Some(n) = &name { span { class: "selectable truncate font-mono text-xs", title: path().unwrap_or_default(), "{n}" } }
                    if name.is_some() {
                        if armed() {
                            Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| armed.set(false), "Cancel" }
                            Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: busy, onclick: flash, Zap {} "Flash now" }
                        } else {
                            Button { size: ButtonSize::Sm, disabled: busy, onclick: move |_| armed.set(true), Download {} "Install" }
                        }
                    }
                }
                match state() {
                    Flash::Running(p) => rsx! { FlashStatus { p } },
                    Flash::Done(msg) => rsx! { Alert { variant: AlertVariant::Success, CircleCheck {} AlertTitle { "Firmware installed" } AlertDescription { "{msg}" } } },
                    Flash::Failed(e) => rsx! { ErrorBox { title: "Flashing failed", msg: e } },
                    Flash::Idle => rsx! {},
                }
            }
        }
    }
}

/// First line that looks like a crash, if any.
fn crash_line(log: &str) -> Option<String> {
    const SIGNS: [&str; 6] = ["stack overflow", "Guru Meditation", "abort() was called", "panic", "assert failed", "Rebooting..."];
    log.lines().find(|l| SIGNS.iter().any(|s| l.contains(s))).map(|l| l.trim().to_string())
}

/// Restart the key through its COM port and show what the firmware prints while starting.
#[component]
fn BootLog() -> Element {
    let mut log = use_signal(|| None::<Result<String, String>>);
    let mut busy = use_signal(|| false);
    let capture = move |_| async move {
        busy.set(true);
        log.set(Some(api::fw_boot_log(12).await));
        busy.set(false);
    };
    rsx! {
        Card { class: "mt-6",
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "Boot log" }
                        CardDescription {
                            "When a key doesn't come back after flashing, its startup messages say why. Connect the board's second USB port (COM or UART) as well; the app restarts the key through it and records 12 seconds of output. With it connected, flashing also switches the key into download mode for you."
                        }
                    }
                    Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: busy(), onclick: capture,
                        if busy() { Spinner {} } else { ScrollText {} }
                        "Restart & record"
                    }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                match log() {
                    Some(Ok(text)) => rsx! {
                        if let Some(line) = crash_line(&text) {
                            Alert { variant: AlertVariant::Destructive,
                                TriangleAlert {}
                                AlertTitle { "The firmware crashed while starting" }
                                AlertDescription { span { class: "font-mono text-xs", "{line}" } }
                            }
                        } else if text.trim().is_empty() {
                            p { class: "text-muted-foreground", "Nothing was printed. Check that the cable carries data and the key is plugged in." }
                        }
                        pre { class: "selectable max-h-96 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap", "{text}" }
                    },
                    Some(Err(e)) => rsx! { ErrorBox { title: "Couldn't record the boot log", msg: humanize(&e) } },
                    None => rsx! {},
                }
            }
        }
    }
}

#[component]
fn FlashStatus(p: FlashProgress) -> Element {
    let pct = if p.total > 0 { (p.done as f64 / p.total as f64 * 100.0).min(100.0) } else { 0.0 };
    rsx! {
        Card { class: "mb-6",
            CardContent { class: "flex flex-col gap-3",
                div { class: "flex items-center gap-2 text-sm font-medium",
                    Spinner {}
                    "{p.stage}…"
                    if p.total > 0 { span { class: "ml-auto tabular-nums text-muted-foreground", "{pct:.0}%" } }
                }
                Progress { value: pct }
                p { class: "text-xs text-muted-foreground", "Don't unplug the key until this finishes." }
            }
        }
    }
}

#[component]
fn Warnings(board: Board, switching: bool, from: String, to: String) -> Element {
    rsx! {
        div { class: "mb-6 flex flex-col gap-3",
            if board == Board::Rp2040 {
                Alert { variant: AlertVariant::Warning,
                    TriangleAlert {}
                    AlertTitle { "RP2040 can't protect your keys" }
                    AlertDescription {
                        "The RP2040 has no secure boot, no one-time-programmable key storage and no flash encryption. "
                        "Anyone holding the key can put it in BOOTSEL mode and read the whole flash, including credential secrets. "
                        "Fine for testing; use an RP2350 or ESP32-S3 board for accounts that matter."
                    }
                }
            }
            if switching {
                Alert { variant: AlertVariant::Warning,
                    TriangleAlert {}
                    AlertTitle { "Switching from {from} to {to}" }
                    AlertDescription {
                        "The new firmware won't use what the current one stored (passkeys, accounts, keys). "
                        "Treat it as a fresh key, and keep other ways into your accounts before switching."
                    }
                }
            }
            if board.is_esp() {
                Alert { variant: AlertVariant::Info,
                    AlertTitle { "Put the key in download mode first" }
                    AlertDescription {
                        "Unplug the key, hold its BOOT button while plugging it back in, then release it and click Install. "
                        "If the board's COM port is connected too, the app does this for you. "
                        "Only the program area is rewritten; passkeys and settings on the key are kept when updating the same firmware."
                    }
                }
            } else {
                Alert { variant: AlertVariant::Info,
                    AlertTitle { "The key restarts into update mode" }
                    AlertDescription {
                        "You'll be asked to touch the key so it restarts as a USB drive, then the update is copied onto it. "
                        "If the key doesn't respond, unplug it, hold BOOTSEL while plugging it back in, and click Install again."
                    }
                }
            }
        }
    }
}
