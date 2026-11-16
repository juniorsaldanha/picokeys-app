//! Pico Keys hardware page: rescue-applet info, PHY settings, FIDO factory reset.
use crate::pages::{ErrorBox, PageHeader, humanize};
use crate::{AppState, api};
use dioxus::prelude::*;
use icons::{Cpu, HardDrive, RefreshCw, RotateCcw, Save, ShieldCheck, TriangleAlert, Usb};
use types::{Phy, PicoInfo};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::progress::Progress;
use crate::ui::separator::Separator;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;
use crate::ui::switch::Switch;

#[component]
pub fn DevicePage() -> Element {
    let mut info = use_resource(|| api::pico_info());
    rsx! {
        PageHeader { title: "Device", subtitle: "Pico Keys hardware and configuration.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| info.restart(), RefreshCw {} "Refresh" }
        }
        match &*info.read() {
            Some(Ok(i)) => rsx! { DeviceBody { info: i.clone() } },
            Some(Err(e)) => rsx! { ErrorBox { title: "Couldn't reach the key's management interface", msg: humanize(e) } },
            None => rsx! {
                div { class: "grid gap-4 lg:grid-cols-3",
                    for _ in 0..3 { Skeleton { class: "h-44 rounded-xl" } }
                }
                Skeleton { class: "mt-4 h-96 rounded-xl" }
            },
        }
        FactoryReset {}
    }
}

fn kib(b: u32) -> String {
    if b >= 1 << 20 { format!("{:.1} MiB", b as f64 / (1 << 20) as f64) } else { format!("{} KiB", b / 1024) }
}

#[component]
fn Row(label: &'static str, children: Element) -> Element {
    rsx! {
        div { class: "flex items-center justify-between gap-3 py-1 text-sm",
            span { class: "text-muted-foreground", "{label}" }
            span { class: "selectable truncate font-medium", {children} }
        }
    }
}

#[component]
fn DeviceBody(info: PicoInfo) -> Element {
    rsx! {
        div { class: "grid gap-4 lg:grid-cols-3",
            Card {
                CardHeader { CardTitle { class: "flex items-center gap-2", Cpu { class: "size-4 text-muted-foreground" } "Hardware" } }
                CardContent {
                    Row { label: "Product", "{info.product}" }
                    Row { label: "Firmware", "{info.version}" }
                    Row { label: "Chip", "{info.mcu}" }
                    if let Some(b) = info.build { Row { label: "Build", "{b}" } }
                    Row { label: "Serial", code { class: "font-mono text-xs", "{info.serial}" } }
                }
            }
            Card {
                CardHeader { CardTitle { class: "flex items-center gap-2", HardDrive { class: "size-4 text-muted-foreground" } "Storage" } }
                CardContent {
                    if let Some(f) = info.flash.clone() {
                        div { class: "mb-3",
                            div { class: "mb-1.5 flex justify-between text-xs text-muted-foreground",
                                span { "{kib(f.used)} used" }
                                span { "{kib(f.total)} total" }
                            }
                            Progress { value: f.used as f64, max: f.total.max(1) as f64 }
                        }
                        Row { label: "Free", "{kib(f.free)}" }
                        Row { label: "Files", "{f.files}" }
                        if f.size > 0 { Row { label: "Flash chip", "{kib(f.size)}" } }
                        if let Some(fw) = f.firmware.filter(|v| *v > 0) { Row { label: "Firmware image", "{kib(fw)}" } }
                    } else {
                        p { class: "text-sm text-muted-foreground", "Not reported by this firmware." }
                    }
                }
            }
            Card {
                CardHeader { CardTitle { class: "flex items-center gap-2", ShieldCheck { class: "size-4 text-muted-foreground" } "Security" } }
                CardContent {
                    if let Some(sb) = info.secure_boot.clone() {
                        Row { label: "Secure boot",
                            if sb.enabled { Badge { variant: BadgeVariant::Success, "Enabled" } } else { Badge { variant: BadgeVariant::Muted, "Disabled" } }
                        }
                        Row { label: "Secure lock",
                            if sb.locked { Badge { variant: BadgeVariant::Success, "Locked" } } else { Badge { variant: BadgeVariant::Muted, "Unlocked" } }
                        }
                        if sb.enabled { Row { label: "Boot key", "#{sb.bootkey}" } }
                    }
                    p { class: "mt-3 rounded-lg bg-muted px-3 py-2.5 text-xs text-muted-foreground",
                        "Enabling secure boot burns one-time fuses and can't be undone, so it is read-only here."
                    }
                }
            }
        }
        Settings { phy: info.phy.clone(), esp32: info.mcu.starts_with("ESP32") }
    }
}

const LED_DRIVERS: [(u8, &str); 6] =
    [(1, "Pico GPIO"), (2, "Pimoroni RGB"), (3, "WS2812"), (4, "CYW43 (Pico W)"), (5, "NeoPixel (ESP32)"), (0xFF, "None")];
const LED_ORDERS: [&str; 6] = ["RGB", "RBG", "GRB", "GBR", "BRG", "BGR"];

fn hex16(s: &str) -> Option<u16> {
    u16::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

#[component]
fn Field(label: &'static str, hint: &'static str, children: Element) -> Element {
    rsx! {
        div { class: "flex flex-col gap-1.5",
            Label { "{label}" }
            {children}
            if !hint.is_empty() { p { class: "text-xs text-muted-foreground", "{hint}" } }
        }
    }
}

#[component]
fn Toggle(label: &'static str, hint: &'static str, checked: bool, onchange: EventHandler<bool>) -> Element {
    rsx! {
        div { class: "flex items-center justify-between gap-4 py-2",
            div {
                div { class: "text-sm font-medium", "{label}" }
                if !hint.is_empty() { div { class: "text-xs text-muted-foreground", "{hint}" } }
            }
            Switch { checked, aria_label: label, onchange: move |v| onchange.call(v) }
        }
    }
}

#[component]
fn Settings(phy: Phy, esp32: bool) -> Element {
    let original = phy.clone();
    let mut draft = use_signal(|| phy.clone());
    let mut vid = use_signal(|| phy.vid.map(|v| format!("{v:04X}")).unwrap_or_default());
    let mut pid = use_signal(|| phy.pid.map(|v| format!("{v:04X}")).unwrap_or_default());
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| None::<Result<(), String>>);

    // Build the PHY to write from the draft + text fields.
    let candidate = move || -> Result<Phy, String> {
        let mut p = draft();
        match (vid.read().trim().is_empty(), pid.read().trim().is_empty()) {
            (true, true) => (p.vid, p.pid) = (None, None),
            _ => {
                p.vid = Some(hex16(&vid.read()).ok_or("VID must be 4 hex digits")?);
                p.pid = Some(hex16(&pid.read()).ok_or("PID must be 4 hex digits")?);
            }
        }
        Ok(p)
    };
    let dirty = candidate().map(|p| p != original).unwrap_or(true);
    let invalid = candidate().err();

    let save = move |_| async move {
        let Ok(p) = candidate() else { return };
        busy.set(true);
        status.set(None);
        let r = api::write_phy(&p).await;
        busy.set(false);
        status.set(Some(r));
    };

    let opt = move |bit: u16| draft.read().opts & bit != 0;
    let mut set_opt = move |bit: u16, on: bool| draft.with_mut(|d| if on { d.opts |= bit } else { d.opts &= !bit });
    let itf = move |bit: u8| draft.read().enabled_usb_itf.unwrap_or(Phy::ITF_ALL) & bit != 0;
    let mut set_itf = move |bit: u8, on: bool| {
        draft.with_mut(|d| {
            let cur = d.enabled_usb_itf.unwrap_or(Phy::ITF_ALL);
            d.enabled_usb_itf = Some(if on { cur | bit } else { cur & !bit });
        })
    };
    let k1 = draft.read().enabled_curves.unwrap_or(0) & Phy::CURVE_SECP256K1 != 0;

    let driver_hint: &'static str = if esp32 { "ESP32 boards usually use NeoPixel" } else { "" };
    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";

    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { "Configuration" }
                CardDescription { "Stored on the key. Changes apply after you unplug and replug it." }
            }
            CardContent { class: "grid gap-8 lg:grid-cols-2",
                // USB
                div { class: "flex flex-col gap-4",
                    h3 { class: "flex items-center gap-2 text-sm font-semibold", Usb { class: "size-4 text-muted-foreground" } "USB" }
                    div { class: "grid grid-cols-2 gap-3",
                        Field { label: "Vendor ID", hint: "hex, e.g. 2E8A",
                            Input { class: "font-mono uppercase", placeholder: "default", value: vid(), oninput: move |e: FormEvent| vid.set(e.value()) }
                        }
                        Field { label: "Product ID", hint: "hex, e.g. 10FE",
                            Input { class: "font-mono uppercase", placeholder: "default", value: pid(), oninput: move |e: FormEvent| pid.set(e.value()) }
                        }
                    }
                    Field { label: "Product name", hint: "Shown by the OS. ASCII, up to 31 characters.",
                        Input {
                            placeholder: "Pico Key",
                            value: draft.read().usb_product.clone().unwrap_or_default(),
                            oninput: move |e: FormEvent| { let v = e.value(); draft.with_mut(|d| d.usb_product = (!v.is_empty()).then_some(v)) },
                        }
                    }
                    div { class: "flex flex-col",
                        Label { class: "mb-1", "Interfaces" }
                        Toggle { label: "FIDO (HID)", hint: "Passkeys, U2F", checked: itf(Phy::ITF_HID), onchange: move |v| set_itf(Phy::ITF_HID, v) }
                        Toggle { label: "Smart card (CCID)", hint: "OATH, rescue/management", checked: itf(Phy::ITF_CCID), onchange: move |v| set_itf(Phy::ITF_CCID, v) }
                        Toggle { label: "Keyboard", hint: "OTP typing", checked: itf(Phy::ITF_KB), onchange: move |v| set_itf(Phy::ITF_KB, v) }
                        Toggle { label: "WebUSB (WCID)", hint: "Driverless Windows access", checked: itf(Phy::ITF_WCID), onchange: move |v| set_itf(Phy::ITF_WCID, v) }
                    }
                }
                // LED + behaviour
                div { class: "flex flex-col gap-4",
                    h3 { class: "text-sm font-semibold", "LED & button" }
                    div { class: "grid grid-cols-2 gap-3",
                        Field { label: "LED driver", hint: driver_hint,
                            select {
                                class: select_cls,
                                onchange: move |e: FormEvent| { let v = e.value().parse::<u8>().ok(); draft.with_mut(|d| d.led_driver = v) },
                                option { value: "", selected: draft.read().led_driver.is_none(), "Default" }
                                for (id, name) in LED_DRIVERS {
                                    option { value: "{id}", selected: draft.read().led_driver == Some(id), "{name}" }
                                }
                            }
                        }
                        Field { label: "Color order", hint: "",
                            select {
                                class: select_cls,
                                onchange: move |e: FormEvent| { let v = e.value().parse::<u8>().ok(); draft.with_mut(|d| d.led_order = v) },
                                for (i, name) in LED_ORDERS.iter().enumerate() {
                                    option { value: "{i}", selected: draft.read().led_order.unwrap_or(0) as usize == i, "{name}" }
                                }
                            }
                        }
                        Field { label: "LED GPIO", hint: "Empty = board default",
                            Input {
                                r#type: InputType::Number,
                                placeholder: "default",
                                value: draft.read().led_gpio.map(|v| v.to_string()).unwrap_or_default(),
                                oninput: move |e: FormEvent| { let v = e.value().parse::<u8>().ok(); draft.with_mut(|d| d.led_gpio = v) },
                            }
                        }
                        Field { label: "Button timeout", hint: "Seconds to wait for a touch. 0 = off",
                            Input {
                                r#type: InputType::Number,
                                placeholder: "0",
                                value: draft.read().up_btn.map(|v| v.to_string()).unwrap_or_default(),
                                oninput: move |e: FormEvent| { let v = e.value().parse::<u8>().ok(); draft.with_mut(|d| d.up_btn = v) },
                            }
                        }
                    }
                    Field { label: "Brightness", hint: "",
                        div { class: "flex items-center gap-3",
                            input {
                                r#type: "range",
                                min: "0",
                                max: "15",
                                class: "w-full accent-primary",
                                value: "{draft.read().led_brightness.unwrap_or(15)}",
                                oninput: move |e: FormEvent| { let v = e.value().parse::<u8>().ok(); draft.with_mut(|d| d.led_brightness = v) },
                            }
                            span { class: "w-8 text-right text-sm tabular-nums", "{draft.read().led_brightness.unwrap_or(15)}" }
                        }
                    }
                    div { class: "flex flex-col",
                        Toggle { label: "Dimmable LED", hint: "Apply the brightness setting", checked: opt(Phy::OPT_DIMM), onchange: move |v| set_opt(Phy::OPT_DIMM, v) }
                        Toggle { label: "Steady LED", hint: "No idle blinking", checked: opt(Phy::OPT_LED_STEADY), onchange: move |v| set_opt(Phy::OPT_LED_STEADY, v) }
                        Toggle { label: "Allow reset anytime", hint: "Skip the 10 s after plug-in limit for FIDO reset", checked: opt(Phy::OPT_DISABLE_POWER_RESET), onchange: move |v| set_opt(Phy::OPT_DISABLE_POWER_RESET, v) }
                        Toggle {
                            label: "secp256k1 curve",
                            hint: "Advanced: enables the Bitcoin curve (ES256K)",
                            checked: k1,
                            onchange: move |v: bool| draft.with_mut(|d| {
                                let cur = d.enabled_curves.unwrap_or(0);
                                d.enabled_curves = Some(if v { cur | Phy::CURVE_SECP256K1 } else { cur & !Phy::CURVE_SECP256K1 });
                            }),
                        }
                    }
                }
            }
            Separator {}
            CardFooter { class: "justify-between gap-3",
                div { class: "text-sm",
                    if let Some(e) = invalid.clone() {
                        span { class: "text-destructive", "{e}" }
                    } else if busy() {
                        span { class: "text-muted-foreground", "Touch the key if it blinks…" }
                    } else if let Some(Ok(())) = status() {
                        span { class: "text-success", "Saved. Replug the key to apply." }
                    } else if let Some(Err(e)) = status() {
                        span { class: "text-destructive", "{humanize(&e)}" }
                    }
                }
                div { class: "flex gap-2",
                    Button {
                        variant: ButtonVariant::Ghost,
                        disabled: !dirty || busy(),
                        onclick: move |_| {
                            draft.set(original.clone());
                            vid.set(original.vid.map(|v| format!("{v:04X}")).unwrap_or_default());
                            pid.set(original.pid.map(|v| format!("{v:04X}")).unwrap_or_default());
                            status.set(None);
                        },
                        "Discard"
                    }
                    Button { disabled: !dirty || busy() || invalid.is_some(), onclick: save,
                        if busy() { Spinner {} } else { Save {} }
                        "Save to key"
                    }
                }
            }
        }
    }
}

#[component]
fn FactoryReset() -> Element {
    let mut st = use_context::<AppState>();
    let mut armed = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| None::<Result<(), String>>);

    let reset = move |_| async move {
        let Some(d) = st.device.peek().clone() else { return };
        busy.set(true);
        status.set(None);
        let r = api::fido_reset(&d.path).await;
        if r.is_ok() {
            st.pin.set(None);
            armed.set(false);
        }
        st.info.restart();
        status.set(Some(r));
        busy.set(false);
    };

    rsx! {
        Card { class: "mt-4 border-destructive/40",
            CardHeader {
                CardTitle { class: "flex items-center gap-2 text-destructive", TriangleAlert { class: "size-4" } "Factory reset FIDO" }
                CardDescription { "Erases every passkey, the PIN and FIDO settings on this key. This can't be undone." }
            }
            CardContent {
                if !armed() {
                    Button { variant: ButtonVariant::Outline, class: "border-destructive/50 text-destructive hover:bg-destructive/10 hover:text-destructive", onclick: move |_| armed.set(true),
                        RotateCcw {} "Reset FIDO…"
                    }
                } else {
                    div { class: "flex flex-col gap-4 animate-in fade-in slide-in-from-top-1 duration-200",
                        ol { class: "list-decimal space-y-1 pl-5 text-sm text-muted-foreground",
                            li { "Unplug the key and plug it back in." }
                            li { "Within 10 seconds, click " b { class: "text-foreground", "Erase everything" } "." }
                            li { "Touch the key when it blinks." }
                        }
                        div { class: "flex gap-2",
                            Button { variant: ButtonVariant::Ghost, disabled: busy(), onclick: move |_| { armed.set(false); status.set(None) }, "Cancel" }
                            Button { variant: ButtonVariant::Destructive, disabled: busy() || st.device.read().is_none(), onclick: reset,
                                if busy() { Spinner {} } else { RotateCcw {} }
                                if busy() { "Touch the key…" } else { "Erase everything" }
                            }
                        }
                    }
                }
                match status() {
                    Some(Ok(())) => rsx! { p { class: "mt-3 text-sm text-success", "Key reset. Set a new PIN to manage passkeys." } },
                    Some(Err(e)) => rsx! { p { class: "mt-3 text-sm text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}
