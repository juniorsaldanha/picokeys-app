mod api;
mod device;
mod firmware;
mod hsm;
mod migrate;
mod oath;
mod otp;
mod pages;
mod pgp;
mod policy;
mod ssh;
mod ui;

use dioxus::prelude::*;
use icons::{Cpu, FileKey, Vault, Terminal, HardDriveDownload, Hand, KeyRound, LayoutDashboard, RectangleEllipsis, ShieldCheck, Usb};
use types::{Device, FidoInfo};
use ui::spinner::Spinner;
use ui::theme_toggle::ThemeToggle;

const CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq)]
pub enum Page {
    Overview,
    Passkeys,
    Pin,
    Device,
    Oath,
    Otp,
    Firmware,
    Ssh,
    Pgp,
    Hsm,
}

/// App-wide state. Signals are `Copy`, so pages grab this via `use_context`.
#[derive(Clone, Copy)]
pub struct AppState {
    pub device: Signal<Option<Device>>,
    pub info: Resource<Option<Result<FidoInfo, String>>>,
    /// PIN kept in memory for this session only, cleared when the device changes.
    pub pin: Signal<Option<String>>,
}

#[component]
fn App() -> Element {
    let mut devices = use_signal(Vec::<Device>::new);
    let mut device = use_signal(|| None::<Device>);
    let mut pin = use_signal(|| None::<String>);
    let mut scanned = use_signal(|| false);
    let page = use_signal(|| Page::Overview);

    // Hot-plug: poll HID enumeration (cheap) and only touch state when it changes.
    use_future(move || async move {
        loop {
            if let Ok(list) = api::list_devices().await
                && *devices.peek() != list {
                    let keep = device.peek().clone().filter(|d| list.contains(d));
                    if keep.is_none() {
                        pin.set(None);
                    }
                    device.set(keep.or_else(|| list.first().cloned()));
                    devices.set(list);
                }
            scanned.set(true);
            api::sleep_ms(1200).await;
        }
    });

    let info = use_resource(move || async move {
        let d = device()?;
        Some(api::fido_info(&d.path).await)
    });

    use_context_provider(|| AppState { device, info, pin });

    rsx! {
        document::Stylesheet { href: CSS }
        div { class: "flex h-screen overflow-hidden bg-background text-foreground",
            Sidebar { devices, page }
            main { class: "flex-1 overflow-y-auto",
                if device().is_none() {
                    NoDevice { scanning: !scanned() }
                } else {
                    div { class: "mx-auto max-w-5xl px-8 py-8 animate-in fade-in duration-300",
                        match page() {
                            Page::Overview => rsx! { pages::Overview {} },
                            Page::Passkeys => rsx! { pages::Passkeys {} },
                            Page::Pin => rsx! { pages::PinPage {} },
                            Page::Device => rsx! { device::DevicePage {} },
                            Page::Oath => rsx! { oath::OathPage {} },
                            Page::Otp => rsx! { otp::OtpPage {} },
                            Page::Firmware => rsx! { firmware::FirmwarePage {} },
                            Page::Pgp => rsx! { pgp::PgpPage {} },
                            Page::Hsm => rsx! { hsm::HsmPage {} },
                            Page::Ssh => rsx! { ssh::SshPage {} },
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Sidebar(devices: Signal<Vec<Device>>, page: Signal<Page>) -> Element {
    let mut st = use_context::<AppState>();
    let fw = match &*st.info.read() {
        Some(Some(Ok(i))) => format!("Pico FIDO {}", i.firmware),
        _ => "Pico FIDO".into(),
    };
    rsx! {
        aside { class: "flex w-64 shrink-0 flex-col border-r bg-muted/40 px-3 py-4",
            // brand
            div { class: "flex items-center gap-2.5 px-2 pb-5",
                div { class: "flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-brand-from to-brand-to text-white shadow-sm",
                    KeyRound { class: "size-4" }
                }
                div { class: "leading-tight",
                    div { class: "text-sm font-semibold", "Pico Key Manager" }
                    div { class: "text-[11px] text-muted-foreground", "Open source · GPL-3.0" }
                }
            }

            // devices
            div { class: "px-2 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground", "Devices" }
            div { class: "flex flex-col gap-1 pb-4",
                if devices.read().is_empty() {
                    div { class: "rounded-lg border border-dashed px-3 py-2.5 text-xs text-muted-foreground", "No key connected" }
                }
                for d in devices.read().iter().cloned() {
                    {
                        let active = st.device.read().as_ref() == Some(&d);
                        let cls = if active { "bg-card border shadow-xs" } else { "border border-transparent hover:bg-accent/60" };
                        let dd = d.clone();
                        rsx! {
                            button {
                                key: "{d.path}",
                                class: "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors {cls}",
                                onclick: move |_| {
                                    if st.device.peek().as_ref() != Some(&dd) {
                                        st.pin.set(None);
                                        st.device.set(Some(dd.clone()));
                                    }
                                },
                                span { class: "relative flex size-2",
                                    span { class: "absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60" }
                                    span { class: "relative inline-flex size-2 rounded-full bg-success" }
                                }
                                div { class: "min-w-0",
                                    div { class: "truncate text-sm font-medium", "{d.product}" }
                                    div { class: "truncate text-[11px] text-muted-foreground",
                                        if active { "{fw}" } else { "{d.vid:04X}:{d.pid:04X}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // nav
            div { class: "px-2 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground", "FIDO" }
            nav { class: "flex flex-col gap-0.5",
                NavItem { page, target: Page::Overview, label: "Overview", icon: rsx! { LayoutDashboard {} } }
                NavItem { page, target: Page::Passkeys, label: "Passkeys", icon: rsx! { KeyRound {} } }
                NavItem { page, target: Page::Pin, label: "PIN", icon: rsx! { RectangleEllipsis {} } }
            }
            div { class: "px-2 pb-1.5 pt-4 text-[11px] font-medium uppercase tracking-wider text-muted-foreground", "Pico" }
            nav { class: "flex flex-col gap-0.5",
                NavItem { page, target: Page::Oath, label: "Authenticator", icon: rsx! { ShieldCheck {} } }
                NavItem { page, target: Page::Ssh, label: "SSH & Git", icon: rsx! { Terminal {} } }
                NavItem { page, target: Page::Otp, label: "OTP slots", icon: rsx! { Hand {} } }
                NavItem { page, target: Page::Pgp, label: "OpenPGP", icon: rsx! { FileKey {} } }
                NavItem { page, target: Page::Hsm, label: "HSM", icon: rsx! { Vault {} } }
                NavItem { page, target: Page::Device, label: "Device", icon: rsx! { Cpu {} } }
                NavItem { page, target: Page::Firmware, label: "Firmware", icon: rsx! { HardDriveDownload {} } }
            }

            div { class: "flex-1" }
            div { class: "flex items-center justify-between px-2 text-xs text-muted-foreground",
                span { "v{env!(\"CARGO_PKG_VERSION\")}" }
                ThemeToggle {}
            }
        }
    }
}

#[component]
fn NavItem(page: Signal<Page>, target: Page, label: &'static str, icon: Element) -> Element {
    let active = page() == target;
    let cls = if active {
        "bg-primary/10 text-primary font-medium"
    } else {
        "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
    };
    rsx! {
        button {
            class: "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors [&_svg]:size-4 {cls}",
            onclick: move |_| page.set(target),
            {icon}
            "{label}"
        }
    }
}

#[component]
fn NoDevice(scanning: bool) -> Element {
    rsx! {
        div { class: "flex h-full flex-col items-center justify-center gap-5 p-8 text-center animate-in fade-in duration-500",
            div { class: "relative",
                div { class: "absolute inset-0 animate-ping rounded-3xl bg-primary/15" }
                div { class: "relative flex size-20 items-center justify-center rounded-3xl bg-gradient-to-br from-brand-from to-brand-to text-white shadow-lg",
                    Usb { class: "size-9" }
                }
            }
            div { class: "space-y-1.5",
                h1 { class: "text-xl font-semibold", "Plug in your Pico Key" }
                p { class: "max-w-sm text-sm text-muted-foreground",
                    "Connect a key running Pico FIDO. It will show up here automatically."
                }
            }
            div { class: "flex items-center gap-2 text-xs text-muted-foreground",
                Spinner { class: "size-3.5" }
                if scanning { "Starting…" } else { "Waiting for device" }
            }
        }
    }
}
