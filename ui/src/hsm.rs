//! Pico HSM page: PINs, keys on the HSM, initialize. Key generation and use go through PKCS#11.
use crate::api;
use crate::pages::{ErrorBox, PageHeader};
use dioxus::prelude::*;
use icons::{FileKey, RefreshCw, RotateCcw, Trash2};
use types::{HsmKey, HsmStatus};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;

#[component]
pub fn HsmPage() -> Element {
    let mut status = use_resource(api::hsm_status);
    let refresh = move |_| status.restart();
    rsx! {
        PageHeader { title: "HSM", subtitle: "Hardware security module: keys for PKCS#11 apps (OpenSSL, browsers, code signing).",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| status.restart(), RefreshCw {} "Refresh" }
        }
        match &*status.read() {
            Some(Ok(s)) => rsx! {
                Overview { s: s.clone() }
                if s.initialized {
                    Keys { keys: s.keys.clone(), on_change: refresh }
                    Pins { on_change: refresh }
                }
                Initialize { initialized: s.initialized, on_change: refresh }
            },
            Some(Err(e)) if e.contains("isn't running Pico HSM") => rsx! {
                Card {
                    CardHeader {
                        CardTitle { "This key isn't running Pico HSM" }
                        CardDescription {
                            "Pico HSM is a separate firmware. Flashing it from the Firmware page replaces Pico FIDO on this key, so passkeys, the authenticator and OTP slots go away until you flash Pico FIDO back."
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! { ErrorBox { title: "Couldn't read the HSM", msg: e.clone() } },
            None => rsx! { Skeleton { class: "h-64 rounded-xl" } },
        }
    }
}

fn tries(label: &str, n: Option<u8>) -> Element {
    match n {
        Some(0) => rsx! { Badge { variant: BadgeVariant::Destructive, "{label}: blocked" } },
        Some(n) => rsx! { Badge { variant: BadgeVariant::Secondary, "{label}: {n} tries left" } },
        None => rsx! {},
    }
}

#[component]
fn Overview(s: HsmStatus) -> Element {
    rsx! {
        Card {
            CardHeader {
                CardTitle { "Pico HSM {s.version}" }
                CardDescription {
                    if s.initialized { "Initialized. Use it through the OpenSC PKCS#11 module (opensc-pkcs11.so) or pkcs11-tool." }
                    else { "Not initialized yet. Set a PIN and SO-PIN below to start using it." }
                }
            }
            CardContent { class: "flex flex-wrap gap-2 text-sm",
                {tries("PIN", s.pin_tries)}
                {tries("SO-PIN", s.so_pin_tries)}
                if s.transport_pin { Badge { variant: BadgeVariant::Outline, "Transport PIN set: change the PIN before first use" } }
            }
        }
    }
}

fn key_name(k: &HsmKey) -> String {
    k.label.clone().unwrap_or_else(|| format!("Key {}", k.id))
}

#[component]
fn Keys(keys: Vec<HsmKey>, on_change: EventHandler<()>) -> Element {
    let mut pin = use_signal(String::new);
    let mut confirm = use_signal(|| None::<u8>);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let del = move |id: u8| async move {
        let p = pin.peek().clone();
        let r = api::hsm_delete_key(&p, id).await;
        msg.set(Some(r.map(|_| format!("Key {id} deleted."))));
        confirm.set(None);
        on_change.call(());
    };
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { "Keys" }
                CardDescription { "Create keys with " code { class: "font-mono", "pkcs11-tool --keypairgen" } " or pico-hsm-tool. The device key isn't listed." }
            }
            CardContent { class: "flex flex-col gap-2 text-sm",
                if keys.is_empty() { p { class: "text-muted-foreground", "No keys yet." } }
                for k in keys {
                    div { key: "{k.id}", class: "flex items-center justify-between gap-3 rounded-lg bg-muted px-3 py-2",
                        div { class: "flex min-w-0 items-center gap-2",
                            FileKey { class: "size-4 shrink-0" }
                            span { class: "truncate font-medium", "{key_name(&k)}" }
                            Badge { variant: BadgeVariant::Secondary, "{k.kind}" }
                            if k.has_cert { Badge { variant: BadgeVariant::Outline, "certificate" } }
                            span { class: "font-mono text-xs text-muted-foreground", "ID {k.id}" }
                        }
                        if confirm() == Some(k.id) {
                            div { class: "flex items-center gap-2",
                                Input { r#type: InputType::Password, class: "h-8 w-32", placeholder: "PIN", value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                                Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| confirm.set(None), "Cancel" }
                                Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: pin().len() < 6,
                                    onclick: { let id = k.id; move |_| { spawn(del(id)); } }, "Delete for good" }
                            }
                        } else {
                            Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, aria_label: "Delete key",
                                onclick: { let id = k.id; move |_| confirm.set(Some(id)) }, Trash2 {} }
                        }
                    }
                }
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Pin,
    SoPin,
    Unblock,
}

#[component]
fn Pins(on_change: EventHandler<()>) -> Element {
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { "PINs" }
                CardDescription { "The PIN (6–16 characters) unlocks keys. The SO-PIN (16 hex digits; factory default 3537363231383830) unblocks the PIN and re-initializes." }
            }
            CardContent { class: "grid gap-4 text-sm lg:grid-cols-3",
                PinForm { title: "Change PIN", first: "Current PIN", second: "New PIN", op: Op::Pin, on_change }
                PinForm { title: "Change SO-PIN", first: "Current SO-PIN", second: "New SO-PIN (16 hex digits)", op: Op::SoPin, on_change }
                PinForm { title: "Unblock PIN", first: "SO-PIN", second: "New PIN", op: Op::Unblock, on_change }
            }
        }
    }
}

#[component]
fn PinForm(title: &'static str, first: &'static str, second: &'static str, op: Op, on_change: EventHandler<()>) -> Element {
    let mut a = use_signal(String::new);
    let mut b = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let run = move |_| async move {
        busy.set(true);
        let (x, y) = (a.peek().clone(), b.peek().clone());
        let r = match op {
            Op::Pin => api::hsm_change_pin(false, &x, &y).await,
            Op::SoPin => api::hsm_change_pin(true, &x, &y).await,
            Op::Unblock => api::hsm_unblock(&x, &y).await,
        };
        if r.is_ok() {
            a.set(String::new());
            b.set(String::new());
        }
        msg.set(Some(r.map(|_| "Done.".into())));
        busy.set(false);
        on_change.call(());
    };
    rsx! {
        div { class: "flex flex-col gap-2",
            p { class: "font-medium", "{title}" }
            Label { "{first}" }
            Input { r#type: InputType::Password, value: a(), oninput: move |e: FormEvent| a.set(e.value()) }
            Label { "{second}" }
            Input { r#type: InputType::Password, value: b(), oninput: move |e: FormEvent| b.set(e.value()) }
            Button { size: ButtonSize::Sm, disabled: a().is_empty() || b().is_empty() || busy(), onclick: run,
                if busy() { Spinner {} }
                "Save"
            }
            match msg() {
                Some(Ok(m)) => rsx! { p { class: "text-xs text-success", "{m}" } },
                Some(Err(e)) => rsx! { p { class: "text-xs text-destructive", "{e}" } },
                None => rsx! {},
            }
        }
    }
}

#[component]
fn Initialize(initialized: bool, on_change: EventHandler<()>) -> Element {
    let mut open = use_signal(move || !initialized);
    let mut pin = use_signal(String::new);
    let mut pin2 = use_signal(String::new);
    let mut so = use_signal(String::new);
    let mut retries = use_signal(|| "3".to_string());
    let mut phrase = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let need_phrase = initialized;
    let ready = pin().len() >= 6 && pin() == pin2() && so().len() == 16 && (!need_phrase || phrase() == "ERASE HSM");
    let run = move |_| async move {
        busy.set(true);
        let n = retries.peek().parse().unwrap_or(3);
        let (p, s, ph) = (pin.peek().clone(), so.peek().clone(), phrase.peek().clone());
        let r = api::hsm_initialize(&p, &s, n, &ph).await;
        msg.set(Some(r.map(|_| "Initialized. Keep the SO-PIN somewhere safe: it's the only way to unblock the PIN.".into())));
        pin.set(String::new());
        pin2.set(String::new());
        phrase.set(String::new());
        busy.set(false);
        on_change.call(());
    };
    rsx! {
        Card { class: if initialized { "mt-4 border-destructive/40" } else { "mt-4" },
            CardHeader {
                CardTitle { if initialized { "Re-initialize HSM" } else { "Initialize HSM" } }
                CardDescription {
                    if initialized { "Erases every key and certificate on the HSM and sets new PINs. Keys can't be recovered unless you exported them with a DKEK." }
                    else { "Sets the PIN and SO-PIN and creates a random device key. Write the SO-PIN down: it's the only way to unblock the PIN." }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                if !open() {
                    div { Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| open.set(true), RotateCcw {} "Re-initialize…" } }
                } else {
                    div { class: "grid gap-3 sm:grid-cols-2 lg:grid-cols-4",
                        div { class: "flex flex-col gap-1.5", Label { "PIN (6–16)" }
                            Input { r#type: InputType::Password, value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) } }
                        div { class: "flex flex-col gap-1.5", Label { "Repeat PIN" }
                            Input { r#type: InputType::Password, value: pin2(), oninput: move |e: FormEvent| pin2.set(e.value()) } }
                        div { class: "flex flex-col gap-1.5", Label { "SO-PIN (16 hex digits)" }
                            Input { class: "font-mono", value: so(), placeholder: "e.g. 3537363231383830", oninput: move |e: FormEvent| so.set(e.value().trim().to_uppercase()) } }
                        div { class: "flex flex-col gap-1.5", Label { "PIN tries before blocking" }
                            Input { r#type: InputType::Number, value: retries(), oninput: move |e: FormEvent| retries.set(e.value()) } }
                    }
                    if need_phrase {
                        div { class: "flex max-w-xs flex-col gap-1.5", Label { "Type ERASE HSM" }
                            Input { class: "font-mono", value: phrase(), oninput: move |e: FormEvent| phrase.set(e.value()) } }
                    }
                    div { class: "flex gap-2",
                        if initialized { Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| open.set(false), "Cancel" } }
                        Button { variant: if initialized { ButtonVariant::Destructive } else { ButtonVariant::Default }, size: ButtonSize::Sm, disabled: !ready || busy(), onclick: run,
                            if busy() { Spinner {} }
                            if initialized { "Erase and initialize" } else { "Initialize" }
                        }
                    }
                }
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}
