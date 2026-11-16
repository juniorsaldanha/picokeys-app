//! OpenPGP page (Pico OpenPGP firmware): card status, an SSH key made on the card (ssh-rsa for
//! servers that accept nothing else), PINs, cardholder data, reset. Other key generation stays with gpg.
use crate::api;
use crate::pages::{ErrorBox, PageHeader};
use dioxus::prelude::*;
use icons::{FileKey, KeyRound, Plug, RefreshCw, RotateCcw};
use types::{PgpKey, PgpStatus};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;

#[component]
pub fn PgpPage() -> Element {
    let mut status = use_resource(api::pgp_status);
    let refresh = move |_| status.restart();
    rsx! {
        PageHeader { title: "OpenPGP", subtitle: "Smart-card keys for gpg: signing, encryption and SSH authentication.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| status.restart(), RefreshCw {} "Refresh" }
        }
        match &*status.read() {
            Some(Ok(s)) => rsx! {
                div { class: "grid gap-4 lg:grid-cols-2",
                    Overview { s: s.clone() }
                    Keys { keys: s.keys.clone() }
                }
                SshKey { ssh: s.ssh.clone(), on_change: refresh }
                Pins { s: s.clone(), on_change: refresh }
                Cardholder { s: s.clone(), on_change: refresh }
                Reset { on_change: refresh }
            },
            Some(Err(e)) if e.contains("isn't running Pico OpenPGP") => rsx! {
                Card {
                    CardHeader {
                        CardTitle { "This key isn't running Pico OpenPGP" }
                        CardDescription {
                            "OpenPGP is a separate firmware. Flashing it from the Firmware page replaces Pico FIDO on this key, so passkeys, the authenticator and OTP slots go away until you flash Pico FIDO back."
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! { ErrorBox { title: "Couldn't read the OpenPGP card", msg: e.clone() } },
            None => rsx! { Skeleton { class: "h-64 rounded-xl" } },
        }
    }
}

fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "—".into())
}

#[component]
fn Overview(s: PgpStatus) -> Element {
    rsx! {
        Card {
            CardHeader { CardTitle { "Card" } }
            CardContent { class: "flex flex-col gap-1.5 text-sm",
                for (k, v) in [
                    ("OpenPGP version", s.version.clone()),
                    ("Serial", s.serial.clone()),
                    ("Cardholder", opt(&s.name)),
                    ("Public key URL", opt(&s.url)),
                    ("Language", opt(&s.language)),
                    ("Signatures made", s.signatures.to_string()),
                ] {
                    div { class: "flex justify-between gap-3",
                        span { class: "text-muted-foreground", "{k}" }
                        span { class: "selectable truncate font-medium", "{v}" }
                    }
                }
            }
        }
    }
}

fn fingerprint(hex: &str) -> String {
    hex.to_uppercase().as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

#[component]
fn Keys(keys: Vec<PgpKey>) -> Element {
    rsx! {
        Card {
            CardHeader {
                CardTitle { "Keys" }
                CardDescription { "Generate or import keys with " code { class: "font-mono", "gpg --card-edit" } " (admin → generate) or " code { class: "font-mono", "keytocard" } "." }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                for k in keys {
                    div { key: "{k.slot}", class: "flex flex-col gap-0.5",
                        div { class: "flex items-center justify-between",
                            span { class: "flex items-center gap-1.5 font-medium", FileKey { class: "size-4" } "{k.slot}" }
                            if k.fingerprint.is_some() {
                                Badge { variant: BadgeVariant::Secondary, "{k.algorithm}" }
                            } else {
                                Badge { variant: BadgeVariant::Outline, "Empty" }
                            }
                        }
                        if let Some(fp) = &k.fingerprint {
                            p { class: "selectable font-mono text-xs text-muted-foreground", "{fingerprint(fp)}" }
                        }
                        if let Some(t) = k.created {
                            p { class: "text-xs text-muted-foreground",
                                "Created {js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(t as f64 * 1000.0)).to_locale_date_string(\"default\", &wasm_bindgen::JsValue::UNDEFINED)}"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Pins(s: PgpStatus, on_change: EventHandler<()>) -> Element {
    let tries = |n: u8| if n == 0 { BadgeVariant::Destructive } else { BadgeVariant::Secondary };
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { "PINs" }
                CardDescription { "The PIN unlocks signing and decryption; the Admin PIN changes the card. Defaults are 123456 and 12345678." }
            }
            CardContent { class: "flex flex-col gap-4 text-sm",
                div { class: "flex flex-wrap gap-2",
                    Badge { variant: tries(s.user_pin_tries), "PIN: {s.user_pin_tries} tries left" }
                    Badge { variant: tries(s.admin_pin_tries), "Admin PIN: {s.admin_pin_tries} tries left" }
                    if s.reset_code_tries > 0 { Badge { variant: BadgeVariant::Secondary, "Reset code: {s.reset_code_tries} tries left" } }
                }
                if s.kdf {
                    p { class: "rounded-lg bg-muted px-3 py-2.5 text-xs text-muted-foreground",
                        "This card hashes PINs before sending them (KDF), so change them with " code { "gpg --card-edit" } " → passwd."
                    }
                } else {
                    div { class: "grid gap-4 lg:grid-cols-3",
                        PinForm { title: "Change PIN", first: "Current PIN", min: 6, op: PinOp::User, on_change }
                        PinForm { title: "Change Admin PIN", first: "Current Admin PIN", min: 8, op: PinOp::Admin, on_change }
                        PinForm { title: "Unblock / reset PIN", first: "Admin PIN", min: 6, op: PinOp::Unblock, on_change }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum PinOp {
    User,
    Admin,
    Unblock,
}

#[component]
fn PinForm(title: &'static str, first: &'static str, min: usize, op: PinOp, on_change: EventHandler<()>) -> Element {
    let mut old = use_signal(String::new);
    let mut new = use_signal(String::new);
    let mut again = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let ok = !old().is_empty() && new().len() >= min && new() == again();
    let run = move |_| async move {
        busy.set(true);
        let (o, n) = (old.peek().clone(), new.peek().clone());
        let r = match op {
            PinOp::User => api::pgp_change_pin(false, &o, &n).await,
            PinOp::Admin => api::pgp_change_pin(true, &o, &n).await,
            PinOp::Unblock => api::pgp_reset_pin(&o, &n).await,
        };
        if r.is_ok() {
            old.set(String::new());
            new.set(String::new());
            again.set(String::new());
        }
        msg.set(Some(r.map(|_| "Changed.".into())));
        busy.set(false);
        on_change.call(());
    };
    rsx! {
        div { class: "flex flex-col gap-2",
            p { class: "font-medium", "{title}" }
            Label { "{first}" }
            Input { r#type: InputType::Password, value: old(), oninput: move |e: FormEvent| old.set(e.value()) }
            Label { "New (at least {min} characters)" }
            Input { r#type: InputType::Password, value: new(), oninput: move |e: FormEvent| new.set(e.value()) }
            Label { "Repeat new" }
            Input { r#type: InputType::Password, value: again(), oninput: move |e: FormEvent| again.set(e.value()) }
            if !again().is_empty() && new() != again() { p { class: "text-xs text-destructive", "Doesn't match." } }
            Button { size: ButtonSize::Sm, disabled: !ok || busy(), onclick: run,
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
fn Cardholder(s: PgpStatus, on_change: EventHandler<()>) -> Element {
    let mut name = use_signal(|| s.name.clone().unwrap_or_default());
    let mut url = use_signal(|| s.url.clone().unwrap_or_default());
    let mut admin = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let run = move |_| async move {
        busy.set(true);
        let (a, n, u) = (admin.peek().clone(), name.peek().clone(), url.peek().clone());
        let r = api::pgp_set_cardholder(&a, &n, &u).await;
        if r.is_ok() {
            admin.set(String::new());
        }
        msg.set(Some(r.map(|_| "Saved.".into())));
        busy.set(false);
        on_change.call(());
    };
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { "Cardholder" }
                CardDescription { "Shown by gpg --card-status. The URL lets gpg fetch your public key on a new computer (gpg --card-edit → fetch)." }
            }
            CardContent { class: "grid gap-3 text-sm lg:grid-cols-3",
                div { class: "flex flex-col gap-1.5",
                    Label { "Name" }
                    Input { value: name(), placeholder: "Given Surname", oninput: move |e: FormEvent| name.set(e.value()) }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "Public key URL" }
                    Input { value: url(), placeholder: "https://…/key.asc", oninput: move |e: FormEvent| url.set(e.value()) }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "Admin PIN" }
                    div { class: "flex gap-2",
                        Input { r#type: InputType::Password, value: admin(), oninput: move |e: FormEvent| admin.set(e.value()) }
                        Button { size: ButtonSize::Sm, class: "h-9", disabled: admin().len() < 8 || busy(), onclick: run,
                            if busy() { Spinner {} }
                            "Save"
                        }
                    }
                }
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-xs text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-xs text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}

#[component]
fn Reset(on_change: EventHandler<()>) -> Element {
    let mut open = use_signal(|| false);
    let mut admin = use_signal(String::new);
    let mut phrase = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let run = move |_| async move {
        busy.set(true);
        let a = admin.peek().clone();
        let ph = phrase.peek().clone();
        let r = api::pgp_factory_reset(Some(a.as_str()).filter(|a| !a.is_empty()), &ph).await;
        msg.set(Some(r.map(|_| "OpenPGP was reset. PINs are back to 123456 / 12345678.".into())));
        phrase.set(String::new());
        admin.set(String::new());
        busy.set(false);
        on_change.call(());
    };
    rsx! {
        Card { class: "mt-4 border-destructive/40",
            CardHeader {
                CardTitle { "Reset OpenPGP" }
                CardDescription { "Erases the three keys and the cardholder data and restores the default PINs. Keys generated on the card can't be recovered." }
            }
            CardContent { class: "flex flex-col gap-2 text-sm",
                if !open() {
                    div { Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| open.set(true), RotateCcw {} "Reset OpenPGP…" } }
                } else {
                    div { class: "grid max-w-xl gap-2 sm:grid-cols-2",
                        div { class: "flex flex-col gap-1.5",
                            Label { "Admin PIN (leave empty if it's blocked)" }
                            Input { r#type: InputType::Password, value: admin(), oninput: move |e: FormEvent| admin.set(e.value()) }
                        }
                        div { class: "flex flex-col gap-1.5",
                            Label { "Type RESET OPENPGP" }
                            Input { class: "font-mono", value: phrase(), oninput: move |e: FormEvent| phrase.set(e.value()) }
                        }
                    }
                    div { class: "flex gap-2",
                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| open.set(false), "Cancel" }
                        Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: busy() || phrase() != "RESET OPENPGP", onclick: run,
                            if busy() { Spinner {} }
                            "Erase OpenPGP keys"
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

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprint_groups() {
        assert_eq!(super::fingerprint("abcdef0123456789"), "ABCD EF01 2345 6789");
    }
}

const SSH_TYPES: [(&str, &str); 5] = [
    ("rsa4096", "RSA 4096 (ssh-rsa)"),
    ("rsa3072", "RSA 3072 (ssh-rsa)"),
    ("rsa2048", "RSA 2048 (ssh-rsa)"),
    ("ed25519", "Ed25519 (ssh-ed25519)"),
    ("p256", "ECDSA P-256 (ecdsa-sha2-nistp256)"),
];

/// The authentication key as an SSH key: show it, make a new one, offer it to the built-in agent.
#[component]
fn SshKey(ssh: Option<String>, on_change: EventHandler<()>) -> Element {
    let mut algorithm = use_signal(|| "rsa4096".to_string());
    let mut admin = use_signal(String::new);
    let mut replace = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let mut pin = use_signal(String::new);
    let mut agent = use_resource(api::agent_status);
    let mut agent_msg = use_signal(|| None::<Result<String, String>>);
    let has_key = ssh.is_some();
    let generate = move |_| async move {
        busy.set(true);
        msg.set(None);
        let (a, alg) = (admin.peek().clone(), algorithm.peek().clone());
        let r = api::pgp_ssh_generate(&a, &alg).await;
        if r.is_ok() {
            admin.set(String::new());
            replace.set(false);
            on_change.call(());
        }
        msg.set(Some(r.map(|_| "New SSH key made on the card. Add its public key below to the servers you use.".into())));
        busy.set(false);
    };
    let offer = move |on: bool| async move {
        let p = pin.peek().clone();
        let r = api::agent_pgp(on.then_some(p.as_str())).await;
        if r.is_ok() {
            pin.set(String::new());
        }
        agent_msg.set(Some(r.map(|_| if on { "The agent now offers this key.".into() } else { "The agent stopped offering this key.".into() })));
        agent.restart();
    };
    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    let rsa_slow = algorithm().starts_with("rsa");
    let ag = agent.read().clone().and_then(|r| r.ok());
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { class: "flex items-center gap-2", KeyRound { class: "size-4" } "SSH key" }
                CardDescription {
                    "The card's authentication key, used as a regular SSH key: ssh-rsa for services that accept nothing else (Azure DevOps, many hosting panels). It's made on the card and can't be copied off it. The app's built-in agent signs with it, so you don't need gpg."
                }
            }
            CardContent { class: "flex flex-col gap-4 text-sm",
                if let Some(line) = &ssh {
                    div { class: "flex flex-col gap-2",
                        code { class: "selectable block truncate rounded bg-muted px-2 py-1 font-mono text-xs text-muted-foreground", "{line}" }
                        div { class: "flex flex-wrap gap-2",
                            crate::ssh::CopyButton { text: line.clone(), label: "Copy public key" }
                        }
                    }
                } else {
                    p { class: "text-muted-foreground", "No SSH key on the card yet. Make one below." }
                }

                div { class: "flex flex-col gap-3 rounded-lg border p-3",
                    p { class: "font-medium", if has_key { "Replace with a new key" } else { "Make a key" } }
                    div { class: "grid gap-3 sm:grid-cols-2",
                        div { class: "flex flex-col gap-1.5",
                            Label { "Type" }
                            select { class: select_cls, onchange: move |e: FormEvent| algorithm.set(e.value()),
                                for (v, l) in SSH_TYPES { option { value: v, selected: algorithm() == v, "{l}" } }
                            }
                        }
                        div { class: "flex flex-col gap-1.5",
                            Label { "Admin PIN" }
                            Input { r#type: InputType::Password, value: admin(), placeholder: "Factory default: 12345678", oninput: move |e: FormEvent| admin.set(e.value()) }
                        }
                    }
                    if rsa_slow { p { class: "text-xs text-muted-foreground", "RSA keys take a while to make on the key: up to a few minutes for 4096 bits. Leave it plugged in." } }
                    if has_key {
                        label { class: "flex items-start gap-2 text-xs",
                            input { r#type: "checkbox", class: "mt-0.5", checked: replace(), onchange: move |e: FormEvent| replace.set(e.checked()) }
                            "Replace the current key. Servers that trust it will stop accepting it, and it can't be recovered."
                        }
                    }
                    div {
                        Button { size: ButtonSize::Sm, disabled: busy() || admin().len() < 8 || (has_key && !replace()), onclick: generate,
                            if busy() { Spinner {} } else { KeyRound {} }
                            if busy() { "Making the key…" } else if has_key { "Replace key" } else { "Make key" }
                        }
                    }
                    match msg() {
                        Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                        Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                        None => rsx! {},
                    }
                }

                if has_key {
                    div { class: "flex flex-col gap-3 rounded-lg border p-3",
                        div { class: "flex items-center justify-between gap-3",
                            p { class: "font-medium", "Use with the built-in SSH agent" }
                            if ag.as_ref().is_some_and(|a| a.pgp) { Badge { variant: BadgeVariant::Success, "Offered" } }
                        }
                        p { class: "text-xs text-muted-foreground",
                            "Enter the card's PIN (not the Admin PIN) to have the agent offer this key. The PIN stays in memory until you stop it or quit the app. Turn the agent on and point ssh at it on the SSH & Git page."
                        }
                        if ag.as_ref().is_some_and(|a| !a.running) {
                            p { class: "text-xs text-warning", "The agent isn't running. Start it on the SSH & Git page." }
                        }
                        if ag.as_ref().is_some_and(|a| a.pgp) {
                            div { Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| offer(false), "Stop offering" } }
                        } else {
                            div { class: "flex flex-wrap items-end gap-2",
                                div { class: "flex flex-col gap-1.5",
                                    Label { "PIN" }
                                    Input { r#type: InputType::Password, value: pin(), placeholder: "Factory default: 123456", oninput: move |e: FormEvent| pin.set(e.value()) }
                                }
                                Button { size: ButtonSize::Sm, disabled: pin().len() < 6, onclick: move |_| offer(true), Plug {} "Offer key" }
                            }
                        }
                        match agent_msg() {
                            Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                            Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                            None => rsx! {},
                        }
                    }
                }
            }
        }
    }
}
