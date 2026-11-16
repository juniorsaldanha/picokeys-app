//! FIDO policy (authenticatorConfig) card for the PIN page, and per-passkey controls.
use crate::pages::humanize;
use crate::{AppState, api};
use dioxus::prelude::*;
use icons::{Ban, CalendarClock, Check, Hand, ShieldCheck};
use types::{FidoInfo, FidoPolicy};

use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::spinner::Spinner;
use crate::ui::switch::Switch;

fn opt(info: &FidoInfo, k: &str) -> Option<bool> {
    info.options.iter().find(|(n, _)| n == k).map(|(_, v)| *v)
}

#[component]
pub fn PolicyCard(info: FidoInfo) -> Element {
    let mut st = use_context::<AppState>();
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());
    let mut busy = use_signal(|| None::<&'static str>);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let mut min_len = use_signal(String::new);
    let mut rp_ids = use_signal(String::new);
    let mut force = use_signal(|| false);
    let mut classes = use_signal(|| 0u16);
    let mut ep_armed = use_signal(|| false);

    let apply = move |tag: &'static str, change: FidoPolicy, ok: String| async move {
        let Some(d) = st.device.peek().clone() else { return };
        busy.set(Some(tag));
        msg.set(None);
        let p = pin.peek().clone();
        let r = api::fido_policy(&d.path, &p, &change).await;
        if r.is_ok() && st.pin.peek().is_none() {
            st.pin.set(Some(p)); // proven correct, reuse for this session
        }
        msg.set(Some(r.map(|_| ok).map_err(|e| humanize(&e))));
        st.info.restart();
        busy.set(None);
    };

    let always_uv = opt(&info, "alwaysUv").unwrap_or(false);
    let rk = opt(&info, "rk").unwrap_or(true);
    let mcuv = opt(&info, "makeCredUvNotRqd").unwrap_or(false);
    let ep = opt(&info, "ep");
    let no_pin = pin.read().is_empty();
    let locked = busy().is_some() || no_pin;
    let cur_min = info.min_pin_length.max(4);

    let row = |title: &'static str, desc: &'static str, on: bool, disabled: bool, tag: &'static str, change: FidoPolicy, ok: &'static str| {
        rsx! {
            div { class: "flex items-start justify-between gap-4 py-3",
                div {
                    div { class: "text-sm font-medium", "{title}" }
                    p { class: "text-xs text-muted-foreground", "{desc}" }
                }
                div { class: "flex items-center gap-2",
                    if busy() == Some(tag) { Spinner {} }
                    Switch {
                        checked: on,
                        disabled: locked || disabled,
                        aria_label: title,
                        onchange: move |_| { spawn(apply(tag, change.clone(), ok.to_string())); },
                    }
                }
            }
        }
    };

    rsx! {
        Card { class: "mt-4",
            CardHeader {
                CardTitle { class: "flex items-center gap-2", ShieldCheck { class: "size-4" } "Key policy" }
                CardDescription { "Rules the key enforces for every site. Changing them needs the PIN." }
            }
            CardContent { class: "flex flex-col",
                div { class: "flex max-w-xs flex-col gap-1.5 pb-2",
                    Label { "PIN" }
                    Input { r#type: InputType::Password, value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                }
                div { class: "divide-y",
                    {row("Always require PIN", "Every sign-in asks for the PIN, even where the site doesn't.", always_uv, false, "auv",
                        FidoPolicy::AlwaysUv, "Updated \"Always require PIN\".")}
                    {row("Store passkeys on the key", "Off: sites can't create discoverable passkeys (usernameless sign-in).", rk, false, "rk",
                        FidoPolicy::Toggle { which: "nork".into() }, "Updated passkey storage.")}
                    {row("Create passkeys without PIN", "Sites may register without the PIN; signing in still follows the rules above.", mcuv, always_uv, "mcuv",
                        FidoPolicy::Toggle { which: "mcuv".into() }, "Updated PIN-less registration.")}

                    div { class: "flex flex-col gap-2 py-3",
                        div { class: "text-sm font-medium", "Minimum PIN length" }
                        p { class: "text-xs text-muted-foreground", "Now {cur_min}. It can only be raised; lowering it needs a factory reset." }
                        div { class: "flex flex-wrap items-end gap-2",
                            Input { class: "w-24", r#type: InputType::Number, placeholder: "{cur_min + 2}", value: min_len(), oninput: move |e: FormEvent| min_len.set(e.value()) }
                            Input { class: "min-w-48 flex-1", placeholder: "sites allowed to see it (optional), e.g. login.example.com", value: rp_ids(), oninput: move |e: FormEvent| rp_ids.set(e.value()) }
                        }
                        label { class: "flex items-center gap-2 text-sm",
                            input { r#type: "checkbox", checked: force(), onchange: move |e: FormEvent| force.set(e.checked()) }
                            "Make me change the PIN on next use"
                        }
                        div {
                            Button {
                                size: ButtonSize::Sm,
                                disabled: locked || (min_len.read().is_empty() && rp_ids.read().trim().is_empty() && !force()),
                                onclick: move |_| {
                                    let len = min_len.peek().trim().parse::<u32>().unwrap_or(0);
                                    let ids: Vec<String> = rp_ids.peek().split([',', ' ']).filter(|s| !s.is_empty()).map(String::from).collect();
                                    spawn(apply("min", FidoPolicy::MinPin { len, rp_ids: ids, force_change: force() }, "PIN length rules updated.".into()));
                                },
                                if busy() == Some("min") { Spinner {} } else { Check {} }
                                "Apply"
                            }
                        }
                    }

                    div { class: "flex flex-col gap-2 py-3",
                        div { class: "text-sm font-medium", "PIN must contain" }
                        p { class: "text-xs text-muted-foreground", "Applies to new PINs. Clear all to remove the rule." }
                        div { class: "flex flex-wrap gap-4",
                            for (bit , label) in [(1u16, "Uppercase"), (2, "Lowercase"), (4, "Digit"), (8, "Symbol")] {
                                label { class: "flex items-center gap-2 text-sm",
                                    input {
                                        r#type: "checkbox",
                                        checked: classes() & bit != 0,
                                        onchange: move |e: FormEvent| classes.set(if e.checked() { classes() | bit } else { classes() & !bit }),
                                    }
                                    "{label}"
                                }
                            }
                        }
                        div {
                            Button {
                                size: ButtonSize::Sm,
                                variant: ButtonVariant::Outline,
                                disabled: locked,
                                onclick: move |_| { spawn(apply("cx", FidoPolicy::PinComplexity { bits: classes() }, "PIN complexity rule saved.".into())); },
                                if busy() == Some("cx") { Spinner {} } else { Check {} }
                                "Save rule"
                            }
                        }
                    }

                    div { class: "flex flex-wrap items-center justify-between gap-3 py-3",
                        div {
                            div { class: "text-sm font-medium", "Enterprise attestation" }
                            p { class: "text-xs text-muted-foreground",
                                if ep == Some(true) { "On. Sites in your organization can identify this exact key." }
                                else { "Lets an organization's sites identify this exact key. Turning it off again needs a factory reset." }
                            }
                        }
                        if ep != Some(true) {
                            if ep_armed() {
                                div { class: "flex gap-2",
                                    Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| ep_armed.set(false), "Cancel" }
                                    Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: locked,
                                        onclick: move |_| { ep_armed.set(false); spawn(apply("ep", FidoPolicy::EnterpriseAttestation, "Enterprise attestation enabled.".into())); },
                                        if busy() == Some("ep") { Spinner {} }
                                        "Enable"
                                    }
                                }
                            } else {
                                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: locked, onclick: move |_| ep_armed.set(true), "Enable…" }
                            }
                        }
                    }
                }
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-sm text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}

/// Revoke / expire / touch controls for one passkey (pico-fido 8+ resident credentials).
#[component]
pub fn PasskeyControls(cred_id: String, on_change: EventHandler<()>) -> Element {
    let st = use_context::<AppState>();
    let mut date = use_signal(String::new);
    let mut busy = use_signal(|| None::<&'static str>);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let mut revoke_armed = use_signal(|| false);

    let run = move |tag: &'static str, change: FidoPolicy, ok: &'static str| async move {
        let (Some(d), Some(p)) = (st.device.peek().clone(), st.pin.peek().clone()) else { return };
        busy.set(Some(tag));
        msg.set(Some(api::fido_policy(&d.path, &p, &change).await.map(|_| ok.to_string()).map_err(|e| humanize(&e))));
        busy.set(None);
        on_change.call(());
    };
    let (c1, c2, c3, c4, c5) = (cred_id.clone(), cred_id.clone(), cred_id.clone(), cred_id.clone(), cred_id.clone());
    let b = busy().is_some();

    rsx! {
        div { class: "flex flex-col gap-3",
            div { class: "flex flex-wrap items-end gap-2",
                div { class: "flex flex-col gap-1",
                    Label { "Expires on" }
                    Input { r#type: InputType::Date, value: date(), oninput: move |e: FormEvent| date.set(e.value()) }
                }
                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: b || date.read().is_empty(),
                    onclick: move |_| {
                        let unix = (js_sys::Date::parse(&format!("{}T23:59:59", date.peek())) / 1000.0) as u32;
                        spawn(run("exp", FidoPolicy::Expire { cred_id: c1.clone(), unix }, "Expiry set. The key's clock was synced."));
                    },
                    if busy() == Some("exp") { Spinner {} } else { CalendarClock {} }
                    "Set expiry"
                }
                Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, disabled: b,
                    onclick: move |_| { spawn(run("exp0", FidoPolicy::Expire { cred_id: c2.clone(), unix: 0 }, "Expiry cleared.")); },
                    "Clear expiry"
                }
            }
            div { class: "flex flex-wrap items-center gap-2",
                span { class: "text-sm text-muted-foreground", "Touch to sign in:" }
                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: b,
                    onclick: move |_| { spawn(run("t1", FidoPolicy::Touch { cred_id: c3.clone(), required: true }, "Touch is now required.")); },
                    Hand {} "Required"
                }
                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: b,
                    onclick: move |_| { spawn(run("t0", FidoPolicy::Touch { cred_id: c4.clone(), required: false }, "Touch is no longer needed for this passkey.")); },
                    "Not needed"
                }
                div { class: "ml-auto",
                    if revoke_armed() {
                        span { class: "mr-2 text-sm text-muted-foreground", "Can't be undone." }
                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| revoke_armed.set(false), "Cancel" }
                        Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: b,
                            onclick: move |_| { revoke_armed.set(false); spawn(run("rev", FidoPolicy::Revoke { cred_id: c5.clone() }, "Passkey revoked: it can no longer sign in.")); },
                            if busy() == Some("rev") { Spinner {} } else { Ban {} }
                            "Revoke"
                        }
                    } else {
                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, class: "text-destructive", disabled: b, onclick: move |_| revoke_armed.set(true), Ban {} "Revoke…" }
                    }
                }
            }
            match msg() {
                Some(Ok(m)) => rsx! { p { class: "text-sm text-success", "{m}" } },
                Some(Err(e)) => rsx! { p { class: "text-sm text-destructive", "{e}" } },
                None => rsx! {},
            }
        }
    }
}
