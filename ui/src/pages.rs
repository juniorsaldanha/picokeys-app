use crate::{AppState, api};
use dioxus::prelude::*;
use icons::{Check, CircleCheck, Cpu, KeyRound, Lightbulb, Lock, RefreshCw, Search, ShieldCheck, Trash2, TriangleAlert};
use types::{FidoInfo, Passkey};

use crate::ui::alert::{Alert, AlertDescription, AlertTitle, AlertVariant};
use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::empty::{Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;

#[component]
pub fn PageHeader(title: &'static str, subtitle: &'static str, children: Element) -> Element {
    rsx! {
        div { class: "mb-6 flex items-end justify-between gap-4",
            div {
                h1 { class: "text-2xl font-semibold tracking-tight", "{title}" }
                p { class: "mt-1 text-sm text-muted-foreground", "{subtitle}" }
            }
            div { class: "flex items-center gap-2", {children} }
        }
    }
}

#[component]
pub fn ErrorBox(title: String, msg: String) -> Element {
    rsx! {
        Alert { variant: AlertVariant::Destructive, class: "animate-in fade-in",
            TriangleAlert {}
            AlertTitle { "{title}" }
            AlertDescription { "{msg}" }
        }
    }
}

/// Friendly text for the CTAP errors people actually hit.
pub fn humanize(e: &str) -> String {
    let l = e.to_lowercase();
    if l.contains("pin_invalid") || l.contains("0x31") {
        "Wrong PIN.".into()
    } else if l.contains("pin_auth_blocked") || l.contains("0x34") {
        "Too many wrong attempts. Unplug and replug the key, then try again.".into()
    } else if l.contains("pin_blocked") || l.contains("0x32") {
        "PIN is blocked. The key must be reset to be used again.".into()
    } else if l.contains("pin_policy_violation") || l.contains("0x37") {
        "The new PIN doesn't meet the key's PIN policy.".into()
    } else {
        e.into()
    }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

#[component]
pub fn Overview() -> Element {
    let mut st = use_context::<AppState>();
    let mut winking = use_signal(|| false);

    let identify = move |_| async move {
        let Some(d) = st.device.peek().clone() else { return };
        winking.set(true);
        let _ = api::wink(&d.path).await;
        winking.set(false);
    };

    rsx! {
        PageHeader { title: "Overview", subtitle: "Your key at a glance.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| st.info.restart(),
                RefreshCw {} "Refresh"
            }
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: winking(), onclick: identify,
                if winking() { Spinner {} } else { Lightbulb {} }
                "Identify"
            }
        }
        match &*st.info.read() {
            Some(Some(Ok(i))) => rsx! { OverviewBody { info: i.clone() } },
            Some(Some(Err(e))) => rsx! { ErrorBox { title: "Couldn't read the key", msg: humanize(e) } },
            _ => rsx! {
                div { class: "grid grid-cols-2 gap-4 lg:grid-cols-4",
                    for _ in 0..4 { Skeleton { class: "h-28 rounded-xl" } }
                }
                Skeleton { class: "mt-4 h-48 rounded-xl" }
            },
        }
    }
}

fn option_label(k: &str) -> &str {
    match k {
        "rk" => "Discoverable credentials",
        "up" => "User presence",
        "uv" => "User verification",
        "plat" => "Platform device",
        "alwaysUv" => "Always require UV",
        "credMgmt" => "Credential management",
        "authnrCfg" => "Authenticator config",
        "clientPin" => "Client PIN",
        "largeBlobs" => "Large blobs",
        "pinUvAuthToken" => "PIN/UV auth token",
        "setMinPINLength" => "Set min PIN length",
        "makeCredUvNotRqd" => "MakeCred without UV",
        "perCredMgmtRO" => "Read-only cred mgmt",
        "ep" => "Enterprise attestation",
        "bioEnroll" => "Biometrics",
        other => other,
    }
}

#[component]
fn Stat(label: &'static str, value: String, hint: String, icon: Element) -> Element {
    rsx! {
        Card { class: "gap-2 py-5 transition-shadow hover:shadow-md",
            CardContent { class: "px-5",
                div { class: "flex items-center justify-between text-muted-foreground [&_svg]:size-4",
                    span { class: "text-xs font-medium", "{label}" }
                    {icon}
                }
                div { class: "mt-2 text-2xl font-semibold tracking-tight", "{value}" }
                div { class: "mt-0.5 truncate text-xs text-muted-foreground", "{hint}" }
            }
        }
    }
}

#[component]
fn OverviewBody(info: FidoInfo) -> Element {
    let (pin_value, pin_hint) = match (info.pin_set, info.pin_retries) {
        (Some(true), Some(r)) => ("Set".to_string(), format!("{r} attempts left")),
        (Some(true), None) => ("Set".into(), String::new()),
        (Some(false), _) => ("Not set".into(), "Set one in PIN".into()),
        (None, _) => ("N/A".into(), "Not supported".into()),
    };
    let fido = info
        .versions
        .iter()
        .filter_map(|v| v.strip_prefix("FIDO_"))
        .next_back()
        .map(|v| v.replace('_', "."))
        .unwrap_or_else(|| "U2F".into());
    let slots = if info.remaining_passkeys > 0 {
        format!("characters · {} passkey slots free", info.remaining_passkeys)
    } else {
        "characters".to_string()
    };

    rsx! {
        div { class: "grid grid-cols-2 gap-4 lg:grid-cols-4",
            Stat { label: "Firmware", value: info.firmware.clone(), hint: "Pico FIDO".to_string(), icon: rsx! { Cpu {} } }
            Stat { label: "FIDO", value: fido, hint: info.versions.join(" · ").replace("FIDO_", "").replace('_', "."), icon: rsx! { ShieldCheck {} } }
            Stat { label: "PIN", value: pin_value, hint: pin_hint, icon: rsx! { Lock {} } }
            Stat { label: "Min PIN length", value: info.min_pin_length.to_string(), hint: slots, icon: rsx! { KeyRound {} } }
        }

        div { class: "mt-4 grid gap-4 lg:grid-cols-5",
            Card { class: "lg:col-span-3",
                CardHeader {
                    CardTitle { "Capabilities" }
                    CardDescription { "Options reported by the authenticator" }
                }
                CardContent {
                    div { class: "grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2",
                        for (k, on) in info.options.iter().cloned() {
                            div { key: "{k}", class: "flex items-center justify-between gap-3 border-b border-dashed py-1.5 text-sm last:border-0",
                                span { class: if on { "" } else { "text-muted-foreground" }, "{option_label(&k)}" }
                                if on {
                                    Badge { variant: BadgeVariant::Success, class: "gap-1", Check { class: "size-3" } "On" }
                                } else {
                                    Badge { variant: BadgeVariant::Muted, "Off" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "flex flex-col gap-4 lg:col-span-2",
                Card {
                    CardHeader {
                        CardTitle { "Extensions" }
                        CardDescription { "WebAuthn extensions supported" }
                    }
                    CardContent { class: "flex flex-wrap gap-1.5",
                        for e in info.extensions.iter() { Badge { key: "{e}", variant: BadgeVariant::Secondary, "{e}" } }
                    }
                }
                Card {
                    CardHeader {
                        CardTitle { "Algorithms" }
                    }
                    CardContent { class: "flex flex-wrap gap-1.5",
                        for a in info.algorithms.iter() { Badge { key: "{a}", variant: BadgeVariant::Info, "{a}" } }
                    }
                }
                Card {
                    CardHeader {
                        CardTitle { "AAGUID" }
                    }
                    CardContent {
                        code { class: "selectable block break-all rounded-md bg-muted px-2.5 py-2 font-mono text-xs", "{info.aaguid}" }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

#[component]
pub fn Passkeys() -> Element {
    let st = use_context::<AppState>();
    rsx! {
        if st.pin.read().is_none() {
            PageHeader { title: "Passkeys", subtitle: "Discoverable credentials stored on your key." }
            Unlock {}
        } else {
            PasskeyList {}
        }
    }
}

#[component]
fn Unlock() -> Element {
    let mut st = use_context::<AppState>();
    let mut pin = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let pin_set = matches!(&*st.info.read(), Some(Some(Ok(i))) if i.pin_set == Some(true));

    let submit = move |e: FormEvent| async move {
        e.prevent_default();
        let Some(d) = st.device.peek().clone() else { return };
        let p = pin.peek().clone();
        if p.is_empty() {
            return;
        }
        busy.set(true);
        error.set(None);
        // Validate by actually listing; PasskeyList then reuses the session PIN.
        match api::list_passkeys(&d.path, &p).await {
            Ok(_) => st.pin.set(Some(p)),
            Err(e) => {
                error.set(Some(humanize(&e)));
                st.info.restart(); // refresh retries counter
            }
        }
        busy.set(false);
    };

    if !pin_set {
        return rsx! {
            Empty { class: "py-16",
                EmptyHeader {
                    EmptyMedia { variant: EmptyMediaVariant::Icon, Lock {} }
                    EmptyTitle { "Set a PIN first" }
                    EmptyDescription { "Passkey management requires a PIN on the key. Go to PIN to create one." }
                }
            }
        };
    }

    rsx! {
        Card { class: "mx-auto mt-10 w-full max-w-sm animate-in fade-in slide-in-from-bottom-2 duration-300",
            CardHeader { class: "items-center text-center sm:flex sm:flex-col",
                div { class: "mx-auto mb-2 flex size-12 items-center justify-center rounded-2xl bg-primary/10 text-primary",
                    Lock { class: "size-5" }
                }
                CardTitle { class: "text-lg", "Unlock passkeys" }
                CardDescription { "Enter your key's PIN. It stays in memory for this session only." }
            }
            CardContent {
                form { class: "flex flex-col gap-3", onsubmit: submit,
                    Input {
                        r#type: InputType::Password,
                        placeholder: "PIN",
                        value: pin(),
                        oninput: move |e: FormEvent| pin.set(e.value()),
                    }
                    if let Some(e) = error() {
                        p { class: "text-sm text-destructive", "{e}" }
                    }
                    Button { button_type: "submit", class: "w-full", disabled: busy() || pin.read().is_empty(),
                        if busy() { Spinner {} } else { Lock {} }
                        "Unlock"
                    }
                }
            }
        }
    }
}

#[component]
fn PasskeyList() -> Element {
    let mut st = use_context::<AppState>();
    let mut query = use_signal(String::new);
    let mut confirm = use_signal(|| None::<String>);
    let mut deleting = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    let mut list = use_resource(move || async move {
        let d = (st.device)()?;
        let p = (st.pin)()?;
        Some(api::list_passkeys(&d.path, &p).await)
    });

    let delete = move |cred_id: String| async move {
        let (Some(d), Some(p)) = (st.device.peek().clone(), st.pin.peek().clone()) else { return };
        deleting.set(Some(cred_id.clone()));
        error.set(None);
        match api::delete_passkey(&d.path, &p, &cred_id).await {
            Ok(()) => list.restart(),
            Err(e) => error.set(Some(humanize(&e))),
        }
        confirm.set(None);
        deleting.set(None);
    };

    let body = match &*list.read() {
        Some(Some(Ok(keys))) => {
            let q = query.read().to_lowercase();
            let shown: Vec<Passkey> = keys
                .iter()
                .filter(|k| {
                    q.is_empty()
                        || k.rp_id.to_lowercase().contains(&q)
                        || k.user_name.to_lowercase().contains(&q)
                        || k.user_display_name.to_lowercase().contains(&q)
                })
                .cloned()
                .collect();
            let total = keys.len();
            rsx! {
                div { class: "mb-4 flex items-center gap-3",
                    div { class: "relative flex-1",
                        Search { class: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" }
                        Input {
                            class: "pl-9",
                            r#type: InputType::Search,
                            placeholder: "Search by site or user…",
                            value: query(),
                            oninput: move |e: FormEvent| query.set(e.value()),
                        }
                    }
                    Badge { variant: BadgeVariant::Secondary, size: crate::ui::badge::BadgeSize::Lg, "{total} total" }
                }
                if total == 0 {
                    Empty { class: "py-16",
                        EmptyHeader {
                            EmptyMedia { variant: EmptyMediaVariant::Icon, KeyRound {} }
                            EmptyTitle { "No passkeys yet" }
                            EmptyDescription { "Passkeys you create on websites with this key will appear here." }
                        }
                    }
                } else if shown.is_empty() {
                    p { class: "py-10 text-center text-sm text-muted-foreground", "No passkeys match \"{query}\"." }
                } else {
                    Card { class: "gap-0 py-0 overflow-hidden",
                        for k in shown {
                            PasskeyRow {
                                key: "{k.cred_id}",
                                passkey: k.clone(),
                                confirming: confirm.read().as_deref() == Some(k.cred_id.as_str()),
                                deleting: deleting.read().as_deref() == Some(k.cred_id.as_str()),
                                on_ask: move |id| confirm.set(Some(id)),
                                on_cancel: move |_| confirm.set(None),
                                on_delete: move |id| { spawn(delete(id)); },
                            }
                        }
                    }
                }
            }
        }
        Some(Some(Err(e))) => rsx! { ErrorBox { title: "Couldn't list passkeys", msg: humanize(e) } },
        _ => rsx! {
            div { class: "flex flex-col gap-2",
                for _ in 0..4 { Skeleton { class: "h-16 rounded-xl" } }
            }
        },
    };

    rsx! {
        PageHeader { title: "Passkeys", subtitle: "Discoverable credentials stored on your key.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| list.restart(), RefreshCw {} "Refresh" }
            Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| st.pin.set(None), Lock {} "Lock" }
        }
        if let Some(e) = error() {
            div { class: "mb-4", ErrorBox { title: "Delete failed", msg: e } }
        }
        {body}
    }
}

#[component]
fn PasskeyRow(
    passkey: Passkey,
    confirming: bool,
    deleting: bool,
    on_ask: EventHandler<String>,
    on_cancel: EventHandler<()>,
    on_delete: EventHandler<String>,
) -> Element {
    let k = passkey;
    let initial = k.rp_id.chars().next().unwrap_or('?').to_ascii_uppercase();
    let user = if k.user_display_name.is_empty() || k.user_display_name == k.user_name {
        k.user_name.clone()
    } else {
        format!("{} · {}", k.user_display_name, k.user_name)
    };
    let protect = match k.cred_protect.as_str() {
        "UserVerificationRequired" => Some(("UV required", BadgeVariant::Warning)),
        "UserVerificationOptionalWithCredentialIdList" => Some(("UV optional w/ ID", BadgeVariant::Info)),
        _ => None,
    };
    let id1 = k.cred_id.clone();
    let id2 = k.cred_id.clone();
    rsx! {
        div { class: "group flex items-center gap-4 border-b px-5 py-3.5 transition-colors last:border-0 hover:bg-muted/40",
            div { class: "flex size-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-brand-from/15 to-brand-to/15 text-base font-semibold text-primary",
                "{initial}"
            }
            div { class: "min-w-0 flex-1",
                div { class: "flex items-center gap-2",
                    span { class: "selectable truncate font-medium", "{k.rp_id}" }
                    if let Some((label, v)) = protect { Badge { variant: v, size: crate::ui::badge::BadgeSize::Sm, "{label}" } }
                }
                div { class: "selectable truncate text-sm text-muted-foreground", "{user}" }
            }
            if confirming {
                div { class: "flex items-center gap-2 animate-in fade-in slide-in-from-right-2 duration-200",
                    span { class: "text-sm text-muted-foreground", "Delete permanently?" }
                    Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, disabled: deleting, onclick: move |_| on_cancel.call(()), "Cancel" }
                    Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: deleting, onclick: move |_| on_delete.call(id1.clone()),
                        if deleting { Spinner {} } else { Trash2 {} }
                        "Delete"
                    }
                }
            } else {
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::IconSm,
                    class: "text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive focus-visible:opacity-100",
                    aria_label: "Delete passkey",
                    onclick: move |_| on_ask.call(id2.clone()),
                    Trash2 {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PIN
// ---------------------------------------------------------------------------

#[component]
pub fn PinPage() -> Element {
    let mut st = use_context::<AppState>();
    let mut current = use_signal(String::new);
    let mut new_pin = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut done = use_signal(|| false);

    let (pin_set, min_len, retries) = match &*st.info.read() {
        Some(Some(Ok(i))) => (i.pin_set == Some(true), i.min_pin_length.max(4) as usize, i.pin_retries),
        _ => (false, 4, None),
    };

    // ponytail: client-side checks mirror CTAP2 rules (min length from key, max 63 bytes); the key still enforces them.
    let validation = {
        let n = new_pin.read();
        if n.is_empty() {
            None
        } else if n.chars().count() < min_len {
            Some(format!("At least {min_len} characters."))
        } else if n.len() > 63 {
            Some("At most 63 bytes.".into())
        } else if !confirm.read().is_empty() && *confirm.read() != *n {
            Some("PINs don't match.".into())
        } else {
            None
        }
    };
    let ready = validation.is_none()
        && !new_pin.read().is_empty()
        && *confirm.read() == *new_pin.read()
        && (!pin_set || !current.read().is_empty());

    let submit = move |e: FormEvent| async move {
        e.prevent_default();
        let Some(d) = st.device.peek().clone() else { return };
        let (cur, np) = (current.peek().clone(), new_pin.peek().clone());
        busy.set(true);
        error.set(None);
        done.set(false);
        let r = if pin_set { api::change_pin(&d.path, &cur, &np).await } else { api::set_pin(&d.path, &np).await };
        match r {
            Ok(()) => {
                done.set(true);
                st.pin.set(Some(np));
                current.set(String::new());
                new_pin.set(String::new());
                confirm.set(String::new());
            }
            Err(e) => error.set(Some(humanize(&e))),
        }
        st.info.restart();
        busy.set(false);
    };

    let subtitle = if pin_set { "Change the PIN that protects your key." } else { "Protect your key with a PIN." };
    rsx! {
        PageHeader {
            title: "PIN",
            subtitle: subtitle,
        }
        div { class: "grid gap-4 lg:grid-cols-5",
            Card { class: "lg:col-span-3",
                CardHeader {
                    CardTitle { if pin_set { "Change PIN" } else { "Set PIN" } }
                    CardDescription { "Minimum {min_len} characters. Letters, numbers and symbols are allowed." }
                }
                CardContent {
                    form { class: "flex flex-col gap-4", onsubmit: submit,
                        if pin_set {
                            div { class: "flex flex-col gap-2",
                                Label { html_for: "cur", "Current PIN" }
                                Input { id: "cur", r#type: InputType::Password, value: current(), oninput: move |e: FormEvent| current.set(e.value()) }
                            }
                        }
                        div { class: "flex flex-col gap-2",
                            Label { html_for: "new", "New PIN" }
                            Input { id: "new", r#type: InputType::Password, value: new_pin(), oninput: move |e: FormEvent| { done.set(false); new_pin.set(e.value()) } }
                        }
                        div { class: "flex flex-col gap-2",
                            Label { html_for: "confirm", "Confirm new PIN" }
                            Input { id: "confirm", r#type: InputType::Password, value: confirm(), oninput: move |e: FormEvent| confirm.set(e.value()) }
                        }
                        if let Some(v) = validation {
                            p { class: "text-sm text-muted-foreground", "{v}" }
                        }
                        if let Some(e) = error() {
                            p { class: "text-sm text-destructive", "{e}" }
                        }
                        if done() {
                            div { class: "flex items-center gap-2 text-sm text-success animate-in fade-in",
                                CircleCheck { class: "size-4" }
                                if pin_set { "PIN updated." } else { "PIN set." }
                            }
                        }
                        div {
                            Button { button_type: "submit", disabled: busy() || !ready,
                                if busy() { Spinner {} }
                                if pin_set { "Change PIN" } else { "Set PIN" }
                            }
                        }
                    }
                }
            }
            Card { class: "lg:col-span-2",
                CardHeader {
                    CardTitle { "Status" }
                }
                CardContent { class: "flex flex-col gap-3 text-sm",
                    div { class: "flex items-center justify-between",
                        span { class: "text-muted-foreground", "PIN" }
                        if pin_set { Badge { variant: BadgeVariant::Success, "Set" } } else { Badge { variant: BadgeVariant::Warning, "Not set" } }
                    }
                    if let Some(r) = retries {
                        div { class: "flex items-center justify-between",
                            span { class: "text-muted-foreground", "Attempts left" }
                            Badge { variant: if r <= 3 { BadgeVariant::Destructive } else { BadgeVariant::Secondary }, "{r}" }
                        }
                    }
                    div { class: "flex items-center justify-between",
                        span { class: "text-muted-foreground", "Minimum length" }
                        span { class: "font-medium", "{min_len}" }
                    }
                    p { class: "mt-2 rounded-lg bg-muted px-3 py-2.5 text-xs text-muted-foreground",
                        "After too many wrong PINs the key locks and must be reset, which erases all passkeys."
                    }
                }
            }
        }
    }
}
