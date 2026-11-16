//! OTP slots page: what the key types/answers on a short (slot 1) or long (slot 2) touch.
use crate::api;
use crate::pages::{ErrorBox, PageHeader, humanize};
use dioxus::prelude::*;
use icons::{ArrowUpDown, Eye, EyeOff, Hand, Plus, RefreshCw, Trash2};
use types::{NewOtp, OtpKind, OtpSlot};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;
use crate::ui::switch::Switch;

#[component]
pub fn OtpPage() -> Element {
    let mut slots = use_resource(api::otp_status);
    let mut swapping = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let swap = move |_| async move {
        swapping.set(true);
        error.set(None);
        if let Err(e) = api::otp_swap().await {
            error.set(Some(humanize(&e)));
        }
        swapping.set(false);
        slots.restart();
    };

    let body = match &*slots.read() {
        Some(Ok(list)) => rsx! {
            div { class: "grid gap-4 lg:grid-cols-2",
                for s in list.clone() {
                    SlotCard { key: "{s.slot}", slot: s, on_change: move |_| slots.restart() }
                }
            }
        },
        Some(Err(e)) => rsx! { ErrorBox { title: "Couldn't read OTP slots", msg: humanize(e) } },
        None => rsx! {
            div { class: "grid gap-4 lg:grid-cols-2",
                Skeleton { class: "h-44 rounded-xl" }
                Skeleton { class: "h-44 rounded-xl" }
            }
        },
    };

    rsx! {
        PageHeader { title: "OTP slots", subtitle: "What the key types or answers when you touch it briefly or hold it.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| slots.restart(), RefreshCw {} "Refresh" }
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: swapping(), onclick: swap,
                if swapping() { Spinner {} } else { ArrowUpDown {} }
                "Swap slots"
            }
        }
        if let Some(e) = error() { p { class: "mb-4 text-sm text-destructive", "{e}" } }
        {body}
    }
}

fn kind_label(k: OtpKind) -> (&'static str, &'static str) {
    match k {
        OtpKind::YubicoOtp => ("Yubico OTP", "Types a one-time password that a server validates."),
        OtpKind::Static => ("Static password", "Types the same password every time."),
        OtpKind::ChallengeResponse => ("Challenge-response", "Answers HMAC-SHA1 challenges from apps (KeePassXC, disk unlock, …)."),
        OtpKind::YubicoChallenge => ("Yubico challenge-response", "Answers Yubico OTP challenges from apps."),
        OtpKind::Hotp => ("HOTP", "Types a counter-based one-time code."),
    }
}

#[component]
fn SlotCard(slot: OtpSlot, on_change: EventHandler<()>) -> Element {
    let mut editing = use_signal(|| false);
    let mut confirm = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let n = slot.slot;
    let (title, gesture) = if n == 1 { ("Slot 1", "Short touch") } else { ("Slot 2", "Long touch (hold ~3 s)") };

    let delete = move |_| async move {
        busy.set(true);
        error.set(None);
        match api::otp_delete(n).await {
            Ok(()) => {
                confirm.set(false);
                on_change.call(())
            }
            Err(e) => error.set(Some(humanize(&e))),
        }
        busy.set(false);
    };

    rsx! {
        Card {
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "{title}" }
                        CardDescription { class: "flex items-center gap-1.5 pt-1", Hand { class: "size-3.5" } "{gesture}" }
                    }
                    if let Some(k) = slot.kind {
                        Badge { variant: BadgeVariant::Success, "{kind_label(k).0}" }
                    } else {
                        Badge { variant: BadgeVariant::Secondary, "Empty" }
                    }
                }
            }
            if editing() {
                SlotForm {
                    slot: n,
                    overwrite: slot.kind.is_some(),
                    on_done: move |saved: bool| {
                        editing.set(false);
                        if saved {
                            on_change.call(())
                        }
                    },
                }
            } else {
                CardContent { class: "flex flex-col gap-3",
                    if let Some(k) = slot.kind {
                        p { class: "text-sm text-muted-foreground", "{kind_label(k).1}" }
                        if let Some(id) = &slot.public_id {
                            div { class: "flex items-center justify-between rounded-lg bg-muted/60 px-3 py-2 text-sm",
                                span { class: "text-muted-foreground", "Public ID" }
                                code { class: "font-mono", "{id}" }
                            }
                        }
                        if matches!(k, OtpKind::ChallengeResponse | OtpKind::YubicoChallenge) {
                            div { class: "text-xs text-muted-foreground", if slot.touch { "Requires touch for each challenge." } else { "Answers without touch." } }
                        }
                    } else {
                        p { class: "text-sm text-muted-foreground", "Not configured. Touching the key this way does nothing." }
                    }
                    if confirm() {
                        div { class: "flex items-center justify-between gap-2 rounded-lg bg-destructive/10 px-3 py-2 animate-in fade-in",
                            span { class: "text-sm", "Erase this slot? This can't be undone." }
                            div { class: "flex gap-1.5",
                                Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, disabled: busy(), onclick: move |_| confirm.set(false), "Cancel" }
                                Button { variant: ButtonVariant::Destructive, size: ButtonSize::Sm, disabled: busy(), onclick: delete,
                                    if busy() { Spinner {} } "Erase"
                                }
                            }
                        }
                    }
                    if let Some(e) = error() { p { class: "text-sm text-destructive", "{e}" } }
                }
                CardFooter { class: "justify-end gap-2",
                    if slot.kind.is_some() && !confirm() {
                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, class: "text-destructive", onclick: move |_| confirm.set(true), Trash2 {} "Erase" }
                    }
                    Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| editing.set(true),
                        Plus {}
                        if slot.kind.is_some() { "Replace" } else { "Configure" }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Yubico,
    Static,
    Hmac,
}

const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

fn hex_to_modhex(h: &str) -> String {
    h.chars().filter_map(|c| c.to_digit(16)).map(|d| MODHEX[d as usize] as char).collect()
}

#[component]
fn SlotForm(slot: u8, overwrite: bool, on_done: EventHandler<bool>) -> Element {
    let mut kind = use_signal(|| Kind::Hmac);
    let mut public_id = use_signal(String::new);
    let mut private_id = use_signal(String::new);
    let mut key = use_signal(String::new);
    let mut hmac_key = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut show = use_signal(|| false);
    let mut enter = use_signal(|| true);
    let mut touch = use_signal(|| true);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    // Fresh random secrets on open; shown so they can be copied into the server/app first.
    use_future(move || async move {
        public_id.set(format!("vv{}", hex_to_modhex(&api::random_hex(5).await)));
        private_id.set(api::random_hex(6).await);
        key.set(api::random_hex(16).await);
        hmac_key.set(api::random_hex(20).await);
    });

    let save = move |e: FormEvent| async move {
        e.prevent_default();
        let cfg = match kind() {
            Kind::Yubico => NewOtp::YubicoOtp { public_id: public_id(), private_id: private_id(), key: key() },
            Kind::Static => NewOtp::Static { password: password(), enter: enter() },
            Kind::Hmac => NewOtp::ChallengeResponse { key: hmac_key(), touch: touch() },
        };
        busy.set(true);
        error.set(None);
        match api::otp_configure(slot, &cfg).await {
            Ok(()) => on_done.call(true),
            Err(e) => error.set(Some(humanize(&e))),
        }
        busy.set(false);
    };

    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    let mono = "font-mono text-xs";

    rsx! {
        form { onsubmit: save, class: "animate-in fade-in",
            CardContent { class: "flex flex-col gap-4",
                div { class: "flex flex-col gap-1.5",
                    Label { "Type" }
                    select {
                        class: select_cls,
                        onchange: move |e: FormEvent| kind.set(match e.value().as_str() { "yubico" => Kind::Yubico, "static" => Kind::Static, _ => Kind::Hmac }),
                        option { value: "hmac", selected: kind() == Kind::Hmac, "Challenge-response (HMAC-SHA1)" }
                        option { value: "yubico", selected: kind() == Kind::Yubico, "Yubico OTP" }
                        option { value: "static", selected: kind() == Kind::Static, "Static password" }
                    }
                }
                match kind() {
                    Kind::Hmac => rsx! {
                        div { class: "flex flex-col gap-1.5",
                            Label { "Secret key (40 hex)" }
                            Input { class: mono, value: hmac_key(), oninput: move |e: FormEvent| hmac_key.set(e.value()) }
                            p { class: "text-xs text-muted-foreground", "Keep a copy if you need a backup key that answers the same way." }
                        }
                        div { class: "flex items-center justify-between gap-4",
                            div {
                                div { class: "text-sm font-medium", "Require touch" }
                                div { class: "text-xs text-muted-foreground", "Each challenge waits for a touch on the key." }
                            }
                            Switch { checked: touch(), aria_label: "Require touch", onchange: move |v| touch.set(v) }
                        }
                    },
                    Kind::Yubico => rsx! {
                        div { class: "grid gap-3 sm:grid-cols-2",
                            div { class: "flex flex-col gap-1.5",
                                Label { "Public ID (modhex)" }
                                Input { class: mono, value: public_id(), oninput: move |e: FormEvent| public_id.set(e.value()) }
                            }
                            div { class: "flex flex-col gap-1.5",
                                Label { "Private ID (hex)" }
                                Input { class: mono, value: private_id(), oninput: move |e: FormEvent| private_id.set(e.value()) }
                            }
                        }
                        div { class: "flex flex-col gap-1.5",
                            Label { "Secret key (32 hex)" }
                            Input { class: mono, value: key(), oninput: move |e: FormEvent| key.set(e.value()) }
                            p { class: "text-xs text-muted-foreground", "Register these three values with your validation server before saving." }
                        }
                    },
                    Kind::Static => rsx! {
                        div { class: "flex flex-col gap-1.5",
                            Label { "Password (up to 38 characters)" }
                            div { class: "relative",
                                Input {
                                    class: "pr-10",
                                    r#type: if show() { InputType::Text } else { InputType::Password },
                                    value: password(),
                                    oninput: move |e: FormEvent| password.set(e.value()),
                                }
                                Button {
                                    variant: ButtonVariant::Ghost,
                                    size: ButtonSize::IconXs,
                                    class: "absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground",
                                    aria_label: "Show password",
                                    button_type: "button",
                                    onclick: move |_| show.toggle(),
                                    if show() { EyeOff {} } else { Eye {} }
                                }
                            }
                            p { class: "text-xs text-muted-foreground", "Typed with a US keyboard layout; other layouts may change symbols." }
                        }
                        div { class: "flex items-center justify-between gap-4",
                            div { class: "text-sm font-medium", "Press Enter after typing" }
                            Switch { checked: enter(), aria_label: "Press Enter after typing", onchange: move |v| enter.set(v) }
                        }
                    },
                }
                if let Some(e) = error() { p { class: "text-sm text-destructive", "{e}" } }
            }
            CardFooter { class: "mt-4 justify-end gap-2",
                Button { variant: ButtonVariant::Ghost, button_type: "button", disabled: busy(), onclick: move |_| on_done.call(false), "Cancel" }
                Button {
                    button_type: "submit",
                    variant: if overwrite { ButtonVariant::Destructive } else { ButtonVariant::Default },
                    disabled: busy() || (kind() == Kind::Static && password().is_empty()),
                    if busy() { Spinner {} }
                    if overwrite { "Overwrite slot {slot}" } else { "Save to slot {slot}" }
                }
            }
        }
    }
}
