//! Admin page: the app admin lock and the hash-chained audit log, plus the global unlock dialog.
use crate::api;
use crate::pages::PageHeader;
use dioxus::prelude::*;
use icons::{Download, Lock, RefreshCw, ShieldAlert, ShieldCheck};
use types::{AdminStatus, AuditLog};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::spinner::Spinner;

#[component]
pub fn AdminPage() -> Element {
    let mut status = use_resource(api::admin_status);
    let mut log = use_resource(api::audit_log);
    rsx! {
        PageHeader { title: "Admin", subtitle: "Protect risky actions in this app and review what was changed.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: move |_| { status.restart(); log.restart(); }, RefreshCw {} "Refresh" }
        }
        if let Some(Ok(s)) = status.read().clone() {
            LockCard { s, on_change: move |_| { status.restart(); log.restart(); } }
        }
        match log.read().clone() {
            Some(Ok(l)) => rsx! { AuditCard { log: l } },
            Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
            None => rsx! {},
        }
    }
}

#[component]
fn LockCard(s: AdminStatus, on_change: EventHandler<()>) -> Element {
    let mut current = use_signal(String::new);
    let mut new = use_signal(String::new);
    let mut again = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let enabled = s.enabled;
    let save = move |_| async move {
        busy.set(true);
        let c = current.peek().clone();
        let n = new.peek().clone();
        let r = api::admin_set(enabled.then_some(c.as_str()), &n).await;
        if r.is_ok() {
            current.set(String::new());
            new.set(String::new());
            again.set(String::new());
        }
        msg.set(Some(r.map(|_| if enabled { "Passphrase changed.".into() } else { "Admin lock is on.".into() })));
        busy.set(false);
        on_change.call(());
    };
    let remove = move |_| async move {
        busy.set(true);
        let c = current.peek().clone();
        let r = api::admin_remove(&c).await;
        current.set(String::new());
        msg.set(Some(r.map(|_| "Admin lock removed.".into())));
        busy.set(false);
        on_change.call(());
    };
    let ok_new = new().chars().count() >= 8 && new() == again() && (!enabled || !current().is_empty());
    rsx! {
        Card {
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "Admin lock" }
                        CardDescription {
                            "A passphrase this app asks for before risky actions: resets, key policy, firmware flashing, deleting passkeys, accounts, slots or HSM keys, USB settings, SSH migration steps and exporting recovery files. One unlock lasts 5 minutes."
                        }
                    }
                    if !s.enabled { Badge { variant: BadgeVariant::Outline, "Off" } }
                    else if let Some(n) = s.seconds_left { Badge { variant: BadgeVariant::Secondary, "Unlocked · {n / 60 + 1} min" } }
                    else { Badge { variant: BadgeVariant::Secondary, Lock { class: "size-3" } "Locked" } }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                p { class: "rounded-lg bg-muted px-3 py-2.5 text-xs text-muted-foreground",
                    "This protects this app only. The open-source firmware has no admin/user PIN split, so anyone with your key's PIN can still change it with other tools or on another computer."
                }
                div { class: "grid gap-3 sm:grid-cols-3",
                    if enabled {
                        div { class: "flex flex-col gap-1.5", Label { "Current passphrase" }
                            Input { r#type: InputType::Password, value: current(), oninput: move |e: FormEvent| current.set(e.value()) } }
                    }
                    div { class: "flex flex-col gap-1.5", Label { if enabled { "New passphrase" } else { "Passphrase (8+ characters)" } }
                        Input { r#type: InputType::Password, value: new(), oninput: move |e: FormEvent| new.set(e.value()) } }
                    div { class: "flex flex-col gap-1.5", Label { "Repeat" }
                        Input { r#type: InputType::Password, value: again(), oninput: move |e: FormEvent| again.set(e.value()) } }
                }
                div { class: "flex flex-wrap gap-2",
                    Button { size: ButtonSize::Sm, disabled: !ok_new || busy(), onclick: save,
                        if busy() { Spinner {} }
                        if enabled { "Change passphrase" } else { "Turn on admin lock" }
                    }
                    if enabled {
                        Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: s.seconds_left.is_none(),
                            onclick: move |_| async move { let _ = api::admin_lock().await; on_change.call(()); }, Lock {} "Lock now" }
                        Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, disabled: current().is_empty() || busy(), onclick: remove, "Remove lock" }
                    }
                }
                if !enabled { p { class: "text-xs text-muted-foreground", "If you forget it, deleting ~/.pico-key-manager/admin.json removes the lock." } }
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}

fn when(ts: u64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ts as f64 * 1000.0));
    String::from(d.to_locale_string("default", &wasm_bindgen::JsValue::UNDEFINED))
}

#[component]
fn AuditCard(log: AuditLog) -> Element {
    let mut saved = use_signal(|| None::<Result<String, String>>);
    let total = log.entries.len();
    rsx! {
        Card { class: "mt-4",
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "Audit log" }
                        CardDescription { "Every change made through this app, newest first. Each entry is chained to the one before it, so edits or deletions are detected. Changes made by other tools aren't recorded." }
                    }
                    Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: total == 0,
                        onclick: move |_| async move { saved.set(Some(api::audit_export().await.map(|p| format!("Saved to {p}")))); },
                        Download {} "Export"
                    }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                if log.chain_ok {
                    p { class: "flex items-center gap-1.5 text-success", ShieldCheck { class: "size-4" } "Chain intact ({total} entries)." }
                } else {
                    p { class: "flex items-center gap-1.5 text-destructive", ShieldAlert { class: "size-4" }
                        "The log was modified: entry {log.broken_at.unwrap_or(0) + 1} (oldest = 1) or something around it was edited, inserted or removed."
                    }
                }
                p { class: "selectable font-mono text-xs text-muted-foreground", "{log.path}" }
                match saved() {
                    Some(Ok(m)) => rsx! { p { class: "text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-destructive", "{e}" } },
                    None => rsx! {},
                }
                if total == 0 { p { class: "text-muted-foreground", "Nothing recorded yet." } }
                div { class: "flex flex-col divide-y divide-border",
                    for (i, e) in log.entries.iter().enumerate().rev().take(200) {
                        div { key: "{i}", class: "flex items-start justify-between gap-3 py-2",
                            div { class: "min-w-0",
                                p { class: "font-mono text-xs font-medium", "{e.action}" }
                                if !e.detail.is_empty() { p { class: "selectable truncate text-xs text-muted-foreground", "{e.detail}" } }
                                if let Some(err) = &e.error { p { class: "text-xs text-destructive", "{err}" } }
                            }
                            div { class: "flex shrink-0 flex-col items-end gap-1",
                                if e.ok { Badge { variant: BadgeVariant::Secondary, "ok" } } else { Badge { variant: BadgeVariant::Destructive, "failed" } }
                                span { class: "text-xs text-muted-foreground", "{when(e.ts)}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Modal shown when a risky action hits the admin lock.
#[component]
pub fn AdminPrompt() -> Element {
    let mut pass = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut err = use_signal(|| None::<String>);
    if !api::ADMIN_PROMPT() {
        return rsx! {};
    }
    let mut close = move || {
        *api::ADMIN_PROMPT.write() = false;
        pass.set(String::new());
        err.set(None);
    };
    let unlock = move |e: FormEvent| async move {
        e.prevent_default();
        busy.set(true);
        let p = pass.peek().clone(); // a Ref held across the await panics when the dialog writes to `pass`
        match api::admin_unlock(&p).await {
            Ok(()) => close(),
            Err(e) => err.set(Some(e)),
        }
        busy.set(false);
    };
    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in duration-150",
            form { class: "flex w-full max-w-sm flex-col gap-3 rounded-xl border bg-card p-5 text-sm shadow-lg", onsubmit: unlock,
                p { class: "flex items-center gap-2 text-base font-semibold", Lock { class: "size-4" } "Admin passphrase" }
                p { class: "text-muted-foreground", "This action is protected. Unlock for 5 minutes, then try it again." }
                Input { r#type: InputType::Password, value: pass(), oninput: move |e: FormEvent| pass.set(e.value()) }
                if let Some(e) = err() { p { class: "text-xs text-destructive", "{e}" } }
                div { class: "flex justify-end gap-2",
                    Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, onclick: move |_| close(), "Cancel" }
                    Button { button_type: "submit", size: ButtonSize::Sm, disabled: pass().is_empty() || busy(),
                        if busy() { Spinner {} }
                        "Unlock"
                    }
                }
            }
        }
    }
}
