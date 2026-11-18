//! "Move to Pico" wizard: replace regular SSH keys with a Pico key, host by host.
use crate::AppState;
use crate::api;
use crate::pages::humanize;
use dioxus::prelude::*;
use icons::{Archive, ArrowRightLeft, Check, CircleCheck, Plug, Plus, ShieldAlert, Upload, X};
use types::{LegacyKey, SshKey};

use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::spinner::Spinner;

fn short(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

#[component]
pub fn MigrateCard(pico_keys: Vec<SshKey>, on_change: EventHandler<()>) -> Element {
    let mut inv = use_resource(api::ssh_inventory);
    let st = use_context::<AppState>();
    let mut pico = use_signal({
        let k = pico_keys.clone();
        move || k.first().map(|k| k.path.clone()).unwrap_or_default()
    });
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());

    let list = match &*inv.read() {
        Some(Ok(l)) if l.is_empty() => return rsx! {},
        Some(Ok(l)) => l.clone(),
        Some(Err(e)) => return rsx! {
            p { class: "text-sm text-destructive", "{humanize(e)}" }
        },
        None => return rsx! {},
    };

    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    rsx! {
        Card {
            CardHeader {
                CardTitle { class: "flex items-center gap-2",
                    ArrowRightLeft { class: "size-4" }
                    "Move existing keys to the Pico"
                }
                CardDescription {
                    "Regular SSH keys can't be copied into a Pico. Instead, each server learns your Pico key, you check it works on its own, "
                    "~/.ssh/config switches to it, and the old key files are archived to ~/.ssh/retired."
                }
            }
            CardContent { class: "flex flex-col gap-4",
                if pico_keys.is_empty() {
                    p { class: "text-sm text-warning",
                        "Create a Pico SSH key above first; it's what these keys get replaced with."
                    }
                } else {
                    div { class: "grid gap-3 sm:grid-cols-2",
                        div { class: "flex flex-col gap-1.5",
                            Label { "Replace with Pico key" }
                            select {
                                class: select_cls,
                                onchange: move |e: FormEvent| pico.set(e.value()),
                                for k in pico_keys.iter() {
                                    option {
                                        value: "{k.path}",
                                        selected: k.path == pico(),
                                        "{short(&k.path)} ({k.application})"
                                    }
                                }
                            }
                        }
                        div { class: "flex flex-col gap-1.5",
                            Label { "Key PIN (only if the Pico key requires it)" }
                            Input {
                                r#type: InputType::Password,
                                value: pin(),
                                oninput: move |e: FormEvent| pin.set(e.value()),
                            }
                        }
                    }
                }
                for k in list {
                    LegacyRow {
                        key: "{k.private_path}",
                        legacy: k,
                        pico: pico(),
                        pin: pin(),
                        on_change: move |_| {
                            inv.restart();
                            on_change.call(());
                        },
                    }
                }
            }
        }
    }
}

#[derive(Clone, PartialEq)]
struct Target {
    host: String,
    added: Option<Result<String, String>>,
    checked: Option<Result<String, String>>,
}

impl Target {
    fn new(host: String) -> Self {
        Self { host, added: None, checked: None }
    }
    fn ok(&self) -> bool {
        matches!(self.checked, Some(Ok(_)))
    }
}

#[component]
fn LegacyRow(legacy: LegacyKey, pico: String, pin: String, on_change: EventHandler<()>) -> Element {
    let k = legacy;
    // Concrete hosts from the config; wildcard patterns need a real host typed in.
    let mut targets = use_signal({
        let h = k.hosts.clone();
        let bad = k.unsupported.clone();
        move || h.iter().filter(|h| !h.contains('*') && !h.starts_with("Match") && !bad.contains(h)).cloned().map(Target::new).collect::<Vec<_>>()
    });
    let patterns: Vec<String> = k.hosts.iter().filter(|h| h.contains('*')).cloned().collect();
    let mut new_host = use_signal(String::new);
    let mut busy = use_signal(|| None::<String>);
    let mut result = use_signal(|| None::<Result<String, String>>);
    let mut open = use_signal(|| false);

    let blocked = !k.unsupported.is_empty();
    let all_ok = !targets.read().is_empty() && targets.read().iter().all(Target::ok);
    let in_config = !k.hosts.is_empty();

    // Captures only signals (Copy), so every button can own a copy.
    let run = move |i: usize, check: bool, pico: String, pin: String| {
        let host = targets.read()[i].host.clone();
        async move {
            busy.set(Some(format!("{i}{check}")));
            let r = if check {
                api::ssh_check(&host, &pico, Some(pin.as_str()).filter(|p| !p.is_empty())).await
            } else {
                api::ssh_authorize(&host, &pico).await
            };
            targets.with_mut(|t| if check { t[i].checked = Some(r.map_err(|e| humanize(&e))) } else { t[i].added = Some(r.map_err(|e| humanize(&e))) });
            busy.set(None);
        }
    };
    let old = k.private_path.clone();
    let pico2 = pico.clone();
    let switch = move |_| {
        let (old, pico) = (old.clone(), pico2.clone());
        async move {
            busy.set(Some("switch".into()));
            result.set(Some(api::ssh_switch_config(&old, &pico).await.map(|c| format!("Updated {}", c.join(", ")))));
            busy.set(None);
            on_change.call(());
        }
    };
    let old = k.private_path.clone();
    let on_disk = k.on_disk;
    let archive = move |_| {
        let old = old.clone();
        async move {
            busy.set(Some("archive".into()));
            let r = api::ssh_archive(&old).await.map(|m| {
                if on_disk { m } else { format!("{m}. The private key itself is in your SSH agent (e.g. 1Password): delete it there too.") }
            });
            result.set(Some(r));
            busy.set(None);
            on_change.call(());
        }
    };

    rsx! {
        div { class: "rounded-lg border",
            button {
                class: "flex w-full flex-wrap items-center gap-2 p-3 text-left",
                onclick: move |_| open.toggle(),
                span { class: "font-mono text-sm", "{short(&k.private_path)}" }
                Badge { variant: BadgeVariant::Secondary, "{k.kind}" }
                if !k.on_disk {
                    Badge { variant: BadgeVariant::Outline, "key in agent / 1Password" }
                }
                if blocked {
                    Badge { variant: BadgeVariant::Warning, "can't move" }
                }
                span { class: "ml-auto truncate text-xs text-muted-foreground",
                    if in_config {
                        "{k.hosts.join(\", \")}"
                    } else {
                        "not used in ~/.ssh/config"
                    }
                }
            }
            if open() {
                div { class: "flex flex-col gap-3 border-t p-3 animate-in fade-in",
                    if blocked {
                        p { class: "flex items-start gap-2 text-sm text-warning",
                            ShieldAlert { class: "mt-0.5 size-4 shrink-0" }
                            "Not accepted for security-key SSH keys by {k.unsupported.join(\", \")}, so this key has to stay."
                        }
                    }
                    if !patterns.is_empty() {
                        p { class: "text-xs text-muted-foreground",
                            "{patterns.join(\", \")} is a pattern: add each real server it covers below."
                        }
                    }
                    for (i, t) in targets.read().iter().cloned().enumerate() {
                        div {
                            key: "{t.host}",
                            class: "flex flex-col gap-1.5 rounded-md bg-muted/40 p-2",
                            div { class: "flex flex-wrap items-center gap-2",
                                span { class: "font-mono text-sm", "{t.host}" }
                                if t.ok() {
                                    CircleCheck { class: "size-4 text-success" }
                                }
                                div { class: "ml-auto flex gap-1.5",
                                    Button {
                                        variant: ButtonVariant::Outline,
                                        size: ButtonSize::Sm,
                                        disabled: busy().is_some() || pico.is_empty(),
                                        onclick: {
                                            let (p, n) = (pico.clone(), pin.clone());
                                            move |_| {
                                                spawn(run(i, false, p.clone(), n.clone()));
                                            }
                                        },
                                        if busy() == Some(format!("{i}false")) {
                                            Spinner {}
                                        } else {
                                            Upload {}
                                        }
                                        "1. Add Pico key"
                                    }
                                    Button {
                                        variant: ButtonVariant::Outline,
                                        size: ButtonSize::Sm,
                                        disabled: busy().is_some() || pico.is_empty(),
                                        onclick: {
                                            let (p, n) = (pico.clone(), pin.clone());
                                            move |_| {
                                                spawn(run(i, true, p.clone(), n.clone()));
                                            }
                                        },
                                        if busy() == Some(format!("{i}true")) {
                                            Spinner {}
                                        } else {
                                            Plug {}
                                        }
                                        "2. Test Pico login"
                                    }
                                    Button {
                                        variant: ButtonVariant::Ghost,
                                        size: ButtonSize::IconXs,
                                        aria_label: "Remove host",
                                        onclick: move |_| {
                                            targets
                                                .with_mut(|t| {
                                                    t.remove(i);
                                                });
                                        },
                                        X {}
                                    }
                                }
                            }
                            for r in [t.added.clone(), t.checked.clone()].into_iter().flatten() {
                                match r {
                                    Ok(m) => rsx! {
                                        p { class: "text-xs text-success", "{m}" }
                                    },
                                    Err(e) => rsx! {
                                        p { class: "selectable whitespace-pre-wrap text-xs text-destructive", "{e}" }
                                    },
                                }
                            }
                            if busy() == Some(format!("{i}true")) {
                                p { class: "text-xs text-primary animate-pulse",
                                    "Touch your Pico key…"
                                }
                            }
                        }
                    }
                    if !blocked {
                        form {
                            class: "flex gap-2",
                            onsubmit: move |e: FormEvent| {
                                e.prevent_default();
                                let h = new_host().trim().to_string();
                                if !h.is_empty() && !targets.read().iter().any(|t| t.host == h) {
                                    targets.with_mut(|t| t.push(Target::new(h)));
                                }
                                new_host.set(String::new());
                            },
                            Input {
                                class: "font-mono",
                                placeholder: "another server, e.g. app.example.com or user@host",
                                value: new_host(),
                                oninput: move |e: FormEvent| new_host.set(e.value()),
                            }
                            Button {
                                variant: ButtonVariant::Outline,
                                size: ButtonSize::Sm,
                                button_type: "submit",
                                Plus {}
                                "Add server"
                            }
                        }
                        div { class: "flex flex-wrap items-center justify-end gap-2 border-t pt-3",
                            span { class: "mr-auto text-xs text-muted-foreground",
                                if blocked {
                                    "Archiving is blocked while a host still needs this key."
                                } else if !all_ok {
                                    "Test every server with the Pico key to continue."
                                } else if in_config {
                                    "All servers accept the Pico key."
                                } else {
                                    "Nothing in ~/.ssh/config uses this key, so it can be archived."
                                }
                            }
                            if in_config {
                                Button {
                                    disabled: blocked || !all_ok || busy().is_some(),
                                    onclick: switch,
                                    if busy().as_deref() == Some("switch") {
                                        Spinner {}
                                    } else {
                                        Check {}
                                    }
                                    "3. Switch ~/.ssh/config"
                                }
                            }
                            Button {
                                variant: ButtonVariant::Warning,
                                disabled: blocked || in_config || (!all_ok && !targets.read().is_empty()) || busy().is_some(),
                                onclick: archive,
                                if busy().as_deref() == Some("archive") {
                                    Spinner {}
                                } else {
                                    Archive {}
                                }
                                "4. Archive old key"
                            }
                        }
                    }
                    match result() {
                        Some(Ok(m)) => rsx! {
                            p { class: "selectable text-sm text-success", "{m}" }
                        },
                        Some(Err(e)) => rsx! {
                            p { class: "selectable text-sm text-destructive", "{humanize(&e)}" }
                        },
                        None => rsx! {},
                    }
                }
            }
        }
    }
}
