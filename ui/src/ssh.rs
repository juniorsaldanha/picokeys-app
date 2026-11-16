//! SSH & Git page: security-key SSH keys, git commit signing, ~/.ssh/config, connection test.
use crate::api;
use crate::pages::{ErrorBox, PageHeader, humanize};
use crate::AppState;
use dioxus::prelude::*;
use icons::{Check, Copy, Download, ExternalLink, Fingerprint, GitCommitHorizontal, KeyRound, Plug, Plus, RefreshCw, Server, TriangleAlert};
use types::{GitSetup, GitSigning, NewSshKey, SshEnv, SshKey};

use crate::ui::alert::{Alert, AlertDescription, AlertTitle, AlertVariant};
use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle};
use crate::ui::input::{Input, InputType};
use crate::ui::label::Label;
use crate::ui::skeleton::Skeleton;
use crate::ui::spinner::Spinner;
use crate::ui::switch::Switch;

#[component]
pub fn SshPage() -> Element {
    let mut env = use_resource(api::ssh_env);
    let mut keys = use_resource(api::ssh_keys);
    let refresh = move |_| {
        env.restart();
        keys.restart();
    };

    let body = match (&*env.read(), &*keys.read()) {
        (Some(Ok(e)), Some(Ok(k))) => rsx! {
            Tooling { env: e.clone(), on_change: move |_| { env.restart(); keys.restart(); } }
            Keys { env: e.clone(), keys: k.clone(), on_change: move |_| keys.restart() }
            if !k.is_empty() {
                GitSigningCard {
                    env: e.clone(),
                    keys: k.clone(),
                    on_change: move |_| {
                        env.restart();
                        keys.restart();
                    },
                }
                Hosts { keys: k.clone() }
            }
            AgentCard {}
            if e.keygen.is_some() {
                crate::migrate::MigrateCard { pico_keys: k.clone(), on_change: move |_| keys.restart() }
            }
        },
        (Some(Err(e)), _) | (_, Some(Err(e))) => rsx! { ErrorBox { title: "Couldn't inspect SSH", msg: humanize(e) } },
        _ => rsx! { Skeleton { class: "h-40 rounded-xl" } },
    };

    rsx! {
        PageHeader { title: "SSH & Git", subtitle: "Log in to servers and sign git commits with a key that never leaves your Pico Key.",
            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, onclick: refresh, RefreshCw {} "Refresh" }
        }
        div { class: "flex flex-col gap-6", {body} }
    }
}

#[component]
fn CopyButton(text: String, #[props(default = "Copy")] label: &'static str) -> Element {
    let mut copied = use_signal(|| false);
    rsx! {
        Button {
            variant: ButtonVariant::Outline,
            size: ButtonSize::Sm,
            onclick: move |_| {
                api::copy_text(&text);
                copied.set(true);
                spawn(async move {
                    api::sleep_ms(1200).await;
                    copied.set(false);
                });
            },
            if copied() { Check {} "Copied" } else { Copy {} "{label}" }
        }
    }
}

#[component]
fn Tooling(env: SshEnv, on_change: EventHandler<()>) -> Element {
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let Some(problem) = env.problem.clone() else {
        return rsx! {
            p { class: "-mt-2 text-xs text-muted-foreground", "Using {env.version} ({env.keygen.clone().unwrap_or_default()})" }
        };
    };
    let install = move |_| async move {
        busy.set(true);
        error.set(None);
        match api::ssh_install_openssh().await {
            Ok(_) => on_change.call(()),
            Err(e) => error.set(Some(e)),
        }
        busy.set(false);
    };
    rsx! {
        Alert { variant: AlertVariant::Warning,
            TriangleAlert {}
            AlertTitle { "{problem}" }
            AlertDescription {
                div { class: "flex flex-col gap-2",
                    if env.os == "macos" && env.brew {
                        span { "Install OpenSSH from Homebrew. Apple's own ssh, your keys and your settings aren't changed." }
                        div { class: "flex flex-wrap items-center gap-2",
                            Button { size: ButtonSize::Sm, disabled: busy(), onclick: install,
                                if busy() { Spinner {} } else { Download {} }
                                if busy() { "Installing… (can take a few minutes)" } else { "Install OpenSSH" }
                            }
                            span { class: "text-xs text-muted-foreground", "Runs: brew install openssh" }
                        }
                        if let Some(e) = error() { pre { class: "selectable whitespace-pre-wrap text-xs text-destructive", "{e}" } }
                    } else if env.os == "macos" {
                        span { "Homebrew is needed first. Install it from brew.sh, then come back and click Refresh; the app can install OpenSSH for you after that." }
                        a { href: "https://brew.sh", target: "_blank",
                            Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, ExternalLink {} "Open brew.sh" }
                        }
                    } else if env.os == "windows" {
                        span { "Install the OpenSSH Client (Settings → System → Optional features) or Git for Windows, then click Refresh." }
                    } else {
                        span { "Install OpenSSH 8.2 or newer with your package manager (for example openssh-client), then click Refresh." }
                    }
                }
            }
        }
    }
}

#[component]
fn Keys(env: SshEnv, keys: Vec<SshKey>, on_change: EventHandler<()>) -> Element {
    let mut creating = use_signal(|| false);
    let mut importing = use_signal(|| false);
    let can_create = env.keygen.is_some();
    rsx! {
        Card {
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "SSH keys" }
                        CardDescription { "Security-key SSH keys in ~/.ssh. The private part stays on the Pico Key; the file only points to it." }
                    }
                    div { class: "flex shrink-0 gap-2",
                        Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: !can_create || importing(), onclick: move |_| importing.set(true), Download {} "Import from Pico" }
                        Button { size: ButtonSize::Sm, disabled: !can_create || creating(), onclick: move |_| creating.set(true), Plus {} "New key" }
                    }
                }
            }
            CardContent { class: "flex flex-col gap-3",
                if importing() {
                    ImportForm {
                        on_done: move |n: usize| {
                            importing.set(false);
                            if n > 0 {
                                on_change.call(())
                            }
                        },
                    }
                }
                if creating() {
                    NewKeyForm {
                        on_done: move |made: bool| {
                            creating.set(false);
                            if made {
                                on_change.call(())
                            }
                        },
                    }
                }
                if keys.is_empty() && !creating() {
                    p { class: "text-sm text-muted-foreground",
                        if can_create { "No security-key SSH keys yet. Create one to get started." } else { "No security-key SSH keys yet." }
                    }
                }
                for k in keys {
                    div { key: "{k.path}", class: "flex flex-col gap-2 rounded-lg border p-3",
                        div { class: "flex flex-wrap items-center gap-2",
                            KeyRound { class: "size-4 text-primary" }
                            span { class: "font-mono text-sm", "{k.path.rsplit(['/', '\\\\']).next().unwrap_or(&k.path)}" }
                            Badge { variant: BadgeVariant::Secondary, "{k.kind}" }
                            Badge { variant: BadgeVariant::Outline, "{k.application}" }
                            if k.signing { Badge { variant: BadgeVariant::Success, "Signs git commits" } }
                            span { class: "ml-auto truncate text-xs text-muted-foreground", "{k.comment}" }
                        }
                        code { class: "selectable block truncate rounded bg-muted px-2 py-1 font-mono text-xs text-muted-foreground", "{k.public}" }
                        div { class: "flex flex-wrap gap-2",
                            CopyButton { text: k.public.clone(), label: "Copy public key" }
                            a { href: "https://github.com/settings/ssh/new", target: "_blank",
                                Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, ExternalLink {} "Add to GitHub" }
                            }
                            a { href: "https://gitlab.com/-/user_settings/ssh_keys", target: "_blank",
                                Button { variant: ButtonVariant::Ghost, size: ButtonSize::Sm, ExternalLink {} "Add to GitLab" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ImportForm(on_done: EventHandler<usize>) -> Element {
    let st = use_context::<AppState>();
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let run = move |e: FormEvent| async move {
        e.prevent_default();
        busy.set(true);
        error.set(None);
        let p = pin();
        match api::ssh_recover(Some(p.as_str()).filter(|p| !p.is_empty())).await {
            Ok(k) => on_done.call(k.len()),
            Err(e) => error.set(Some(humanize(&e))),
        }
        busy.set(false);
    };
    rsx! {
        form { class: "flex flex-col gap-3 rounded-lg border bg-muted/30 p-4 animate-in fade-in", onsubmit: run,
            p { class: "text-sm text-muted-foreground",
                "Copies the SSH keys stored on this Pico (created with “Store on the key”) into ~/.ssh, e.g. on a new computer. Existing files are left alone."
            }
            div { class: "flex flex-wrap items-end gap-2",
                div { class: "flex flex-col gap-1.5",
                    Label { "Key PIN" }
                    Input { r#type: InputType::Password, value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                }
                Button { variant: ButtonVariant::Ghost, button_type: "button", disabled: busy(), onclick: move |_| on_done.call(0), "Cancel" }
                Button { button_type: "submit", disabled: busy() || pin().is_empty(),
                    if busy() { Spinner {} } else { Download {} }
                    "Import"
                }
                if busy() { span { class: "flex items-center gap-1.5 text-sm text-primary animate-pulse", Fingerprint { class: "size-4" } "Touch your key if it blinks…" } }
            }
            if let Some(e) = error() { p { class: "text-sm text-destructive", "{e}" } }
        }
    }
}

#[component]
fn NewKeyForm(on_done: EventHandler<bool>) -> Element {
    let st = use_context::<AppState>();
    // Default to Ed25519 only if the key says it supports EdDSA.
    let eddsa = st.info.read().as_ref().and_then(|o| o.as_ref()).and_then(|r| r.as_ref().ok()).is_some_and(|i| i.algorithms.iter().any(|a| a.contains("EdDSA") || a.contains("Ed25519")));
    let mut ed25519 = use_signal(move || eddsa);
    let mut file = use_signal(move || if eddsa { "id_ed25519_sk".to_string() } else { "id_ecdsa_sk".to_string() });
    let mut label = use_signal(String::new);
    let mut comment = use_signal(|| "pico-key".to_string());
    let mut resident = use_signal(|| false);
    let mut verify = use_signal(|| false);
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let save = move |e: FormEvent| async move {
        e.prevent_default();
        busy.set(true);
        error.set(None);
        let req = NewSshKey {
            file: file(),
            ed25519: ed25519(),
            resident: resident(),
            verify_required: verify(),
            label: label(),
            comment: comment(),
            pin: Some(pin()).filter(|p| !p.is_empty()),
        };
        match api::ssh_generate(&req).await {
            Ok(_) => on_done.call(true),
            Err(e) => error.set(Some(humanize(&e))),
        }
        busy.set(false);
    };

    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    rsx! {
        form { class: "flex flex-col gap-4 rounded-lg border bg-muted/30 p-4 animate-in fade-in", onsubmit: save,
            div { class: "grid gap-3 sm:grid-cols-3",
                div { class: "flex flex-col gap-1.5",
                    Label { "Type" }
                    select {
                        class: select_cls,
                        onchange: move |e: FormEvent| {
                            let ed = e.value() == "ed";
                            ed25519.set(ed);
                            if file().starts_with("id_ecdsa_sk") || file().starts_with("id_ed25519_sk") {
                                file.set(if ed { "id_ed25519_sk".into() } else { "id_ecdsa_sk".into() });
                            }
                        },
                        option { value: "ecdsa", selected: !ed25519(), "ECDSA P-256 (ecdsa-sk)" }
                        option { value: "ed", selected: ed25519(), disabled: !eddsa,
                            if eddsa { "Ed25519 (ed25519-sk)" } else { "Ed25519 (ed25519-sk): not supported by this key" }
                        }
                    }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "File in ~/.ssh" }
                    Input { class: "font-mono", value: file(), oninput: move |e: FormEvent| file.set(e.value()) }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "Comment" }
                    Input { value: comment(), oninput: move |e: FormEvent| comment.set(e.value()) }
                }
            }
            div { class: "grid gap-3 sm:grid-cols-2",
                div { class: "flex flex-col gap-1.5",
                    Label { "Label (optional)" }
                    Input { placeholder: "work", value: label(), oninput: move |e: FormEvent| label.set(e.value()) }
                    p { class: "text-xs text-muted-foreground", "Stored as ssh:{label}. Use different labels for separate keys on the same Pico Key." }
                }
                div { class: "flex flex-col gap-1.5",
                    Label { "Key PIN" }
                    Input { r#type: InputType::Password, placeholder: "Needed because the key has a PIN", value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                }
            }
            div { class: "flex items-center justify-between gap-4",
                div {
                    div { class: "text-sm font-medium", "Store on the key (resident)" }
                    div { class: "text-xs text-muted-foreground", "Lets you recreate the file on another computer with ssh-keygen -K. Anyone with the key and its PIN can do the same." }
                }
                Switch { checked: resident(), aria_label: "Resident", onchange: move |v| resident.set(v) }
            }
            div { class: "flex items-center justify-between gap-4",
                div {
                    div { class: "text-sm font-medium", "Require PIN on every use" }
                    div { class: "text-xs text-muted-foreground", "Otherwise a touch is enough to log in or sign." }
                }
                Switch { checked: verify(), aria_label: "Require PIN", onchange: move |v| verify.set(v) }
            }
            if let Some(e) = error() { p { class: "text-sm text-destructive", "{e}" } }
            div { class: "flex items-center justify-end gap-2",
                if busy() {
                    span { class: "mr-auto flex items-center gap-1.5 text-sm text-primary animate-pulse", Fingerprint { class: "size-4" } "Touch your key…" }
                }
                Button { variant: ButtonVariant::Ghost, button_type: "button", disabled: busy(), onclick: move |_| on_done.call(false), "Cancel" }
                Button { button_type: "submit", disabled: busy() || file().is_empty(),
                    if busy() { Spinner {} } else { Plus {} }
                    "Create key"
                }
            }
        }
    }
}

/// Shell commands that put the previous signing setup back.
fn restore_cmds(prev: &GitSigning) -> String {
    let set = |k: &str, v: &Option<String>| match v {
        Some(v) => format!("git config --global {k} '{}'", v.replace('\'', r"'\''")),
        None => format!("git config --global --unset {k}"),
    };
    [
        set("gpg.format", &prev.format),
        set("user.signingkey", &prev.signing_key),
        set("gpg.ssh.program", &prev.ssh_program),
        set("core.sshCommand", &prev.ssh_command),
        format!("git config --global commit.gpgsign {}", prev.commit_sign),
        format!("git config --global tag.gpgsign {}", prev.tag_sign),
    ]
    .join("\n")
}

#[component]
fn GitSigningCard(env: SshEnv, keys: Vec<SshKey>, on_change: EventHandler<()>) -> Element {
    let cur = env.signing.clone();
    let mut key = use_signal({
        let k = keys.clone();
        move || k.iter().find(|k| k.signing).or(k.first()).map(|k| k.path.clone()).unwrap_or_default()
    });
    let mut email = use_signal({
        let e = cur.email.clone();
        move || e.unwrap_or_default()
    });
    let mut commits = use_signal(|| true);
    let mut tags = use_signal(|| true);
    let mut transport = use_signal(|| true);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut confirm = use_signal(|| false);
    let mut backup = use_signal(|| None::<String>);

    let already = keys.iter().any(|k| k.signing && k.path == key());
    // Something else (another key, 1Password, GPG) is set up for signing.
    let replacing = cur.signing_key.is_some() && !keys.iter().any(|k| k.signing);
    let via = cur.ssh_program.as_deref().map(|p| if p.contains("1Password") || p.contains("op-ssh-sign") { "1Password".to_string() } else { p.to_string() });
    let mac_brew = env.os == "macos" && env.keygen.as_deref().is_some_and(|k| !k.starts_with("/usr/bin"));

    let prev_sig = cur.clone();
    let apply = move |_: ()| {
        let prev = prev_sig.clone();
        async move {
            busy.set(true);
            error.set(None);
            let setup = GitSetup { key: key(), email: email(), sign_commits: commits(), sign_tags: tags(), use_for_transport: transport() };
            match api::ssh_git_setup(&setup).await {
                Ok(_) => {
                    if prev.signing_key.is_some() {
                        backup.set(Some(restore_cmds(&prev)));
                    }
                    confirm.set(false);
                    on_change.call(());
                }
                Err(e) => error.set(Some(humanize(&e))),
            }
            busy.set(false);
        }
    };

    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    rsx! {
        Card {
            CardHeader {
                CardTitle { class: "flex items-center gap-2", GitCommitHorizontal { class: "size-4" } "Git commit signing" }
                CardDescription { "Signs commits and tags with your Pico Key (git 2.34+). You'll touch the key for each signature." }
            }
            CardContent { class: "flex flex-col gap-4",
                div { class: "rounded-lg bg-muted/60 px-3 py-2 text-sm",
                    span { class: "text-muted-foreground", "Now: " }
                    match (&cur.format, &cur.signing_key) {
                        (_, None) => rsx! { "commits aren't signed." },
                        (f, Some(k)) => rsx! {
                            span { class: "font-mono text-xs break-all", "{k.chars().take(60).collect::<String>()}" }
                            span { class: "text-muted-foreground", " ({f.clone().unwrap_or(\"gpg\".into())}" }
                            if let Some(v) = &via { span { class: "text-muted-foreground", ", via {v}" } }
                            span { class: "text-muted-foreground", if cur.commit_sign { ", commits signed)" } else { ", commits not signed by default)" } }
                        },
                    }
                }
                div { class: "grid gap-3 sm:grid-cols-2",
                    div { class: "flex flex-col gap-1.5",
                        Label { "Key" }
                        select { class: select_cls, onchange: move |e: FormEvent| key.set(e.value()),
                            for k in keys.iter() {
                                option { value: "{k.path}", selected: k.path == key(), "{k.path.rsplit(['/', '\\\\']).next().unwrap_or(&k.path)} ({k.application})" }
                            }
                        }
                    }
                    div { class: "flex flex-col gap-1.5",
                        Label { "Commit email" }
                        Input { r#type: InputType::Email, value: email(), oninput: move |e: FormEvent| email.set(e.value()) }
                    }
                }
                div { class: "flex flex-wrap gap-x-8 gap-y-3",
                    label { class: "flex items-center gap-2 text-sm", Switch { checked: commits(), aria_label: "Sign commits", onchange: move |v| commits.set(v) } "Sign every commit" }
                    label { class: "flex items-center gap-2 text-sm", Switch { checked: tags(), aria_label: "Sign tags", onchange: move |v| tags.set(v) } "Sign every tag" }
                    if mac_brew {
                        label { class: "flex items-center gap-2 text-sm", Switch { checked: transport(), aria_label: "Use for push", onchange: move |v| transport.set(v) } "Use Homebrew ssh for git push/pull" }
                    }
                }
                if replacing && confirm() {
                    Alert { variant: AlertVariant::Warning,
                        TriangleAlert {}
                        AlertTitle { "This replaces your current signing setup" }
                        AlertDescription {
                            if let Some(v) = &via { "Commits are signed with a key from {v} today. " }
                            "You'll get the commands to switch back right after."
                        }
                    }
                }
                if let Some(cmds) = backup() {
                    div { class: "flex flex-col gap-2 rounded-lg border p-3",
                        div { class: "flex items-center justify-between gap-2",
                            span { class: "text-sm font-medium", "To go back to your previous setup, run:" }
                            CopyButton { text: cmds.clone() }
                        }
                        pre { class: "selectable overflow-x-auto rounded bg-muted p-2 font-mono text-xs", "{cmds}" }
                    }
                }
                if let Some(e) = error() { p { class: "text-sm text-destructive", "{e}" } }
            }
            CardFooter { class: "justify-end gap-2",
                if confirm() {
                    Button { variant: ButtonVariant::Ghost, onclick: move |_| confirm.set(false), "Cancel" }
                }
                Button {
                    variant: if replacing && confirm() { ButtonVariant::Warning } else { ButtonVariant::Default },
                    disabled: busy() || key().is_empty(),
                    onclick: move |_| {
                        if replacing && !confirm() {
                            confirm.set(true);
                        } else {
                            spawn(apply(()));
                        }
                    },
                    if busy() { Spinner {} }
                    if already { "Update git settings" } else if replacing && confirm() { "Replace and sign with Pico Key" } else { "Sign with this key" }
                }
            }
        }
    }
}

#[component]
fn Hosts(keys: Vec<SshKey>) -> Element {
    let st = use_context::<AppState>();
    let mut host = use_signal(|| "github.com".to_string());
    let mut key = use_signal({
        let k = keys.clone();
        move || k.first().map(|k| k.path.clone()).unwrap_or_default()
    });
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());
    let mut busy = use_signal(|| None::<&'static str>);
    let mut result = use_signal(|| None::<Result<String, String>>);

    let add = move |_| async move {
        busy.set(Some("add"));
        result.set(Some(api::ssh_add_host(&host(), &key()).await.map(|b| format!("Added to ~/.ssh/config:\n{b}"))));
        busy.set(None);
    };
    let test = move |_| async move {
        busy.set(Some("test"));
        let p = pin();
        result.set(Some(api::ssh_test(&host(), &key(), Some(p.as_str()).filter(|p| !p.is_empty())).await));
        busy.set(None);
    };

    let select_cls = "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 dark:bg-input/30";
    rsx! {
        Card {
            CardHeader {
                CardTitle { class: "flex items-center gap-2", Server { class: "size-4" } "Servers and git hosts" }
                CardDescription { "Tell ssh to use this key for a host, then check that logging in works. Add the public key to the host first." }
            }
            CardContent { class: "flex flex-col gap-4",
                div { class: "grid gap-3 sm:grid-cols-3",
                    div { class: "flex flex-col gap-1.5",
                        Label { "Host" }
                        Input { placeholder: "github.com", value: host(), oninput: move |e: FormEvent| host.set(e.value()) }
                    }
                    div { class: "flex flex-col gap-1.5",
                        Label { "Key" }
                        select { class: select_cls, onchange: move |e: FormEvent| key.set(e.value()),
                            for k in keys.iter() {
                                option { value: "{k.path}", selected: k.path == key(), "{k.path.rsplit(['/', '\\\\']).next().unwrap_or(&k.path)}" }
                            }
                        }
                    }
                    div { class: "flex flex-col gap-1.5",
                        Label { "PIN (if the key requires it)" }
                        Input { r#type: InputType::Password, value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                    }
                }
                match result() {
                    Some(Ok(msg)) => rsx! { pre { class: "selectable whitespace-pre-wrap rounded-lg bg-success/10 p-3 font-mono text-xs", "{msg}" } },
                    Some(Err(e)) => rsx! { pre { class: "selectable whitespace-pre-wrap rounded-lg bg-destructive/10 p-3 font-mono text-xs text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
            CardFooter { class: "justify-end gap-2",
                if busy() == Some("test") {
                    span { class: "mr-auto flex items-center gap-1.5 text-sm text-primary animate-pulse", Fingerprint { class: "size-4" } "Touch your key…" }
                }
                Button { variant: ButtonVariant::Outline, disabled: busy().is_some(), onclick: add,
                    if busy() == Some("add") { Spinner {} } else { Plus {} }
                    "Add to ~/.ssh/config"
                }
                Button { disabled: busy().is_some(), onclick: test,
                    if busy() == Some("test") { Spinner {} } else { Plug {} }
                    "Test connection"
                }
            }
        }
    }
}

/// Built-in ssh-agent: lets any ssh (even Apple's) use the Pico keys.
#[component]
fn AgentCard() -> Element {
    let st = use_context::<AppState>();
    let mut status = use_resource(api::agent_status);
    let mut pin = use_signal(move || st.pin.peek().clone().unwrap_or_default());
    let mut err = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let Some(Ok(s)) = status.read().clone() else { return rsx! {} };
    if !s.supported {
        return rsx! {};
    }
    let toggle = move |on: bool| async move {
        busy.set(true);
        let p = pin.peek().clone();
        match api::agent_set(on, Some(p.as_str()).filter(|p| !p.is_empty())).await {
            Ok(_) => err.set(None),
            Err(e) => err.set(Some(e)),
        }
        status.restart();
        busy.set(false);
    };
    let export = format!("export SSH_AUTH_SOCK=\"{}\"", s.socket);
    rsx! {
        Card {
            CardHeader {
                div { class: "flex items-start justify-between gap-3",
                    div {
                        CardTitle { "Built-in SSH agent" }
                        CardDescription { "Signs with your Pico keys for any ssh client, including Apple's, without Homebrew. Runs while this app is open." }
                    }
                    Switch { checked: s.running, disabled: busy(), aria_label: "Run agent", onchange: move |v: bool| { spawn(toggle(v)); } }
                }
            }
            CardContent { class: "flex flex-col gap-3 text-sm",
                if !s.running {
                    div { class: "flex max-w-xs flex-col gap-1.5",
                        Label { "Key PIN (needed when \"Always require PIN\" is on)" }
                        Input { r#type: InputType::Password, value: pin(), oninput: move |e: FormEvent| pin.set(e.value()) }
                    }
                } else {
                    p { class: "text-muted-foreground",
                        if s.keys.is_empty() { "Running, but there are no Pico SSH keys in ~/.ssh yet." } else { "Offering {s.keys.len()} key(s): {s.keys.join(\", \")}" }
                    }
                    p { "Use it in a terminal:" }
                    div { class: "flex items-center gap-2",
                        code { class: "selectable flex-1 truncate rounded-md bg-muted px-2.5 py-2 font-mono text-xs", "{export}" }
                        CopyButton { text: export.clone() }
                    }
                    p { class: "text-xs text-muted-foreground",
                        "Or per host in ~/.ssh/config: IdentityAgent {s.socket}. Your 1Password agent stays the default everywhere else."
                    }
                }
                if let Some(e) = err() { p { class: "text-destructive", "{e}" } }
            }
        }
    }
}
