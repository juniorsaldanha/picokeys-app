//! Pico Vault: copy passkeys between keys enrolled in the same vault (pico-fido 8.2+).
use crate::pages::humanize;
use crate::ui::badge::{Badge, BadgeVariant};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::spinner::Spinner;
use crate::{AppState, api};
use dioxus::prelude::*;
use icons::{Download, Upload};

fn use_vault() -> Resource<Option<Result<types::VaultStatus, String>>> {
    let st = use_context::<AppState>();
    use_resource(move || async move { Some(api::vault_status(&(st.device)()?.path).await) })
}

#[component]
pub fn VaultCard(on_change: EventHandler<()>) -> Element {
    let st = use_context::<AppState>();
    let vault = use_vault();
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let import = move |_| async move {
        let (Some(d), Some(p)) = (st.device.peek().clone(), st.pin.peek().clone()) else { return };
        busy.set(true);
        msg.set(None);
        match api::vault_import(&d.path, &p).await {
            Ok(true) => {
                msg.set(Some(Ok("Passkey imported.".into())));
                on_change.call(());
            }
            Ok(false) => {}
            Err(e) => msg.set(Some(Err(humanize(&e)))),
        }
        busy.set(false);
    };
    let body = match &*vault.read() {
        Some(Some(Ok(v))) if v.enrolled => rsx! {
            div { class: "flex items-center gap-2 text-sm",
                Badge { variant: BadgeVariant::Success, "Enrolled" }
                if !v.label.is_empty() { span { "{v.label}" } }
                span { class: "selectable truncate font-mono text-xs text-muted-foreground", "{v.id}" }
            }
            p { class: "text-sm text-muted-foreground", "Export a passkey from its details below. Import works on any key enrolled in this same vault." }
            div {
                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: busy(), onclick: import,
                    if busy() { Spinner {} } else { Upload {} }
                    "Import package…"
                }
            }
        },
        Some(Some(Ok(_))) => rsx! {
            p { class: "text-sm text-muted-foreground",
                "This key isn't enrolled in a vault. Enrolling is done once with the vendor's licensed "
                code { "pico_vault_enroller" }
                "; after that, export and import work here."
            }
        },
        Some(Some(Err(e))) => rsx! { p { class: "text-sm text-muted-foreground", "{humanize(e)}" } },
        _ => rsx! { Spinner {} },
    };
    rsx! {
        Card { class: "mt-6",
            CardHeader {
                CardTitle { "Pico Vault" }
                CardDescription { "Move passkeys between your own keys as encrypted packages only keys in the same vault can open." }
            }
            CardContent { class: "flex flex-col gap-3",
                {body}
                match msg() {
                    Some(Ok(m)) => rsx! { p { class: "text-sm text-success", "{m}" } },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-destructive", "{e}" } },
                    None => rsx! {},
                }
            }
        }
    }
}

/// Per-passkey export button; renders nothing unless the key is enrolled.
#[component]
pub fn VaultExportButton(cred_id: String, rp_id: String) -> Element {
    let st = use_context::<AppState>();
    let vault = use_vault();
    let mut busy = use_signal(|| false);
    let mut msg = use_signal(|| None::<Result<String, String>>);
    let enrolled = matches!(&*vault.read(), Some(Some(Ok(v))) if v.enrolled);
    if !enrolled {
        return rsx! {};
    }
    let export = move |_| {
        let (cred_id, rp_id) = (cred_id.clone(), rp_id.clone());
        async move {
            let (Some(d), Some(p)) = (st.device.peek().clone(), st.pin.peek().clone()) else { return };
            busy.set(true);
            let r = api::vault_export(&d.path, &p, &cred_id, &format!("passkey-{rp_id}")).await;
            msg.set(Some(r.map(|f| format!("Saved to {f}. It holds the passkey's private key, encrypted to your vault.")).map_err(|e| humanize(&e))));
            busy.set(false);
        }
    };
    rsx! {
        div { class: "flex flex-col gap-2",
            div {
                Button { variant: ButtonVariant::Outline, size: ButtonSize::Sm, disabled: busy(), onclick: export,
                    if busy() { Spinner {} } else { Download {} }
                    "Export to Vault package"
                }
            }
            match msg() {
                Some(Ok(m)) => rsx! { p { class: "selectable text-sm text-success", "{m}" } },
                Some(Err(e)) => rsx! { p { class: "text-sm text-destructive", "{e}" } },
                None => rsx! {},
            }
        }
    }
}
