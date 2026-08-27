use ap_core::Locale;
use ap_core::i18n::{Argument, message, message_with};
use clap::Subcommand;
use uuid::Uuid;

use crate::api::{Api, Reply};
use crate::args::{parse_size, parse_until};
use crate::output::{Format, Rendered};

/// Why a command did not run to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The arguments were not accepted.
    Arguments(String),
    /// What was asked for does not exist.
    NotFound(String),
    /// Everything was understood, the work did not finish.
    Execution(String),
}

/// Settings shared by every command.
pub struct Context {
    /// Language of the output.
    pub locale: Locale,
    /// How the result is written.
    pub format: Format,
    /// The panel this client speaks to.
    pub api: Api,
    /// Where the session token is kept.
    pub token_path: std::path::PathBuf,
}

type Outcome = Result<Rendered, Failure>;

#[derive(Subcommand)]
pub enum ClientCommand {
    /// Registers a client.
    Add {
        /// Name the operator knows this client by.
        label: String,
        /// Ceiling across every access, such as 50G, or 0 for none.
        #[arg(long, default_value = "0")]
        quota: String,
        /// Last day of service, or never.
        #[arg(long, default_value = "never")]
        until: String,
    },
    /// Shows one client and the accesses it holds.
    Show {
        /// Name the operator knows this client by.
        label: String,
    },
    /// Lists every client.
    List,
    /// Stops serving a client, reversibly.
    Suspend {
        /// Name the operator knows this client by.
        label: String,
    },
    /// Resumes a suspended client.
    Resume {
        /// Name the operator knows this client by.
        label: String,
    },
    /// Keeps a client for the record only.
    Archive {
        /// Name the operator knows this client by.
        label: String,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Issues an access to a client on a node.
    Add {
        /// Client the access belongs to.
        client: String,
        /// Node the access lives on.
        #[arg(long)]
        node: String,
        /// One of faketls, web, mtproto, socks5, http.
        #[arg(long)]
        method: String,
        /// Group the access is selected and withdrawn by.
        #[arg(long)]
        tag: Option<String>,
        /// Ceiling for this access, such as 50G, or 0 for none.
        #[arg(long, default_value = "0")]
        quota: String,
        /// Last day of service, or never.
        #[arg(long, default_value = "never")]
        until: String,
    },
    /// Lists the accesses a client holds.
    List {
        /// Client the accesses belong to.
        client: String,
    },
    /// Prints the connection link, revealing the secret.
    Link {
        /// Identifier of the access.
        id: Uuid,
        /// Address clients reach the node at.
        #[arg(long)]
        host: String,
        /// Acknowledges that a secret is about to be printed.
        #[arg(long)]
        yes: bool,
    },
    /// Stops serving an access, reversibly.
    Disable {
        /// Identifier of the access.
        id: Uuid,
    },
    /// Resumes a disabled access.
    Enable {
        /// Identifier of the access.
        id: Uuid,
    },
    /// Withdraws an access for good.
    Revoke {
        /// Identifier of the access.
        id: Uuid,
    },
}

#[derive(Subcommand)]
pub enum TagCommand {
    /// Creates a tag.
    Add {
        /// Name of the tag.
        name: String,
    },
    /// Lists every tag.
    List,
}

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Registers a node and shows its enrolment code once.
    Add {
        /// Name the operator knows this node by.
        label: String,
        /// Either stealth or open.
        #[arg(long)]
        kind: String,
        /// Hostname a stealth node answers on.
        #[arg(long)]
        domain: Option<String>,
    },
    /// Lists every node.
    List,
}

/// Runs one command.
pub async fn dispatch(command: crate::Command, context: Context) -> Outcome {
    match command {
        crate::Command::Login => login(context).await,
        crate::Command::Logout => logout(context),
        crate::Command::Client(command) => client(command, context).await,
        crate::Command::Access(command) => access(command, context).await,
        crate::Command::Tag(command) => tag(command, context).await,
        crate::Command::Node(command) => node(command, context).await,
    }
}

// ── talking to the panel ─────────────────────────────────────────────────

/// Turns a refusal into something the operator can read.
///
/// The panel's own message is discarded. It is written in whichever language
/// the panel runs in, and nothing says that is the language of the person
/// reading it; what travels is the code, and the sentence is made here.
fn refused(reply: &Reply, locale: Locale) -> Failure {
    let code = reply.code();
    let key = format!("api-{}", code.replace('_', "-"));
    let message = say(locale, &key, &[]).unwrap_or_else(|_| {
        say(
            locale,
            "api-unknown",
            &[("code", Argument::Text(code.as_str()))],
        )
        .unwrap_or(code.clone())
    });

    match reply.status {
        401 | 403 => Failure::Execution(message),
        404 => Failure::NotFound(message),
        400 | 422 | 429 => Failure::Arguments(message),
        _ => Failure::Execution(message),
    }
}

/// Reads something, or says why not.
async fn get(context: &Context, path: &str) -> Result<serde_json::Value, Failure> {
    let reply = context.api.get(path).await.map_err(Failure::Execution)?;
    if reply.ok() {
        Ok(reply.json())
    } else {
        Err(refused(&reply, context.locale))
    }
}

/// Asks for something to be done, or says why not.
async fn post(
    context: &Context,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, Failure> {
    let reply = context
        .api
        .post(path, body)
        .await
        .map_err(Failure::Execution)?;
    if reply.ok() {
        Ok(reply.json())
    } else {
        Err(refused(&reply, context.locale))
    }
}

fn say(locale: Locale, key: &str, args: &[(&str, Argument<'_>)]) -> Result<String, Failure> {
    let rendered = if args.is_empty() {
        message(locale, key)
    } else {
        message_with(locale, key, args)
    };
    rendered.map_err(|error| Failure::Execution(error.to_string()))
}

fn field(locale: Locale, key: &str, value: &str) -> Result<String, Failure> {
    Ok(format!("{}: {value}", say(locale, key, &[])?))
}

/// A string field, or an empty one.
fn text(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
}

// ── signing in ───────────────────────────────────────────────────────────

async fn login(context: Context) -> Outcome {
    let locale = context.locale;

    // Neither the password nor the code is ever an argument: an argument
    // reaches the shell history and the process list, where anyone on the
    // machine can read it. They are typed, and they are visible while typed —
    // turning the terminal's echo off needs a foreign function interface,
    // which this project forbids, and pretending otherwise would be worse
    // than saying so.
    let login = ask(locale, "cli-login-prompt")?;
    let password = ask(locale, "cli-password-prompt")?;
    let totp = ask(locale, "cli-totp-prompt")?;

    let body = serde_json::json!({ "login": login, "password": password, "totp": totp });
    let reply = context
        .api
        .post("/v1/session", body)
        .await
        .map_err(Failure::Execution)?;
    if !reply.ok() {
        return Err(refused(&reply, locale));
    }

    let token = reply.json()["token"]
        .as_str()
        .ok_or_else(|| Failure::Execution("the panel returned no token".to_owned()))?
        .to_owned();
    crate::api::write_token(&context.token_path, &token).map_err(Failure::Execution)?;

    Ok(Rendered::line(say(
        locale,
        "cli-signed-in",
        &[("login", Argument::Text(&login))],
    )?))
}

fn logout(context: Context) -> Outcome {
    crate::api::forget_token(&context.token_path).map_err(Failure::Execution)?;
    Ok(Rendered::line(say(context.locale, "cli-signed-out", &[])?))
}

/// Asks the operator for one value.
///
/// Prompts go to standard error so that piping the output of a command does
/// not swallow them, and so a value read here never lands in a redirect.
fn ask(locale: Locale, key: &str) -> Result<String, Failure> {
    use std::io::Write as _;

    let prompt = say(locale, key, &[])?;
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{prompt} ");
    let _ = err.flush();
    drop(err);

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| Failure::Execution(error.to_string()))?;
    Ok(line.trim_end().to_owned())
}

// ── clients ──────────────────────────────────────────────────────────────

async fn client(command: ClientCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        ClientCommand::Add {
            label,
            quota,
            until,
        } => {
            let quota =
                parse_size(&quota).map_err(|error| Failure::Arguments(error.to_string()))?;
            let until =
                parse_until(&until).map_err(|error| Failure::Arguments(error.to_string()))?;
            let expires_at = until
                .map(ap_core::time::format_rfc3339)
                .transpose()
                .map_err(|error| Failure::Execution(error.to_string()))?;

            post(
                &context,
                "/v1/clients",
                serde_json::json!({
                    "label": label,
                    "quota_bytes": quota,
                    "expires_at": expires_at,
                }),
            )
            .await?;

            Ok(Rendered::line(say(
                locale,
                "cli-client-created",
                &[("label", Argument::Text(&label))],
            )?))
        }
        ClientCommand::Show { label } => {
            let record = client_by_label(&context, &label).await?;
            let id = text(&record, "id");
            let accesses = get(&context, &format!("/v1/clients/{id}/accesses")).await?;
            show_client(&record, &accesses, &context)
        }
        ClientCommand::List => {
            let clients = get(&context, "/v1/clients").await?;
            list_clients(&clients, &context)
        }
        ClientCommand::Suspend { label } => set_client_state(&context, &label, "suspended").await,
        ClientCommand::Resume { label } => set_client_state(&context, &label, "active").await,
        ClientCommand::Archive { label } => set_client_state(&context, &label, "archived").await,
    }
}

/// The one client with this label, or nothing found.
async fn client_by_label(context: &Context, label: &str) -> Result<serde_json::Value, Failure> {
    let found = get(context, &format!("/v1/clients?label={label}")).await?;
    found
        .as_array()
        .and_then(|rows| rows.first())
        .cloned()
        .ok_or_else(|| {
            Failure::NotFound(
                say(
                    context.locale,
                    "cli-client-not-found",
                    &[("label", Argument::Text(label))],
                )
                .unwrap_or_else(|_| label.to_owned()),
            )
        })
}

/// The one node with this label, or nothing found.
async fn node_by_label(context: &Context, label: &str) -> Result<serde_json::Value, Failure> {
    let found = get(context, &format!("/v1/nodes?label={label}")).await?;
    found
        .as_array()
        .and_then(|rows| rows.first())
        .cloned()
        .ok_or_else(|| {
            Failure::NotFound(
                say(
                    context.locale,
                    "cli-node-not-found",
                    &[("label", Argument::Text(label))],
                )
                .unwrap_or_else(|_| label.to_owned()),
            )
        })
}

async fn set_client_state(context: &Context, label: &str, state: &str) -> Outcome {
    let record = client_by_label(context, label).await?;
    let id = text(&record, "id");
    post(
        context,
        &format!("/v1/clients/{id}/state"),
        serde_json::json!({ "state": state }),
    )
    .await?;
    Ok(Rendered::Silent)
}

fn show_client(
    record: &serde_json::Value,
    accesses: &serde_json::Value,
    context: &Context,
) -> Outcome {
    let locale = context.locale;
    let rows = accesses.as_array().cloned().unwrap_or_default();

    match context.format {
        Format::Json => {
            let mut shown = record.clone();
            shown["accesses"] = serde_json::json!(
                rows.iter()
                    .map(|access| serde_json::json!({
                        "id": access["id"],
                        "surface": access["surface"],
                        "method": access["method"],
                        "state": access["state"],
                    }))
                    .collect::<Vec<_>>()
            );
            Ok(Rendered::Json(shown))
        }
        Format::Text => {
            let none = say(locale, "cli-value-none", &[])?;
            let quota = record["quota_bytes"]
                .as_i64()
                .map(|bytes| bytes.to_string())
                .unwrap_or_else(|| none.clone());
            let expires = record["expires_at"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| none.clone());

            let mut lines = vec![
                field(locale, "cli-field-label", &text(record, "label"))?,
                field(locale, "cli-field-state", &text(record, "state"))?,
                field(locale, "cli-field-quota", &quota)?,
                field(locale, "cli-field-expires", &expires)?,
                field(locale, "cli-field-created", &text(record, "created_at"))?,
            ];
            for access in &rows {
                lines.push(field(
                    locale,
                    "cli-field-method",
                    &format!(
                        "{} {} {}",
                        text(access, "id"),
                        text(access, "method"),
                        text(access, "state")
                    ),
                )?);
            }
            Ok(Rendered::Text(lines))
        }
    }
}

fn list_clients(clients: &serde_json::Value, context: &Context) -> Outcome {
    let rows = clients.as_array().cloned().unwrap_or_default();
    match context.format {
        Format::Json => Ok(Rendered::Json(serde_json::json!(
            rows.iter()
                .map(|record| serde_json::json!({
                    "id": record["id"],
                    "label": record["label"],
                    "state": record["state"],
                }))
                .collect::<Vec<_>>()
        ))),
        Format::Text if rows.is_empty() => Ok(Rendered::line(say(
            context.locale,
            "cli-nothing-found",
            &[],
        )?)),
        Format::Text => Ok(Rendered::Text(
            rows.iter()
                .map(|record| format!("{} {}", text(record, "label"), text(record, "state")))
                .collect(),
        )),
    }
}

// ── accesses ─────────────────────────────────────────────────────────────

async fn access(command: AccessCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        AccessCommand::Add {
            client: client_label,
            node: node_label,
            method,
            tag: tag_name,
            quota,
            until,
        } => {
            let quota =
                parse_size(&quota).map_err(|error| Failure::Arguments(error.to_string()))?;
            let until =
                parse_until(&until).map_err(|error| Failure::Arguments(error.to_string()))?;
            let expires_at = until
                .map(ap_core::time::format_rfc3339)
                .transpose()
                .map_err(|error| Failure::Execution(error.to_string()))?;

            let client_record = client_by_label(&context, &client_label).await?;
            let node_record = node_by_label(&context, &node_label).await?;

            let tag_id = match tag_name {
                Some(name) => Some(tag_by_name(&context, &name).await?),
                None => None,
            };

            post(
                &context,
                "/v1/accesses",
                serde_json::json!({
                    "client_id": client_record["id"],
                    "node_id": node_record["id"],
                    "method": method,
                    "tag_id": tag_id,
                    "quota_bytes": quota,
                    "expires_at": expires_at,
                }),
            )
            .await?;

            Ok(Rendered::line(say(
                locale,
                "cli-access-created",
                &[("node", Argument::Text(&node_label))],
            )?))
        }
        AccessCommand::List { client: label } => {
            let record = client_by_label(&context, &label).await?;
            let id = text(&record, "id");
            let accesses = get(&context, &format!("/v1/clients/{id}/accesses")).await?;
            let rows = accesses.as_array().cloned().unwrap_or_default();

            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(
                    rows.iter()
                        .map(|access| serde_json::json!({
                            "id": access["id"],
                            "surface": access["surface"],
                            "method": access["method"],
                            "state": access["state"],
                        }))
                        .collect::<Vec<_>>()
                ))),
                Format::Text if rows.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    rows.iter()
                        .map(|access| {
                            format!(
                                "{} {} {}",
                                text(access, "id"),
                                text(access, "method"),
                                text(access, "state")
                            )
                        })
                        .collect(),
                )),
            }
        }
        AccessCommand::Link { id, host, yes } => {
            if !yes {
                // Refused here rather than at the panel: the acknowledgement is
                // about what is printed on this terminal.
                return Err(Failure::Arguments(say(locale, "cli-link-confirm", &[])?));
            }
            let answer = post(
                &context,
                &format!("/v1/accesses/{id}/link"),
                serde_json::json!({ "host": host, "acknowledged": true }),
            )
            .await?;
            // A masked or MTProto access has a link a client can be handed.
            // SOCKS5 and HTTP have no link form at all, so what comes back is
            // an address, a port and an account, and printing nothing for them
            // is how an operator ends up believing the access does not work.
            if let Some(link) = answer["link"].as_str() {
                return Ok(Rendered::line(link.to_owned()));
            }
            let host = text(&answer, "host");
            let user = text(&answer, "user");
            let password = text(&answer, "password");
            let port = answer["port"].as_i64().unwrap_or_default();
            if host.is_empty() || user.is_empty() || port == 0 {
                return Err(Failure::Execution(
                    "the panel returned neither a link nor an account".to_owned(),
                ));
            }
            Ok(Rendered::line(format!("{host} {port} {user} {password}")))
        }
        AccessCommand::Disable { id } => set_access_state(&context, id, "disabled").await,
        AccessCommand::Enable { id } => set_access_state(&context, id, "active").await,
        AccessCommand::Revoke { id } => set_access_state(&context, id, "revoked").await,
    }
}

async fn set_access_state(context: &Context, id: Uuid, state: &str) -> Outcome {
    post(
        context,
        &format!("/v1/accesses/{id}/state"),
        serde_json::json!({ "state": state }),
    )
    .await?;
    Ok(Rendered::line(say(
        context.locale,
        "cli-access-updated",
        &[],
    )?))
}

// ── tags ─────────────────────────────────────────────────────────────────

async fn tag_by_name(context: &Context, name: &str) -> Result<serde_json::Value, Failure> {
    let tags = get(context, "/v1/tags").await?;
    tags.as_array()
        .into_iter()
        .flatten()
        .find(|tag| tag["name"].as_str() == Some(name))
        .map(|tag| tag["id"].clone())
        .ok_or_else(|| {
            Failure::NotFound(
                say(
                    context.locale,
                    "cli-tag-not-found",
                    &[("label", Argument::Text(name))],
                )
                .unwrap_or_else(|_| name.to_owned()),
            )
        })
}

async fn tag(command: TagCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        TagCommand::Add { name } => {
            post(&context, "/v1/tags", serde_json::json!({ "name": name })).await?;
            Ok(Rendered::line(say(
                locale,
                "cli-tag-created",
                &[("name", Argument::Text(&name))],
            )?))
        }
        TagCommand::List => {
            let tags = get(&context, "/v1/tags").await?;
            let rows = tags.as_array().cloned().unwrap_or_default();
            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(rows))),
                Format::Text if rows.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    rows.iter().map(|tag| text(tag, "name")).collect(),
                )),
            }
        }
    }
}

// ── nodes ────────────────────────────────────────────────────────────────

async fn node(command: NodeCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        NodeCommand::Add {
            label,
            kind,
            domain,
        } => {
            let created = post(
                &context,
                "/v1/nodes",
                serde_json::json!({ "label": label, "kind": kind, "domain": domain }),
            )
            .await?;
            let id = text(&created, "id");

            // The code is shown here and nowhere again: the panel keeps only
            // its digest, so a second reading of the node does not carry it.
            let issued = post(
                &context,
                &format!("/v1/nodes/{id}/enrollment"),
                serde_json::json!({}),
            )
            .await?;
            let code = text(&issued, "code");
            // The panel calls it what it is: the fingerprint of the panel, not
            // of the node being added.
            let fingerprint = text(&issued, "panel_fingerprint");
            if code.is_empty() || fingerprint.is_empty() {
                // A line telling an operator to pin nothing is worse than no
                // line at all: it would be run, and the node would trust
                // whatever answered.
                return Err(Failure::Execution(
                    "the panel issued an enrolment without a code or a fingerprint".to_owned(),
                ));
            }
            let command = format!(
                "anyproxy-agent enroll --panel <panel-host>:8443 --code {code} \
                 --fingerprint {fingerprint}"
            );

            Ok(Rendered::Text(vec![
                say(
                    locale,
                    "cli-node-created",
                    &[("label", Argument::Text(&label))],
                )?,
                say(
                    locale,
                    "cli-enrollment-code",
                    &[("code", Argument::Text(&code))],
                )?,
                say(
                    locale,
                    "cli-enrollment-fingerprint",
                    &[("fingerprint", Argument::Text(&fingerprint))],
                )?,
                say(
                    locale,
                    "cli-enrollment-command",
                    &[("command", Argument::Text(&command))],
                )?,
            ]))
        }
        NodeCommand::List => {
            let nodes = get(&context, "/v1/nodes").await?;
            let rows = nodes.as_array().cloned().unwrap_or_default();
            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(rows))),
                Format::Text if rows.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    rows.iter()
                        .map(|node| {
                            format!(
                                "{} {} {}",
                                text(node, "label"),
                                text(node, "kind"),
                                text(node, "state")
                            )
                        })
                        .collect(),
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_reply(status: u16, code: &str) -> Reply {
        Reply {
            status,
            body: format!(r#"{{"error":{{"code":"{code}","message":"x"}}}}"#),
        }
    }

    #[test]
    fn each_status_becomes_the_exit_code_the_shell_acts_on() {
        assert!(matches!(
            refused(&a_reply(401, "unauthenticated"), Locale::En),
            Failure::Execution(_)
        ));
        assert!(matches!(
            refused(&a_reply(403, "forbidden"), Locale::En),
            Failure::Execution(_)
        ));
        assert!(matches!(
            refused(&a_reply(404, "not_found"), Locale::En),
            Failure::NotFound(_)
        ));
        for status in [400, 422, 429] {
            assert!(
                matches!(
                    refused(&a_reply(status, "method_not_served"), Locale::En),
                    Failure::Arguments(_)
                ),
                "{status} did not become an argument error"
            );
        }
    }

    #[test]
    fn a_known_code_is_said_in_the_operators_language() {
        let english = refused(&a_reply(404, "not_found"), Locale::En);
        let russian = refused(&a_reply(404, "not_found"), Locale::Ru);
        assert_ne!(english, russian, "both languages said the same thing");

        let Failure::NotFound(message) = english else {
            panic!("expected a not-found failure");
        };
        assert!(!message.contains("not_found"), "the code was printed raw");
    }

    #[test]
    fn a_code_nobody_has_a_sentence_for_is_not_printed_raw() {
        let Failure::Execution(message) = refused(&a_reply(500, "some_future_code"), Locale::En)
        else {
            panic!("expected an execution failure");
        };
        // The code appears inside a sentence rather than as the whole message.
        assert!(message.len() > "some_future_code".len());
        assert!(message.contains("some_future_code"));
    }

    #[test]
    fn the_panels_own_wording_never_reaches_the_operator() {
        let reply = Reply {
            status: 404,
            body: r#"{"error":{"code":"not_found","message":"такого нет"}}"#.to_owned(),
        };
        let Failure::NotFound(message) = refused(&reply, Locale::En) else {
            panic!("expected a not-found failure");
        };
        assert!(!message.contains("такого нет"));
    }
}
