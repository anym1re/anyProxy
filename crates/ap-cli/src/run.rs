use std::path::PathBuf;

use ap_core::i18n::{Argument, message, message_with};
use ap_core::time::format_rfc3339;
use ap_core::{
    Access, AccessCommon, AccessState, AnyAccess, Client, ClientState, Credential, Domain,
    KeyStore, Label, Locale, Node, NodeKind, NodeKindTag, Open, OpenMethod, Stealth, StealthMethod,
    Tag, TagName,
};
use ap_store::{AccessRepo, AuditRepo, ClientRepo, NodeRepo, TagRepo};
use clap::Subcommand;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

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
    /// Where the panel keeps its data.
    pub database_url: Option<String>,
    /// File holding the key that seals secrets.
    pub key_file: Option<PathBuf>,
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
    /// Registers a node.
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
        crate::Command::Client(command) => client(command, context).await,
        crate::Command::Access(command) => access(command, context).await,
        crate::Command::Tag(command) => tag(command, context).await,
        crate::Command::Node(command) => node(command, context).await,
    }
}

async fn pool(context: &Context) -> Result<PgPool, Failure> {
    let url = context
        .database_url
        .as_deref()
        .ok_or_else(|| Failure::Arguments("set DATABASE_URL or pass --database-url".to_owned()))?;
    let pool = ap_store::connect(url, 5)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?;
    ap_store::migrate(&pool)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?;
    Ok(pool)
}

fn key(context: &Context) -> Result<KeyStore, Failure> {
    match context.key_file.as_deref() {
        Some(path) => {
            KeyStore::from_file(path).map_err(|error| Failure::Arguments(error.to_string()))
        }
        None => Err(Failure::Arguments(
            "set ANYPROXY_KEY_FILE or pass --key-file".to_owned(),
        )),
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

fn label(text: &str) -> Result<Label, Failure> {
    Label::try_from(text).map_err(|error| Failure::Arguments(error.to_string()))
}

fn moment(value: Option<OffsetDateTime>) -> Result<Option<String>, Failure> {
    value
        .map(|at| format_rfc3339(at).map_err(|error| Failure::Execution(error.to_string())))
        .transpose()
}

async fn client(command: ClientCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        ClientCommand::Add {
            label: text,
            quota,
            until,
        } => {
            let label = label(&text)?;
            let quota =
                parse_size(&quota).map_err(|error| Failure::Arguments(error.to_string()))?;
            let until =
                parse_until(&until).map_err(|error| Failure::Arguments(error.to_string()))?;

            let mut record = Client::new(label.clone(), OffsetDateTime::now_utc());
            if let Some(bytes) = quota {
                record = record
                    .with_quota(bytes)
                    .map_err(|error| Failure::Arguments(error.to_string()))?;
            }
            if let Some(at) = until {
                record = record.with_expiry(at);
            }

            let pool = pool(&context).await?;
            ClientRepo::insert(&pool, &record, None)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;

            Ok(Rendered::line(say(
                locale,
                "cli-client-created",
                &[("label", Argument::Text(label.as_str()))],
            )?))
        }
        ClientCommand::Show { label: text } => {
            let label = label(&text)?;
            let pool = pool(&context).await?;
            let record = ClientRepo::by_label(&pool, &label)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(
                        say(
                            locale,
                            "cli-client-not-found",
                            &[("label", Argument::Text(label.as_str()))],
                        )
                        .unwrap_or_else(|_| text.clone()),
                    )
                })?;
            let accesses = AccessRepo::by_client(&pool, record.id())
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            show_client(&record, &accesses, &context)
        }
        ClientCommand::List => {
            let pool = pool(&context).await?;
            let clients = ClientRepo::list(&pool, 200)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            list_clients(&clients, &context)
        }
        ClientCommand::Suspend { label: text } => {
            set_client_state(&text, ClientState::Suspended, &context).await
        }
        ClientCommand::Resume { label: text } => {
            set_client_state(&text, ClientState::Active, &context).await
        }
        ClientCommand::Archive { label: text } => {
            set_client_state(&text, ClientState::Archived, &context).await
        }
    }
}

async fn set_client_state(text: &str, state: ClientState, context: &Context) -> Outcome {
    let label = label(text)?;
    let pool = pool(context).await?;
    let record = ClientRepo::by_label(&pool, &label)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?
        .ok_or_else(|| {
            Failure::NotFound(
                say(
                    context.locale,
                    "cli-client-not-found",
                    &[("label", Argument::Text(label.as_str()))],
                )
                .unwrap_or_else(|_| text.to_owned()),
            )
        })?;
    ClientRepo::set_state(&pool, record.id(), state)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?;
    Ok(Rendered::Silent)
}

fn show_client(record: &Client, accesses: &[AnyAccess], context: &Context) -> Outcome {
    let locale = context.locale;
    let expires = moment(record.expires_at())?;
    let created = moment(Some(record.created_at()))?.unwrap_or_default();

    match context.format {
        Format::Json => Ok(Rendered::Json(serde_json::json!({
            "id": record.id(),
            "label": record.label().as_str(),
            "state": record.state().as_stored(),
            "quota_bytes": record.quota_bytes(),
            "expires_at": expires,
            "created_at": created,
            "accesses": accesses
                .iter()
                .map(|access| serde_json::json!({
                    "id": access.common().id(),
                    "surface": access.surface_tag(),
                    "method": method_name(access),
                    "state": access.common().state().as_stored(),
                }))
                .collect::<Vec<_>>(),
        }))),
        Format::Text => {
            let none = say(locale, "cli-value-none", &[])?;
            let mut lines = vec![
                field(locale, "cli-field-label", record.label().as_str())?,
                field(locale, "cli-field-state", record.state().as_stored())?,
                field(
                    locale,
                    "cli-field-quota",
                    &record
                        .quota_bytes()
                        .map(|bytes| bytes.to_string())
                        .unwrap_or_else(|| none.clone()),
                )?,
                field(
                    locale,
                    "cli-field-expires",
                    expires.as_deref().unwrap_or(&none),
                )?,
                field(locale, "cli-field-created", &created)?,
            ];
            for access in accesses {
                lines.push(field(
                    locale,
                    "cli-field-method",
                    &format!(
                        "{} {} {}",
                        access.common().id(),
                        method_name(access),
                        access.common().state().as_stored()
                    ),
                )?);
            }
            Ok(Rendered::Text(lines))
        }
    }
}

fn list_clients(clients: &[Client], context: &Context) -> Outcome {
    match context.format {
        Format::Json => Ok(Rendered::Json(serde_json::json!(
            clients
                .iter()
                .map(|record| serde_json::json!({
                    "id": record.id(),
                    "label": record.label().as_str(),
                    "state": record.state().as_stored(),
                }))
                .collect::<Vec<_>>()
        ))),
        Format::Text if clients.is_empty() => Ok(Rendered::line(say(
            context.locale,
            "cli-nothing-found",
            &[],
        )?)),
        Format::Text => Ok(Rendered::Text(
            clients
                .iter()
                .map(|record| format!("{} {}", record.label().as_str(), record.state().as_stored()))
                .collect(),
        )),
    }
}

fn field(locale: Locale, key: &str, value: &str) -> Result<String, Failure> {
    Ok(format!("{}: {value}", say(locale, key, &[])?))
}

fn method_name(access: &AnyAccess) -> &'static str {
    match access {
        AnyAccess::Stealth(access) => access.method().as_stored(),
        AnyAccess::Open(access) => access.method().as_stored(),
    }
}

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
            let client_label = label(&client_label)?;
            let node_label = label(&node_label)?;
            let quota =
                parse_size(&quota).map_err(|error| Failure::Arguments(error.to_string()))?;
            let until =
                parse_until(&until).map_err(|error| Failure::Arguments(error.to_string()))?;

            let pool = pool(&context).await?;
            let key = key(&context)?;

            let client_record = ClientRepo::by_label(&pool, &client_label)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(
                        say(
                            locale,
                            "cli-client-not-found",
                            &[("label", Argument::Text(client_label.as_str()))],
                        )
                        .unwrap_or_default(),
                    )
                })?;
            let node_record = NodeRepo::by_label(&pool, &node_label)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(
                        say(
                            locale,
                            "cli-node-not-found",
                            &[("label", Argument::Text(node_label.as_str()))],
                        )
                        .unwrap_or_default(),
                    )
                })?;

            let tag_id = match tag_name {
                Some(name) => {
                    let name = TagName::try_from(name.as_str())
                        .map_err(|error| Failure::Arguments(error.to_string()))?;
                    let record = TagRepo::by_name(&pool, &name)
                        .await
                        .map_err(|error| Failure::Execution(error.to_string()))?
                        .ok_or_else(|| {
                            Failure::NotFound(
                                say(
                                    locale,
                                    "cli-tag-not-found",
                                    &[("label", Argument::Text(name.as_str()))],
                                )
                                .unwrap_or_default(),
                            )
                        })?;
                    Some(record.id())
                }
                None => None,
            };

            let mut common = AccessCommon::new(
                client_record.id(),
                node_record.id(),
                OffsetDateTime::now_utc(),
            );
            if let Some(id) = tag_id {
                common = common.with_tag(id);
            }
            if let Some(bytes) = quota {
                common = common
                    .with_quota(bytes)
                    .map_err(|error| Failure::Arguments(error.to_string()))?;
            }
            if let Some(at) = until {
                common = common.with_expiry(at);
            }

            let built = build_access(node_record.kind().tag(), &method, common, locale)?;
            let credential = match &built {
                AnyAccess::Stealth(_) => Credential::generate_secret(),
                AnyAccess::Open(access) => match access.method() {
                    OpenMethod::Mtproto => Credential::generate_secret(),
                    _ => Credential::generate_login(client_label.as_str().to_owned())
                        .map_err(|error| Failure::Arguments(error.to_string()))?,
                },
            };

            AccessRepo::insert(&pool, &built, &credential, &key)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;

            Ok(Rendered::line(say(
                locale,
                "cli-access-created",
                &[("node", Argument::Text(node_label.as_str()))],
            )?))
        }
        AccessCommand::List { client: text } => {
            let label = label(&text)?;
            let pool = pool(&context).await?;
            let record = ClientRepo::by_label(&pool, &label)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(
                        say(
                            locale,
                            "cli-client-not-found",
                            &[("label", Argument::Text(label.as_str()))],
                        )
                        .unwrap_or_default(),
                    )
                })?;
            let accesses = AccessRepo::by_client(&pool, record.id())
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(
                    accesses
                        .iter()
                        .map(|access| serde_json::json!({
                            "id": access.common().id(),
                            "surface": access.surface_tag(),
                            "method": method_name(access),
                            "state": access.common().state().as_stored(),
                        }))
                        .collect::<Vec<_>>()
                ))),
                Format::Text if accesses.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    accesses
                        .iter()
                        .map(|access| {
                            format!(
                                "{} {} {}",
                                access.common().id(),
                                method_name(access),
                                access.common().state().as_stored()
                            )
                        })
                        .collect(),
                )),
            }
        }
        AccessCommand::Link { id, host, yes } => {
            if !yes {
                return Err(Failure::Arguments(say(locale, "cli-link-confirm", &[])?));
            }
            let pool = pool(&context).await?;
            let key = key(&context)?;
            let access = AccessRepo::by_id(&pool, id)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(say(locale, "cli-access-not-found", &[]).unwrap_or_default())
                })?;
            let credential = AccessRepo::credential(&pool, id, &key)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?
                .ok_or_else(|| {
                    Failure::NotFound(say(locale, "cli-access-not-found", &[]).unwrap_or_default())
                })?;

            let link = render_link(&pool, &access, &credential, &host).await?;

            AuditRepo::record(
                &pool,
                None,
                "access.link.rendered",
                Some(&id.to_string()),
                OffsetDateTime::now_utc(),
                serde_json::json!({ "host": host }),
            )
            .await
            .map_err(|error| Failure::Execution(error.to_string()))?;

            Ok(Rendered::line(link))
        }
        AccessCommand::Disable { id } => {
            set_access_state(id, AccessState::Disabled, &context).await
        }
        AccessCommand::Enable { id } => set_access_state(id, AccessState::Active, &context).await,
        AccessCommand::Revoke { id } => set_access_state(id, AccessState::Revoked, &context).await,
    }
}

async fn set_access_state(id: Uuid, state: AccessState, context: &Context) -> Outcome {
    let pool = pool(context).await?;
    let changed = AccessRepo::set_state(&pool, id, state)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?;
    if changed {
        Ok(Rendered::line(say(
            context.locale,
            "cli-access-updated",
            &[],
        )?))
    } else {
        Err(Failure::NotFound(say(
            context.locale,
            "cli-access-not-found",
            &[],
        )?))
    }
}

fn build_access(
    kind: NodeKindTag,
    method: &str,
    common: AccessCommon,
    locale: Locale,
) -> Result<AnyAccess, Failure> {
    let refuse = || -> Failure {
        Failure::Arguments(
            say(
                locale,
                "cli-method-not-served",
                &[
                    ("kind", Argument::Text(kind.as_stored())),
                    ("method", Argument::Text(method)),
                ],
            )
            .unwrap_or_default(),
        )
    };

    match kind {
        NodeKindTag::Stealth => {
            let method = StealthMethod::from_stored(method).map_err(|_| refuse())?;
            Ok(AnyAccess::Stealth(Access::<Stealth>::new(common, method)))
        }
        NodeKindTag::Open => {
            let method = OpenMethod::from_stored(method).map_err(|_| refuse())?;
            Ok(AnyAccess::Open(Access::<Open>::new(common, method)))
        }
    }
}

async fn render_link(
    pool: &PgPool,
    access: &AnyAccess,
    credential: &Credential,
    host: &str,
) -> Result<String, Failure> {
    let node = node_of(pool, access.common().node_id()).await?;
    let secret = match credential {
        Credential::Secret(secret) => secret,
        Credential::Login { user, pass } => {
            return Ok(format!("{host} {user} {pass}"));
        }
    };

    match access {
        AnyAccess::Stealth(access) => {
            let domain = node
                .kind()
                .domain()
                .ok_or_else(|| Failure::Execution("node has no domain".to_owned()))?;
            ap_core::stealth_link(*access.method(), host, domain, secret)
                .map_err(|error| Failure::Execution(error.to_string()))
        }
        AnyAccess::Open(_) => ap_core::mtproto_link(host, 8443, secret)
            .map_err(|error| Failure::Execution(error.to_string())),
    }
}

async fn node_of(pool: &PgPool, id: Uuid) -> Result<Node, Failure> {
    NodeRepo::list(pool)
        .await
        .map_err(|error| Failure::Execution(error.to_string()))?
        .into_iter()
        .find(|node| node.id() == id)
        .ok_or_else(|| Failure::NotFound("node".to_owned()))
}

async fn tag(command: TagCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        TagCommand::Add { name } => {
            let name = TagName::try_from(name.as_str())
                .map_err(|error| Failure::Arguments(error.to_string()))?;
            let pool = pool(&context).await?;
            TagRepo::insert(&pool, &Tag::new(name.clone()))
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            Ok(Rendered::line(say(
                locale,
                "cli-tag-created",
                &[("name", Argument::Text(name.as_str()))],
            )?))
        }
        TagCommand::List => {
            let pool = pool(&context).await?;
            let tags = TagRepo::list(&pool)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(
                    tags.iter()
                        .map(|tag| serde_json::json!({
                            "id": tag.id(),
                            "name": tag.name().as_str(),
                        }))
                        .collect::<Vec<_>>()
                ))),
                Format::Text if tags.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    tags.iter().map(|tag| tag.name().to_string()).collect(),
                )),
            }
        }
    }
}

async fn node(command: NodeCommand, context: Context) -> Outcome {
    let locale = context.locale;
    match command {
        NodeCommand::Add {
            label: text,
            kind,
            domain,
        } => {
            let label = label(&text)?;
            let tag = NodeKindTag::from_stored(&kind)
                .map_err(|error| Failure::Arguments(error.to_string()))?;
            let domain = domain
                .map(|text| Domain::try_from(text.as_str()))
                .transpose()
                .map_err(|error| Failure::Arguments(error.to_string()))?;
            let kind = NodeKind::from_parts(tag, domain)
                .map_err(|error| Failure::Arguments(error.to_string()))?;

            let pool = pool(&context).await?;
            NodeRepo::insert(
                &pool,
                &Node::new(label.clone(), kind, OffsetDateTime::now_utc()),
            )
            .await
            .map_err(|error| Failure::Execution(error.to_string()))?;
            Ok(Rendered::line(say(
                locale,
                "cli-node-created",
                &[("label", Argument::Text(label.as_str()))],
            )?))
        }
        NodeCommand::List => {
            let pool = pool(&context).await?;
            let nodes = NodeRepo::list(&pool)
                .await
                .map_err(|error| Failure::Execution(error.to_string()))?;
            match context.format {
                Format::Json => Ok(Rendered::Json(serde_json::json!(
                    nodes
                        .iter()
                        .map(|node| serde_json::json!({
                            "id": node.id(),
                            "label": node.label().as_str(),
                            "kind": node.kind().tag().as_stored(),
                            "domain": node.kind().domain().map(Domain::as_str),
                            "state": node.state().as_stored(),
                        }))
                        .collect::<Vec<_>>()
                ))),
                Format::Text if nodes.is_empty() => {
                    Ok(Rendered::line(say(locale, "cli-nothing-found", &[])?))
                }
                Format::Text => Ok(Rendered::Text(
                    nodes
                        .iter()
                        .map(|node| {
                            format!(
                                "{} {} {}",
                                node.label().as_str(),
                                node.kind().tag().as_stored(),
                                node.state().as_stored()
                            )
                        })
                        .collect(),
                )),
            }
        }
    }
}
