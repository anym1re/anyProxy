//! Command line client for the panel.
//!
//! Every line it prints comes from a message catalogue. Reading commands also
//! speak JSON, which never carries a secret: a link is the one way a secret
//! leaves, and that path is recorded in the audit log.

mod api;
mod args;
mod output;
mod run;

use clap::{Parser, Subcommand};

/// Exit codes the shell can act on.
mod code {
    /// The command did what was asked.
    pub const SUCCESS: i32 = 0;
    /// The command was understood but could not be carried out.
    pub const FAILURE: i32 = 1;
    /// The arguments were not accepted.
    pub const ARGUMENTS: i32 = 2;
    /// What was asked for does not exist.
    pub const NOT_FOUND: i32 = 3;
}

#[derive(Parser)]
#[command(name = "anyproxy", version, about = None, long_about = None)]
struct Cli {
    /// Language of the output.
    #[arg(long, global = true, env = "ANYPROXY_LOCALE", default_value = "en")]
    locale: String,

    /// Print machine-readable output.
    #[arg(long, global = true, default_value = "text")]
    format: output::Format,

    /// Address of the panel, host and port.
    #[arg(long, global = true, env = "ANYPROXY_PANEL")]
    panel: Option<String>,

    /// Session token, when it is not being read from the token file.
    #[arg(long, global = true, env = "ANYPROXY_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Signs in and keeps the session token.
    Login,
    /// Forgets the session token.
    Logout,
    /// People the panel accounts for.
    #[command(subcommand)]
    Client(run::ClientCommand),
    /// Connections issued to a client.
    #[command(subcommand)]
    Access(run::AccessCommand),
    /// Groups an access can be selected and withdrawn by.
    #[command(subcommand)]
    Tag(run::TagCommand),
    /// Servers that carry traffic.
    #[command(subcommand)]
    Node(run::NodeCommand),
}

fn main() {
    let cli = Cli::parse();
    let locale = ap_core::Locale::from_code(&cli.locale);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            output::fail(&error.to_string());
            std::process::exit(code::FAILURE);
        }
    };

    let token_path = api::token_path();
    let token = match cli.token {
        Some(token) => Some(token),
        None => match api::read_token(&token_path) {
            Ok(token) => token,
            Err(reason) => {
                output::fail(&reason);
                std::process::exit(code::FAILURE);
            }
        },
    };

    let Some(panel) = cli.panel else {
        let message = ap_core::i18n::message(locale, "cli-panel-required")
            .unwrap_or_else(|_| "set ANYPROXY_PANEL or pass --panel".to_owned());
        output::fail(&message);
        std::process::exit(code::ARGUMENTS);
    };

    let outcome = runtime.block_on(run::dispatch(
        cli.command,
        run::Context {
            locale,
            format: cli.format,
            api: api::Api::new(panel, token),
            token_path,
        },
    ));

    match outcome {
        Ok(rendered) => {
            output::emit(&rendered);
            std::process::exit(code::SUCCESS);
        }
        Err(run::Failure::Arguments(message)) => {
            output::fail(&message);
            std::process::exit(code::ARGUMENTS);
        }
        Err(run::Failure::NotFound(message)) => {
            output::fail(&message);
            std::process::exit(code::NOT_FOUND);
        }
        Err(run::Failure::Execution(message)) => {
            output::fail(&message);
            std::process::exit(code::FAILURE);
        }
    }
}
