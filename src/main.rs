use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reverse_tunnel::download::tools;
use reverse_tunnel::paths::Paths;
use reverse_tunnel::supervisor;

/// Publishes this machine's services through the reverse-tunnel bridge.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The service's entry point; not for humans.
    Run {
        /// Render the configuration, have frpc verify it, and exit.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Run { check } => {
            let paths = Paths::system()?;
            supervisor::run(&paths, &tools(&paths), check)
        }
    }
}
