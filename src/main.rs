use std::io;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reverse_tunnel::download::tools;
#[cfg(unix)]
use reverse_tunnel::install::{self, InstallOpts};
use reverse_tunnel::ops;
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
    /// Installs the service and starts it, or restarts it if anything it reads changed. Needs root.
    Install {
        /// The name for a new config.yaml; default: this machine's name. Ignored when config.yaml exists.
        #[arg(long)]
        host: Option<String>,
        /// The bridge's join code; asked for if missing and needed.
        #[arg(long)]
        join: Option<String>,
    },
    /// Stops the service and removes it, its files and its account. Needs root.
    Uninstall {
        /// What `uninstall` runs in the background.
        #[arg(long, hide = true)]
        finish: bool,
    },
    /// Starts the service. Needs root.
    Start,
    /// Stops the service. It starts again at boot if it is enabled. Needs root.
    Stop,
    /// Shows the service's state, the bridge and the last login result.
    Status,
    /// Shows the service's logs.
    Logs {
        /// Keep showing what the logs gain, until interrupted.
        #[arg(short, long)]
        follow: bool,
    },
}

fn main() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Run { check } => {
            let paths = Paths::system()?;
            supervisor::run(&paths, &tools(&paths), check)
        }
        #[cfg(unix)]
        Command::Install { host, join } => {
            require_root()?;
            install::install(InstallOpts {
                host,
                join,
                paths: Paths::system()?,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(unix)]
        Command::Uninstall { finish } => {
            require_root()?;
            let paths = Paths::system()?;
            if finish {
                install::finish_uninstall(&paths)?;
            } else {
                install::uninstall(&paths)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Start => {
            require_root()?;
            ops::start(&*goetia::manager::native()?, &Paths::system()?)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Stop => {
            require_root()?;
            ops::stop(&*goetia::manager::native()?, &Paths::system()?)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Status => {
            ops::status(
                &*goetia::manager::native()?,
                &Paths::system()?,
                &mut io::stdout().lock(),
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Logs { follow } => {
            ops::logs(&Paths::system()?, follow, &mut io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::Install { .. } | Command::Uninstall { .. } => {
            anyhow::bail!("install and uninstall are not available on Windows yet")
        }
    }
}

fn require_root() -> Result<()> {
    anyhow::ensure!(
        cosca::elevation::is_elevated(),
        "this needs {}",
        if cfg!(windows) {
            "an elevated prompt"
        } else {
            "root: run it with sudo"
        }
    );
    Ok(())
}
