use std::env;
use std::io;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reverse_tunnel::dialog::Dialog;
use reverse_tunnel::download::tools;
use reverse_tunnel::install::{self, InstallOpts};
use reverse_tunnel::logs;
use reverse_tunnel::ops;
use reverse_tunnel::paths::Paths;
use reverse_tunnel::report::report;
use reverse_tunnel::service;
use reverse_tunnel::supervisor;
use reverse_tunnel::upgrade;

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
    #[command(hide = true)]
    Run {
        /// Render the configuration, have frpc verify it, and exit.
        #[arg(long)]
        check: bool,
    },
    /// Installs the service and starts it, or restarts it if anything `install` writes changed. Needs root.
    ///
    /// On a terminal it asks for the host name and the join code, unless they are given or already known; without one
    /// a missing value is an error.
    ///
    /// A hand edit of config.yaml is not noticed; apply it with `restart`.
    Install {
        /// The name for a new config.yaml, which is otherwise asked for, with this machine's name as the default. With
        /// an existing one, a different name is an error.
        #[arg(long)]
        host: Option<String>,
        /// The bridge's join code; asked for if needed and not given. Without a terminal to ask on, it is required
        /// then.
        #[arg(long)]
        join: Option<String>,
    },
    /// Replaces this host's binary with the latest release's, or with `--from`, and restarts the service. Needs root.
    ///
    /// The release is staged in the bin directory as `upgrade-<...>`. A successful upgrade's download is removed by the
    /// `install` it runs, a failed one by `upgrade`. `install` removes its own check copy, also `upgrade-<...>`, and
    /// sweeps any left behind. On Windows, builds that still run are renamed to `.reverse-tunnel.*` beside the bin
    /// directory and deleted by the next `install`.
    Upgrade {
        /// Install this binary instead of downloading one.
        #[arg(long)]
        from: Option<std::path::PathBuf>,
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
    /// Checks config.yaml, then restarts the service to apply it; works over the tunnel. Needs root.
    Restart,
    /// Shows the service's state, this host's name and token hash (what `ctl add` takes), the bridge, and the end of
    /// frpc's log.
    Status,
    /// Shows frpc's log, which every local account may read.
    Logs {
        /// Show only the last N lines.
        #[arg(short = 'n', long = "lines", value_name = "N")]
        lines: Option<usize>,
        /// Keep running and show lines as they are appended, until interrupted. Starts with the last 10 lines unless
        /// -n says otherwise, and waits for the log if there is none yet.
        #[arg(short, long)]
        follow: bool,
    },
}

/// std prints the error, ignoring a closed stderr; it is handed the report, as std alone would drop goetia's details.
fn main() -> Result<ExitCode> {
    // SCM starts the installed binary as the service's host (see `service::registering_manager`): not a subcommand,
    // before clap.
    if cfg!(windows)
        && env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == service::SERVICE_HOST_ARG)
    {
        goetia::shim::main()
    }
    run().map_err(|err| anyhow::anyhow!(report(&err)))
}

fn run() -> Result<ExitCode> {
    let command = Cli::parse().command;
    let paths = Paths::system()?;
    match command {
        Command::Run { check } => supervisor::run(&paths, &tools(&paths), check),
        Command::Install { host, join } => {
            require_root()?;
            install::install(InstallOpts { host, join, paths }, &mut Dialog::terminal())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Uninstall { finish } => {
            require_root()?;
            if finish {
                install::finish_uninstall(&paths)?;
            } else {
                install::uninstall(&paths)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Upgrade { from } => {
            require_root()?;
            upgrade::upgrade(&paths, from.as_deref(), &mut io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Start => {
            require_root()?;
            ops::start(&*service::manager(&paths)?)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Stop => {
            require_root()?;
            ops::stop(&*service::manager(&paths)?)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Restart => {
            require_root()?;
            ops::check_and_restart(&*service::manager(&paths)?, &paths, &mut io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Status => {
            ops::status(&*service::manager(&paths)?, &paths, &mut io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Logs { lines, follow } => {
            logs::show(&paths.frpc_log(), lines, follow, &mut io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
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
