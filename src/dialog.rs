//! What `install` asks the person at the terminal, line by line, and what it prints while it does.
//!
//! A value given as a flag is never asked for. Without a terminal on stdin nothing is asked: a missing value fails,
//! naming its flag, so that a script does not wait for input that will not come.

use std::io::{self, BufRead, IsTerminal, Stdin, StdinLock, Stdout, Write};

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::config::{Config, valid_label};
use crate::join::{self, JoinInfo};
use crate::paths::Paths;

pub struct Dialog<I, O> {
    input: I,
    out: O,
    /// Whether the input is a person at a terminal, who can be asked.
    interactive: bool,
}

impl Dialog<StdinLock<'static>, Stdout> {
    /// Asks on stdout and reads stdin.
    pub fn terminal() -> Self {
        let stdin: Stdin = io::stdin();
        Dialog {
            interactive: stdin.is_terminal(),
            input: stdin.lock(),
            out: io::stdout(),
        }
    }
}

impl<I: BufRead, O: Write> Dialog<I, O> {
    /// Says what is being set up and where its config is saved.
    pub fn intro(&mut self, paths: &Paths) -> Result<()> {
        writeln!(self.out, "Setting up a system-wide reverse tunnel service.")?;
        writeln!(self.out, "  Config is saved to: {}", paths.config_file().display())?;
        Ok(())
    }

    /// The name for a new `config.yaml`, or none when one exists, whose host is then shown. A name given as `explicit`
    /// is shown and not asked for; with an existing config it must be that config's name. Otherwise the machine's name
    /// is offered.
    pub fn host(&mut self, paths: &Paths, explicit: Option<&str>) -> Result<Option<String>> {
        let config = paths.config_file();
        let explicit = explicit.map(explicit_host).transpose()?;
        if config.try_exists()? {
            let current = Config::load(&config).map(|config| config.host);
            if let Some(asked) = explicit {
                let current = current.as_ref().map_err(|err| anyhow!("{err:#}"))?;
                ensure!(
                    asked == current,
                    "--host {asked:?} differs from this host's name {current:?} in {}: `install` does not rename a \n                     host. To rename it, uninstall it and install it again with --host {asked}",
                    config.display()
                );
            }
            // A config that cannot be read is reported by the checks `install` runs next, as the service account.
            if let Ok(current) = current {
                writeln!(self.out, "Hostname: {current}")?;
            }
            return Ok(None);
        }
        let host = match explicit {
            Some(host) => {
                writeln!(self.out, "Hostname: {host}")?;
                host.to_string()
            }
            None => {
                self.ensure_interactive("a host name", "--host NAME")?;
                self.ask_host(machine_host(&gethostname::gethostname().to_string_lossy()).as_deref())?
            }
        };
        Ok(Some(host))
    }

    /// The join code given as `explicit` or typed, or none when `config.yaml` and the bridge's files already exist.
    pub fn join(&mut self, paths: &Paths, explicit: Option<&str>) -> Result<Option<JoinInfo>> {
        if let Some(code) = explicit {
            return join::decode(code).map(Some);
        }
        if !needs_join(paths)? {
            return Ok(None);
        }
        self.ensure_interactive("a join code", "--join CODE")?;
        self.ask_join().map(Some)
    }

    fn ensure_interactive(&self, what: &str, flag: &str) -> Result<()> {
        ensure!(
            self.interactive,
            "{what} is needed, and stdin is not a terminal to ask for it: pass {flag}"
        );
        Ok(())
    }

    /// Asks until the answer is a valid host name; Enter takes `default`. The end of the input gives up.
    fn ask_host(&mut self, default: Option<&str>) -> Result<String> {
        loop {
            match default {
                Some(default) => write!(self.out, "Hostname [{default}]: ")?,
                None => write!(self.out, "Hostname: ")?,
            }
            self.out.flush()?;
            let mut line = String::new();
            ensure!(
                self.input.read_line(&mut line)? > 0,
                "no host name was entered; pass --host NAME"
            );
            let answer = line.trim();
            let answer = if answer.is_empty() {
                default.unwrap_or("")
            } else {
                answer
            };
            if valid_label(answer) {
                return Ok(answer.to_string());
            }
            writeln!(
                self.out,
                "  A host name is one DNS label: lowercase letters, digits and hyphens."
            )?;
        }
    }

    /// Reads lines until they form a join code, which may be wrapped over several. A blank line, or the end of the
    /// input, gives up.
    fn ask_join(&mut self) -> Result<JoinInfo> {
        write!(
            self.out,
            "Join code (run `uv run ctl join-code` on the bridge; an empty line gives up): "
        )?;
        self.out.flush()?;
        let mut code = String::new();
        loop {
            let mut line = String::new();
            self.input.read_line(&mut line)?;
            code += &line;
            if line.trim().is_empty() {
                return join::decode(&code).context("no complete join code was entered");
            }
            if let Ok(info) = join::decode(&code) {
                return Ok(info);
            }
        }
    }
}

/// A host name given with `--host`.
fn explicit_host(host: &str) -> Result<&str> {
    if !valid_label(host) {
        bail!("--host {host:?} is not a valid name: one DNS label of lowercase letters, digits and hyphens");
    }
    Ok(host)
}

/// A machine name as a host name: lowercased, and it must then be one valid DNS label.
fn machine_host(machine: &str) -> Option<String> {
    let host = machine.to_lowercase();
    valid_label(&host).then_some(host)
}

/// Whether a join code is needed: some file it provides is missing.
fn needs_join(paths: &Paths) -> Result<bool> {
    let files = [paths.config_file(), paths.bridge_pem(), paths.bridge_token()];
    for file in files {
        if !file.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "dialog_tests.rs"]
mod tests;
