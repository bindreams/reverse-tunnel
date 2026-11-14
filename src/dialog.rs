//! What `install` asks the person at the terminal, line by line, and what it prints while it does.
//!
//! A value given as a flag is never asked for. Without a terminal on stdin nothing is asked: a missing value fails,
//! naming its flag, so that a script does not wait for input that will not come.

use std::io::{self, BufRead, IsTerminal, Stderr, Stdin, StdinLock, Stdout, Write};

use anyhow::{Context, Result, anyhow, ensure};

use crate::config::{Config, valid_label};
use crate::join::{self, JoinInfo};
use crate::paths::Paths;

/// What a host name is, as the person is told when theirs is not one.
const HOST_RULE: &str = "lowercase letters, digits and hyphens, not starting or ending with a hyphen, with no `--` \
                         as its third and fourth characters, at most 63 characters";

pub struct Dialog<I, O, P> {
    input: I,
    /// The results, which a script may read: stdout.
    out: O,
    /// The questions: stderr, so that they do not mix into the results, and a script's stderr holds only warnings.
    prompts: P,
    /// Whether the input is a person at a terminal, who can be asked.
    interactive: bool,
}

impl Dialog<StdinLock<'static>, Stdout, Stderr> {
    /// Asks on stderr and reads stdin.
    pub fn terminal() -> Self {
        let stdin: Stdin = io::stdin();
        Dialog::new(stdin.lock(), io::stdout(), io::stderr(), stdin.is_terminal())
    }
}

/// The values given as flags, checked before anything is asked: a host name that is not valid, or a join code that does
/// not decode, is an error here.
pub fn flags<'a>(host: Option<&'a str>, join: Option<&str>) -> Result<(Option<&'a str>, Option<JoinInfo>)> {
    if let Some(host) = host {
        ensure!(
            valid_label(host),
            "--host {host:?} is not a valid name: it is {HOST_RULE}"
        );
    }
    Ok((host, join.map(join::decode).transpose()?))
}

impl<I: BufRead, O: Write, P: Write> Dialog<I, O, P> {
    /// Reads `input`, writes the results to `out` and the questions to `prompts`. `interactive`: whether `input` is a
    /// person at a terminal.
    pub fn new(input: I, out: O, prompts: P, interactive: bool) -> Self {
        Dialog {
            input,
            out,
            prompts,
            interactive,
        }
    }

    /// Says what is being set up and where its config is saved.
    pub fn intro(&mut self, paths: &Paths) -> Result<()> {
        writeln!(self.out, "Setting up a system-wide reverse tunnel service.")?;
        writeln!(self.out, "  Config is saved to: {}", paths.config_file().display())?;
        Ok(())
    }

    /// The name for a new `config.yaml`, or none when one exists, whose host is then shown. A name given as `explicit`
    /// (checked by `flags`) is shown and not asked for; with an existing config it must be that config's name.
    /// Otherwise the machine's name is offered.
    pub fn host(&mut self, paths: &Paths, explicit: Option<&str>) -> Result<Option<String>> {
        let config = paths.config_file();
        if config.try_exists()? {
            let current = Config::load(&config).map(|config| config.host);
            if let Some(asked) = explicit {
                let current = current.as_ref().map_err(|err| anyhow!("{err:#}"))?;
                ensure!(
                    asked == current,
                    "--host {asked:?} differs from this host's name {current:?} in {}: `install` does not rename a \
                     host. To rename it, uninstall it and install it again with --host {asked}",
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

    /// The join code given as `explicit` (checked by `flags`) or typed, or none when `config.yaml` and the bridge's
    /// files already exist.
    pub fn join(&mut self, paths: &Paths, explicit: Option<JoinInfo>) -> Result<Option<JoinInfo>> {
        if explicit.is_some() {
            return Ok(explicit);
        }
        if !needs_join(paths)? {
            return Ok(None);
        }
        self.ensure_interactive("a join code", "--join CODE")?;
        self.ask_join().map(Some)
    }

    /// `flag` is what gives the value; the advice is to run `install` with it, which `upgrade` cannot pass.
    fn ensure_interactive(&self, what: &str, flag: &str) -> Result<()> {
        ensure!(
            self.interactive,
            "{what} is needed, and stdin is not a terminal to ask for it: run `reverse-tunnel install {flag}`"
        );
        Ok(())
    }

    /// Asks until the answer is a valid host name, lowercased; Enter takes `default`. The end of the input gives up.
    fn ask_host(&mut self, default: Option<&str>) -> Result<String> {
        loop {
            match default {
                Some(default) => write!(self.prompts, "Hostname [{default}]: ")?,
                None => write!(self.prompts, "Hostname: ")?,
            }
            self.prompts.flush()?;
            let mut line = String::new();
            ensure!(
                self.input.read_line(&mut line)? > 0,
                "no host name was entered; pass --host NAME"
            );
            let answer = line.trim().to_lowercase();
            let answer = if answer.is_empty() {
                default.unwrap_or("").to_string()
            } else {
                answer
            };
            if valid_label(&answer) {
                return Ok(answer);
            }
            writeln!(self.prompts, "  A host name is {HOST_RULE}.")?;
        }
    }

    /// Reads lines until they form a join code, which may be wrapped over several. A blank line, or the end of the
    /// input, gives up.
    fn ask_join(&mut self) -> Result<JoinInfo> {
        write!(
            self.prompts,
            "Join code (run `uv run ctl join-code` on the bridge; an empty line gives up): "
        )?;
        self.prompts.flush()?;
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

/// A machine name as a host name: its first label, lowercased, if that is a valid host name.
fn machine_host(machine: &str) -> Option<String> {
    let host = machine.split('.').next()?.to_lowercase();
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
