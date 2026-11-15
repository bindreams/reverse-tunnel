//! What `install` asks the person at the terminal, line by line, and what it prints.
//!
//! The questions go to stderr, so that stdout holds only the results.

use std::io::{self, BufRead, IsTerminal, Stderr, Stdin, StdinLock, Stdout, Write};

use anyhow::{Context, Result, ensure};

use crate::config::valid_label;
use crate::join::{self, JoinInfo};
use crate::paths::Paths;

const HOST_RULE: &str = "lowercase letters, digits and hyphens, not starting or ending with a hyphen, with no `--` \
                         as its third and fourth characters, at most 63 characters";

pub struct Dialog<I, O, P> {
    input: I,
    /// The results; `pick_up` hands it to `restart_pending`.
    pub(crate) out: O,
    prompts: P,
    interactive: bool,
}

impl Dialog<StdinLock<'static>, Stdout, Stderr> {
    /// Asks on stderr and reads stdin. Interactive only if stdin and stderr are both terminals: a person who cannot see
    /// the questions cannot answer them.
    pub fn terminal() -> Self {
        let stdin: Stdin = io::stdin();
        let interactive = stdin.is_terminal() && io::stderr().is_terminal();
        Dialog::new(stdin.lock(), io::stdout(), io::stderr(), interactive)
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
    /// `interactive`: whether `input` is a person at a terminal.
    pub fn new(input: I, out: O, prompts: P, interactive: bool) -> Self {
        Dialog {
            input,
            out,
            prompts,
            interactive,
        }
    }

    pub fn intro(&mut self, paths: &Paths) -> Result<()> {
        writeln!(self.out, "Setting up a system-wide reverse tunnel service.")?;
        writeln!(self.out, "  Config is saved to: {}", paths.config_file().display())?;
        Ok(())
    }

    /// Shows a host name that was not asked for.
    pub fn show_host(&mut self, host: &str) -> Result<()> {
        writeln!(self.out, "Hostname: {host}")?;
        Ok(())
    }

    /// Prints a line to the results: what `install` is about to do, or has done. On the terminal `out` is stdout, a
    /// line-buffered writer, so the line is written when this returns.
    pub fn say(&mut self, line: &str) -> Result<()> {
        writeln!(self.out, "{line}")?;
        Ok(())
    }

    /// Prints a line to stderr, for what went wrong after `install` had done its work. A write failure is ignored: there
    /// is nothing left to report it to.
    pub fn warn(&mut self, line: &str) {
        let _ = writeln!(self.prompts, "{line}");
    }

    /// Where the results go, for what prints itself.
    pub fn out(&mut self) -> &mut O {
        &mut self.out
    }

    pub fn interactive(&self) -> bool {
        self.interactive
    }

    /// End of input is an error.
    pub fn ask_host(&mut self, default: Option<&str>) -> Result<String> {
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
    pub fn ask_join(&mut self) -> Result<JoinInfo> {
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

/// The machine's name as a host name, if it is one.
pub fn default_host() -> Option<String> {
    machine_host(&gethostname::gethostname().to_string_lossy())
}

/// A machine name as a host name: its first label, lowercased, if that is a valid host name.
fn machine_host(machine: &str) -> Option<String> {
    let host = machine.split('.').next()?.to_lowercase();
    valid_label(&host).then_some(host)
}

#[cfg(test)]
#[path = "dialog_tests.rs"]
mod tests;
