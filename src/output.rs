//! Best-effort printing: a closed stdout or stderr is ignored rather than a panic. A command that stops the service
//! over the tunnel ends the session that would read what it prints.

use std::io::Write;

/// Prints a line on stdout (a report, a wait) whose write failure is ignored (see the module).
pub fn println_best_effort(message: &str) {
    writeln_best_effort(&mut std::io::stdout(), message);
}

/// Prints a line on stderr (a warning, a wait, an error) whose write failure is ignored (see the module).
pub fn eprintln_best_effort(message: &str) {
    writeln_best_effort(&mut std::io::stderr(), message);
}

fn writeln_best_effort(out: &mut impl Write, message: &str) {
    let _ = writeln!(out, "{message}");
}
