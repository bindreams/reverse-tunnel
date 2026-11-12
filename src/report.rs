//! What `main` prints for a failed command.

use std::fmt::Write;

/// `err` as anyhow's `{:?}` prints it (the outermost message, then `Caused by:`), except that a `goetia::Error` in the
/// chain is written by `goetia::Error::report` in place of itself and its causes: goetia's `Display` is only its
/// outermost context, and the stderr of a failed tool and the remedies are written by `report` alone.
pub fn report(err: &anyhow::Error) -> String {
    let mut messages = Vec::new();
    for link in err.chain() {
        if let Some(goetia) = link.downcast_ref::<goetia::Error>() {
            messages.push(goetia.report().to_string());
            break;
        }
        messages.push(link.to_string());
    }
    let mut out = messages.remove(0);
    if !messages.is_empty() {
        out.push_str("\n\nCaused by:");
        for (i, message) in messages.iter().enumerate() {
            if messages.len() == 1 {
                write!(out, "\n    {message}").unwrap();
            } else {
                write!(out, "\n    {i}: {message}").unwrap();
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
