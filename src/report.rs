//! Error text for people.

/// `err` as anyhow's `{:#}` writes it (`context: cause: cause`), except that a `goetia::Error` in the chain is written
/// by `goetia::Error::report` in place of itself and its causes: goetia's `Display` is only its outermost context, and
/// only `report` writes a failed tool's stderr and the remedies.
pub fn report(err: &anyhow::Error) -> String {
    let mut messages = Vec::new();
    for link in err.chain() {
        if let Some(goetia) = link.downcast_ref::<goetia::Error>() {
            messages.push(goetia.report().to_string());
            break;
        }
        messages.push(link.to_string());
    }
    messages.join(": ")
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
