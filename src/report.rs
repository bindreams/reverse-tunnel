/// `err` as anyhow's `{:#}` writes it, but a `goetia::Error` in the chain is written by its `report()`: goetia's
/// `Display` is only the outermost context, and only `report` includes a failed tool's stderr and remedies.
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
