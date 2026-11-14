//! What a person needs to reach a host from another machine.

/// The text `install` prints after the registration line: the `~/.ssh/config` block for the host `host` on the bridge
/// `bridge` (the README's, filled in), and where the README explains the rest.
pub fn instructions(host: &str, bridge: &str) -> String {
    format!(
        "To reach this host with ssh from another machine, add this to ~/.ssh/config there (it needs websocat; \
        the README's \"Set up a client\" has the details: \
        https://github.com/bindreams/reverse-tunnel#set-up-a-client):\n\n\
        Host {host}\n    HostName {host}.{bridge}\n    ProxyCommand websocat --binary wss://%h/\n"
    )
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
