//! What a person needs to reach a host from another machine.

use crate::config::{Config, Kind};

/// The text `install` prints after the registration line: the `~/.ssh/config` block for the host (the README's, filled
/// in) and where the README explains the rest. `None` when the host publishes no `ssh` tcp service: the block would
/// point at nothing.
pub fn instructions(cfg: &Config) -> Option<String> {
    let ssh = cfg.services.get("ssh")?;
    if ssh.r#type != Kind::Tcp {
        return None;
    }
    let (host, bridge) = (&cfg.host, &cfg.bridge);
    // The service-qualified name always routes; the bare `<host>.T` only when `ssh` is the host's default service.
    Some(format!(
        "To reach this host with ssh from another machine, add this to ~/.ssh/config there (it needs websocat; \
        the README's \"Set up a client\" has the details: \
        https://github.com/bindreams/reverse-tunnel#set-up-a-client):\n\n\
        Host {host}\n    HostName ssh.{host}.{bridge}\n    ProxyCommand websocat --binary wss://%h/\n"
    ))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
