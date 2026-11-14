//! What a person needs to reach a host from another machine.

use crate::config::{Config, Kind};
use crate::frpc::hosts;

/// The text `install` prints after the registration line: the `~/.ssh/config` block for the host (the README's, filled
/// in) and where the README explains the rest. The block is for the service named `ssh` when it is `type: tcp`,
/// whatever its port; `None` otherwise: the block would point at nothing.
pub fn instructions(cfg: &Config) -> Option<String> {
    if cfg.services.get("ssh")?.r#type != Kind::Tcp {
        return None;
    }
    // The service-qualified name always routes; the bare `<host>.T` only for the host's default service.
    let target = &hosts(cfg, "ssh")[0];
    let host = &cfg.host;
    Some(format!(
        "To reach this host with ssh from another machine, add this to ~/.ssh/config there (it needs websocat; \
        the README's \"Set up a client\" has the details: \
        https://github.com/bindreams/reverse-tunnel#set-up-a-client):\n\n\
        Host {host}\n    HostName {target}\n    ProxyCommand websocat --binary wss://%h/\n"
    ))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
