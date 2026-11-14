//! frpc's admin API, on loopback: whether this host is logged in to the bridge, and what each published service is
//! doing. Its password is `secrets/admin.password`, which only the service account and administrators read, and its port
//! is the one `run` recorded (`Paths::admin_port_file`).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::io::{self, ErrorKind};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::config::Config;
use crate::paths::Paths;
use crate::supervisor::token;

/// The admin API's user; the password is in `Paths::admin_password`.
pub const USER: &str = "reverse-tunnel";

/// How long frpc has to answer a request on loopback.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// One published service as frpc reports it.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Proxy {
    pub name: String,
    /// frpc's word for it, such as `running` or `start error`.
    pub status: String,
    #[serde(default)]
    pub err: String,
}

/// What frpc says of its connection to the bridge.
#[derive(Debug, PartialEq, Eq)]
pub enum Tunnel {
    /// Logged in; each published service.
    Connected(Vec<Proxy>),
    NotConnected,
    /// Not asked, or not answered; why.
    Unknown(String),
}

/// Asks the running frpc. Never fails: what stops the answer is the answer.
pub fn tunnel(cfg: &Config, paths: &Paths) -> Tunnel {
    // frpc lists no service for a host that publishes none, logged in or not.
    if cfg.services.is_empty() {
        return Tunnel::Unknown("no service is published, so frpc has nothing to report".into());
    }
    let password = match token(&paths.admin_password()) {
        Ok(password) => password,
        Err(err)
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::PermissionDenied) =>
        {
            let how = if cfg!(windows) { "an elevated prompt" } else { "sudo" };
            return Tunnel::Unknown(format!("only administrators can read the admin password: use {how}"));
        }
        Err(err) => return Tunnel::Unknown(format!("{err:#}")),
    };
    let port = match recorded_port(paths) {
        Ok(port) => port,
        Err(err) => return Tunnel::Unknown(format!("{err:#}")),
    };
    match get(port, &password).and_then(|body| parse(&body)) {
        Ok(proxies) if proxies.is_empty() => Tunnel::NotConnected,
        Ok(proxies) => Tunnel::Connected(proxies),
        Err(err) => Tunnel::Unknown(format!("{err:#}")),
    }
}

/// The port `run` recorded when it last started frpc, which picks a new one at each start.
fn recorded_port(paths: &Paths) -> Result<u16> {
    let file = paths.admin_port_file();
    let text = match fs::read_to_string(&file) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => bail!("the service has not started frpc"),
        Err(err) => return Err(err).with_context(|| format!("reading {}", file.display())),
    };
    let port: u16 = text
        .trim()
        .parse()
        .with_context(|| format!("{} does not hold a port", file.display()))?;
    ensure!(port != 0, "{} holds port 0", file.display());
    Ok(port)
}

/// The body of frpc's `/api/status`.
fn get(port: u16, password: &str) -> Result<String> {
    // No proxy: the address is loopback, and ureq would otherwise take one from the environment.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(ANSWER_WITHIN))
        .http_status_as_error(false)
        .build()
        .into();
    let basic = STANDARD.encode(format!("{USER}:{password}"));
    let url = format!("http://127.0.0.1:{port}/api/status");
    let mut response = match agent.get(&url).header("Authorization", format!("Basic {basic}")).call() {
        Ok(response) => response,
        Err(err) => bail!("frpc did not answer at 127.0.0.1:{port}: {err}"),
    };
    match response.status().as_u16() {
        200 => Ok(response.body_mut().read_to_string()?),
        401 => bail!("frpc rejected the admin password"),
        status => bail!("frpc answered {status} at 127.0.0.1:{port}"),
    }
}

/// The proxies in frpc's `/api/status`, which groups them by type, by name. An empty answer (`{}`) is what frpc gives
/// until it has logged in, and again once it has lost the bridge.
fn parse(body: &str) -> Result<Vec<Proxy>> {
    let groups: BTreeMap<String, Vec<Proxy>> = serde_json::from_str(body)?;
    let mut proxies: Vec<Proxy> = groups.into_values().flatten().collect();
    proxies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(proxies)
}

/// The `bridge:` line of `status`, and a line for each published service.
pub fn describe(bridge: &str, tunnel: &Tunnel) -> String {
    let mut out = String::new();
    match tunnel {
        Tunnel::Connected(_) => writeln!(out, "bridge: {bridge} (connected)"),
        Tunnel::NotConnected => writeln!(out, "bridge: {bridge} (not connected)"),
        Tunnel::Unknown(why) => writeln!(out, "bridge: {bridge} (not checked: {why})"),
    }
    .unwrap();
    if let Tunnel::Connected(proxies) = tunnel {
        for Proxy { name, status, err } in proxies {
            match err.is_empty() {
                true => writeln!(out, "published {name}: {status}"),
                false => writeln!(out, "published {name}: {status} ({err})"),
            }
            .unwrap();
        }
    }
    out
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
