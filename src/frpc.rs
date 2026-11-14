use std::collections::BTreeMap;

use crate::config::{CONTROL_PORT, Config, Kind};
use crate::paths::Paths;

/// The frpc.toml for `cfg`. It holds no secret: tokens are read from frpc's environment. `tcp` services point at
/// `ws_port`.
pub fn render(cfg: &Config, ws_port: u16, paths: &Paths) -> String {
    let (host, bridge) = (&cfg.host, &cfg.bridge);
    // `Paths::system()` guarantees Unicode, and a Windows backslash escapes alike in JSON and TOML basic strings.
    let ca = serde_json::to_string(paths.bridge_pem().to_str().unwrap()).unwrap();
    let mut out = format!(
        r#"serverAddr = "{bridge}"
serverPort = {CONTROL_PORT}
user = "{host}"
loginFailExit = false
transport.protocol = "quic"
transport.tls.trustedCaFile = {ca}
auth.token = "{{{{ .Envs.RT_BRIDGE_TOKEN }}}}"
metadatas.token = "{{{{ .Envs.RT_HOST_TOKEN }}}}"
log.to = "console"
log.level = "info"
log.disablePrintColor = true
"#
    );
    for (name, service) in &cfg.services {
        let port = match service.r#type {
            Kind::Http => service.port,
            Kind::Tcp => ws_port,
        };
        let domains = hosts(cfg, name)
            .iter()
            .map(|host| format!("\"{host}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out += &format!(
            r#"
[[proxies]]
name = "{name}"
type = "http"
localPort = {port}
customDomains = [{domains}]
"#
        );
    }
    out
}

/// The `Host` each `tcp` service is reached at, mapped to the service's port.
pub fn ws_routes(cfg: &Config) -> BTreeMap<String, u16> {
    let tcp = cfg.services.iter().filter(|(_, service)| service.r#type == Kind::Tcp);
    tcp.flat_map(|(name, service)| hosts(cfg, name).into_iter().map(|host| (host, service.port)))
        .collect()
}

/// Public hostnames of service `name`: first `<name>.<host>.T`, which always routes, then, for the default service, the
/// bare `<host>.T`.
pub(crate) fn hosts(cfg: &Config, name: &str) -> Vec<String> {
    let mut hosts = vec![format!("{name}.{}.{}", cfg.host, cfg.bridge)];
    if cfg.default.as_deref() == Some(name) {
        hosts.push(format!("{}.{}", cfg.host, cfg.bridge));
    }
    hosts
}

#[cfg(test)]
#[path = "frpc_tests.rs"]
mod tests;
