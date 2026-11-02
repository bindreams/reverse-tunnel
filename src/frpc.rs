use std::collections::BTreeMap;

use crate::config::{CONTROL_PORT, Config, Kind};
use crate::paths::Paths;

/// The frpc.toml for `cfg`. It holds no secret: frpc reads both tokens from the environment variables
/// `RT_BRIDGE_TOKEN` and `RT_HOST_TOKEN`. Every `tcp` service is proxied to the supervisor's WebSocket
/// listener on `127.0.0.1:ws_port`.
pub fn render(cfg: &Config, ws_port: u16, paths: &Paths) -> String {
    let (host, bridge) = (&cfg.host, &cfg.bridge);
    // The path comes from `Paths::system()`; its only character needing an escape is the Windows backslash,
    // which JSON and TOML basic strings escape alike.
    let ca = serde_json::to_string(&paths.config_dir.join("bridge.pem").to_string_lossy()).unwrap();
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

/// The names service `name` is published at: `s.<host>.T`, and `<host>.T` for the default service.
fn hosts(cfg: &Config, name: &str) -> Vec<String> {
    let mut hosts = vec![format!("{name}.{}.{}", cfg.host, cfg.bridge)];
    if cfg.default.as_deref() == Some(name) {
        hosts.push(format!("{}.{}", cfg.host, cfg.bridge));
    }
    hosts
}

#[cfg(test)]
#[path = "frpc_tests.rs"]
mod tests;
