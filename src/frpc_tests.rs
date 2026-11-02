use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::download::{fetch, host_pin};
use crate::paths::Paths;

const YAML: &str = "\
host: mothership
bridge: tunnel.example.test
default: ssh
services:
  ssh:
    port: 22
    type: tcp
  jellyfin:
    port: 8096
    type: http
";
const WS_PORT: u16 = 41234;

fn paths(config_dir: &str) -> Paths {
    Paths {
        bin_dir: PathBuf::from("bin"),
        config_dir: PathBuf::from(config_dir),
        secrets_dir: PathBuf::from(config_dir).join("secrets"),
        log_dir: PathBuf::from("logs"),
        link: None,
    }
}

fn render_yaml(yaml: &str) -> String {
    render(&Config::parse(yaml).unwrap(), WS_PORT, &paths("config"))
}

/// The text of the `[[proxies]]` table named `name`.
fn proxy(out: &str, name: &str) -> String {
    let table = out
        .split("[[proxies]]")
        .find(|t| t.contains(&format!("name = \"{name}\"")))
        .unwrap();
    table.to_string()
}

#[test]
fn render_transport() {
    let p = paths("config");
    let ca = serde_json::to_string(p.config_dir.join("bridge.pem").to_str().unwrap()).unwrap();
    let out = render(&Config::parse(YAML).unwrap(), WS_PORT, &p);
    for line in [
        "serverAddr = \"tunnel.example.test\"",
        "serverPort = 7000",
        "transport.protocol = \"quic\"",
        &format!("transport.tls.trustedCaFile = {ca}"),
        "user = \"mothership\"",
        "loginFailExit = false",
        "log.to = \"console\"",
        "log.level = \"info\"",
        "log.disablePrintColor = true",
        "auth.token = \"{{ .Envs.RT_BRIDGE_TOKEN }}\"",
        "metadatas.token = \"{{ .Envs.RT_HOST_TOKEN }}\"",
    ] {
        assert!(out.lines().any(|l| l == line), "missing line {line:?} in\n{out}");
    }
}

#[test]
fn render_http_service() {
    let table = proxy(&render_yaml(YAML), "jellyfin");
    assert!(table.contains("type = \"http\""));
    assert!(table.contains("localPort = 8096"));
    assert!(table.contains("customDomains = [\"jellyfin.mothership.tunnel.example.test\"]"));
}

#[test]
fn render_tcp_service_points_at_listener() {
    let table = proxy(&render_yaml(YAML), "ssh");
    assert!(table.contains("type = \"http\""));
    assert!(table.contains(&format!("localPort = {WS_PORT}")));
    assert!(!table.contains("localPort = 22"));
}

#[test]
fn render_default_adds_bare_name() {
    let out = render_yaml(&YAML.replace("default: ssh", "default: jellyfin"));
    let default = "customDomains = [\"jellyfin.mothership.tunnel.example.test\", \"mothership.tunnel.example.test\"]";
    assert!(proxy(&out, "jellyfin").contains(default));
    assert!(proxy(&out, "ssh").contains("customDomains = [\"ssh.mothership.tunnel.example.test\"]"));
}

#[test]
fn ws_routes_cover_tcp_services_and_default() {
    let routes = ws_routes(&Config::parse(YAML).unwrap());
    let want = BTreeMap::from([
        ("ssh.mothership.tunnel.example.test".to_string(), 22),
        ("mothership.tunnel.example.test".to_string(), 22),
    ]);
    assert_eq!(routes, want);
}

/// Fetches the host's frpc.
#[test]
#[ignore = "downloads frpc from the network"]
fn frpc_verify_accepts_render() {
    let dir = tempfile::tempdir().unwrap();
    let frpc = fetch(host_pin().unwrap(), dir.path()).unwrap();
    std::fs::write(
        dir.path().join("bridge.pem"),
        include_str!("../server/testdata/bridge.pem"),
    )
    .unwrap();
    let toml = dir.path().join("frpc.toml");
    let out = render(
        &Config::parse(YAML).unwrap(),
        WS_PORT,
        &paths(dir.path().to_str().unwrap()),
    );
    std::fs::write(&toml, out).unwrap();
    let verify = Command::new(frpc).args(["verify", "-c"]).arg(&toml).output().unwrap();
    assert!(
        verify.status.success(),
        "{}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}
