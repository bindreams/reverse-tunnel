use std::process::Command;

use super::*;
use crate::download::{fetch, host_pin};
use crate::paths::Paths;

const YAML: &str = "\
host: myhost
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
const ADMIN_PORT: u16 = 41235;

fn render_yaml(yaml: &str) -> String {
    render(
        &Config::parse(yaml).unwrap(),
        WS_PORT,
        ADMIN_PORT,
        &Paths::testing("root"),
    )
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
    let p = Paths::testing("root");
    let ca = serde_json::to_string(p.bridge_pem().to_str().unwrap()).unwrap();
    let out = render(&Config::parse(YAML).unwrap(), WS_PORT, ADMIN_PORT, &p);
    for line in [
        "serverAddr = \"tunnel.example.test\"",
        "serverPort = 7000",
        "transport.protocol = \"quic\"",
        &format!("transport.tls.trustedCaFile = {ca}"),
        "user = \"myhost\"",
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

/// The admin API is on loopback, at the port `render` is given, with the password read from frpc's environment like
/// the tokens.
#[test]
fn render_admin_api() {
    let lines = render_yaml(YAML).lines().map(String::from).collect::<Vec<_>>();
    for line in [
        "webServer.addr = \"127.0.0.1\"".to_string(),
        format!("webServer.port = {ADMIN_PORT}"),
        "webServer.user = \"reverse-tunnel\"".to_string(),
        "webServer.password = \"{{ .Envs.RT_ADMIN_PASSWORD }}\"".to_string(),
    ] {
        assert!(lines.contains(&line), "missing line {line:?}");
    }
    let other = render(&Config::parse(YAML).unwrap(), WS_PORT, 7777, &Paths::testing("root"));
    assert!(other.lines().any(|line| line == "webServer.port = 7777"));
}

#[test]
fn render_http_service() {
    let table = proxy(&render_yaml(YAML), "jellyfin");
    assert!(table.contains("type = \"http\""));
    assert!(table.contains("localPort = 8096"));
    assert!(table.contains("customDomains = [\"jellyfin.myhost.tunnel.example.test\"]"));
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
    let default = "customDomains = [\"jellyfin.myhost.tunnel.example.test\", \"myhost.tunnel.example.test\"]";
    assert!(proxy(&out, "jellyfin").contains(default));
    assert!(proxy(&out, "ssh").contains("customDomains = [\"ssh.myhost.tunnel.example.test\"]"));
}

#[test]
fn ws_routes_cover_tcp_services_and_default() {
    let routes = ws_routes(&Config::parse(YAML).unwrap());
    let want = BTreeMap::from([
        ("ssh.myhost.tunnel.example.test".to_string(), 22),
        ("myhost.tunnel.example.test".to_string(), 22),
    ]);
    assert_eq!(routes, want);
}

/// Fetches the host's frpc.
#[test]
#[ignore = "downloads frpc from the network"]
fn frpc_verify_accepts_render() {
    let dir = tempfile::tempdir().unwrap();
    let frpc = fetch(host_pin().unwrap(), dir.path()).unwrap();
    let paths = Paths::testing(dir.path());
    std::fs::create_dir(&paths.config_dir).unwrap();
    std::fs::write(paths.bridge_pem(), include_str!("../server/testdata/bridge.pem")).unwrap();
    let toml = dir.path().join("frpc.toml");
    let out = render(&Config::parse(YAML).unwrap(), WS_PORT, ADMIN_PORT, &paths);
    std::fs::write(&toml, out).unwrap();
    let verify = Command::new(frpc).args(["verify", "-c"]).arg(&toml).output().unwrap();
    assert!(
        verify.status.success(),
        "{}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}
