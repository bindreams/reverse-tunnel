use super::*;

const OK: &str = "\
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

fn error(text: &str) -> String {
    format!("{:#}", Config::parse(text).unwrap_err())
}

#[test]
fn config_rejects_unknown_key_naming_it() {
    assert!(error(&format!("{OK}colour: red\n")).contains("colour"));
}

#[test]
fn config_rejects_nested_unknown_key() {
    assert!(error(&OK.replace("port: 22", "port: 22\n    prot: 23")).contains("prot"));
}

#[test]
fn config_default_must_exist() {
    assert!(error(&OK.replace("default: ssh", "default: nope")).contains("nope"));
}

#[test]
fn config_rejects_duplicate_service() {
    // `22` and `'22'` are different YAML values but the same service name.
    for (first, second) in [("ssh", "ssh"), ("22", "'22'")] {
        let doubled = format!("{OK}  {first}:\n    port: 1\n    type: tcp\n  {second}:\n    port: 2\n    type: tcp\n");
        assert!(error(&doubled).contains(first), "{first} and {second} were accepted");
    }
}

#[test]
fn config_rejects_bad_service_name() {
    for name in ["my_box", "Ssh", "-ssh", "ssh-", "ab--cd", &"a".repeat(64)] {
        let text = OK.replace("jellyfin", name);
        assert!(error(&text).contains(name), "{name} was accepted");
    }
}

#[test]
fn config_rejects_bad_host_name() {
    assert!(error(&OK.replace("mothership", "DESKTOP-7Q2X")).contains("DESKTOP-7Q2X"));
}

#[test]
fn config_bridge_must_be_a_domain() {
    for bridge in [
        "localhost",
        "tunnel.example.test.",
        "Tunnel.example.test",
        &format!("{}.{}", "a".repeat(63), "b".repeat(62)),
    ] {
        let text = OK.replace("tunnel.example.test", bridge);
        assert!(error(&text).contains("bridge"), "{bridge} was accepted");
    }
}

#[test]
fn config_requires_type() {
    assert!(error(&OK.replace("    type: http\n", "")).contains("type"));
}

#[test]
fn config_rejects_port_0_and_65536() {
    for port in ["0", "65536"] {
        assert!(error(&OK.replace("22", port)).contains("port"), "{port} was accepted");
    }
}

#[test]
fn config_accepts_utf8_bom() {
    Config::parse(&format!("\u{feff}{OK}")).unwrap();
}
