use super::instructions;
use crate::config::Config;

fn config(services: &str) -> Config {
    Config::parse(&format!(
        "host: myhost\nbridge: tunnel.example.com\nservices:\n{services}"
    ))
    .unwrap()
}

#[test]
fn the_ssh_config_block_names_the_ssh_service_of_the_host_on_the_bridge() {
    let text = instructions(&config("  ssh:\n    port: 22\n    type: tcp\n")).unwrap();
    let block =
        "Host myhost\n    HostName ssh.myhost.tunnel.example.com\n    ProxyCommand websocat --binary wss://%h/\n";
    assert!(text.ends_with(block), "{text}");
    assert!(text.contains("~/.ssh/config"), "{text}");
    assert!(
        text.contains("#set-up-a-client"),
        "the README pointer is missing: {text}"
    );
}

#[test]
fn there_is_no_block_for_a_host_that_does_not_publish_ssh() {
    assert!(instructions(&config("  web:\n    port: 80\n    type: http\n")).is_none());
    assert!(instructions(&config("  ssh:\n    port: 22\n    type: http\n")).is_none());
}
