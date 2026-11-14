use super::instructions;

#[test]
fn the_ssh_config_block_names_the_host_and_the_bridge() {
    let text = instructions("myhost", "tunnel.example.com");
    let block = "Host myhost\n    HostName myhost.tunnel.example.com\n    ProxyCommand websocat --binary wss://%h/\n";
    assert!(text.contains(block), "{text}");
    assert!(text.contains("~/.ssh/config"), "{text}");
    assert!(
        text.contains("#set-up-a-client"),
        "the README pointer is missing: {text}"
    );
}
