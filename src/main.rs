use clap::Parser;

/// Publishes this machine's services through the reverse-tunnel bridge.
#[derive(Parser)]
#[command(version)]
struct Cli {}

fn main() {
    Cli::parse();
}
