//! Stands in for frpc in `tests/`. What it does is the text of `<this exe>.mode`:
//!
//! - `exit <code>`: print a line to stderr and exit.
//! - `record <code> <file>`: write `ARG <argument>` and `ENV <name>=<value>` lines, then `TOML` and the `-c` file's
//!   text, to `<file>`, then exit.
//! - `hold <addr>`: connect to `<addr>`, send the port the `-c` file gives the `tcp` services and a newline, then
//!   obey one byte at a time until the peer closes: `f` opens `FLOOD` connections to that port and answers `flooded`,
//!   anything else closes them again.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::{env, fs};

const FLOOD: usize = 100;

fn main() {
    let mode = fs::read_to_string(env::current_exe().unwrap().with_extension("mode")).unwrap();
    let words: Vec<&str> = mode.trim_end().splitn(3, ' ').collect();
    let args: Vec<String> = env::args().skip(1).collect();
    let config = args
        .iter()
        .position(|arg| arg == "-c")
        .map(|at| fs::read_to_string(&args[at + 1]).unwrap());
    match words[..] {
        ["exit", code] => {
            eprintln!("stub frpc: failing");
            exit(code.parse().unwrap());
        }
        ["record", code, file] => {
            let mut out = String::new();
            args.iter().for_each(|arg| out += &format!("ARG {arg}\n"));
            env::vars().for_each(|(name, value)| out += &format!("ENV {name}={value}\n"));
            fs::write(file, format!("{out}TOML\n{}", config.unwrap_or_default())).unwrap();
            exit(code.parse().unwrap());
        }
        ["hold", addr] => {
            let config = config.unwrap();
            let port = config
                .lines()
                .find_map(|line| line.strip_prefix("localPort = "))
                .unwrap();
            let mut peer = TcpStream::connect(addr).unwrap();
            writeln!(peer, "{port}").unwrap();
            let mut flood = Vec::new();
            let mut command = [0];
            while peer.read(&mut command).unwrap() == 1 {
                flood.clear();
                if command[0] == b'f' {
                    flood.extend(
                        (0..FLOOD).map(|_| TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap()),
                    );
                    writeln!(peer, "flooded").unwrap();
                }
            }
        }
        _ => panic!("unknown mode {mode:?}"),
    }
}
